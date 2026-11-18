# SPDX-License-Identifier: Apache-2.0
"""Mesh Chronicle: local, durable, source-bound CRDT evidence store.

This is a node-local SQLite persistence and replay layer, not a consensus,
distributed SQL, live production, or authorizing control plane. It stores
immutable operations and exact DSSE evidence. All actionable reads REQUIRE
a fresh, independent enrollment registry and current receipt revalidation.
No signer private keys or provider credentials are persisted or inferred.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import threading
from typing import Any

from . import receipts
from .crdt import AUTHORIZED, OBSERVED, CRDTDocument, Op

SCHEMA_VERSION = 1
GENESIS = "0" * 64
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_OPERATION_BYTES = 1_048_576
MAX_RECEIPT_BYTES = 131_072
MAX_EVIDENCE_PER_OP = 8
MAX_BATCH = 256
MAX_DOC_ID = 256
MAX_KEY = 512
MAX_NODE_ID = 128
MAX_LAMPORT = (1 << 63) - 1

DDL = """
CREATE TABLE IF NOT EXISTS operations (
  op_id TEXT PRIMARY KEY NOT NULL,
  doc_id TEXT NOT NULL,
  key_name TEXT NOT NULL,
  lamport INTEGER NOT NULL CHECK(lamport > 0),
  node_id TEXT NOT NULL,
  op_json BLOB NOT NULL,
  CHECK(length(op_id) = 64)
);
CREATE INDEX IF NOT EXISTS ix_mesh_ops_doc ON operations(doc_id, key_name, lamport);
CREATE TABLE IF NOT EXISTS evidence (
  evidence_digest TEXT PRIMARY KEY NOT NULL,
  op_id TEXT NOT NULL REFERENCES operations(op_id),
  envelope_json BLOB NOT NULL,
  CHECK(length(evidence_digest) = 64)
);
CREATE INDEX IF NOT EXISTS ix_mesh_evidence_op ON evidence(op_id, evidence_digest);
CREATE TABLE IF NOT EXISTS event_chain (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  event_kind TEXT NOT NULL CHECK(event_kind IN ('OP', 'EVIDENCE')),
  op_id TEXT NOT NULL,
  item_digest TEXT NOT NULL,
  previous_hash TEXT NOT NULL,
  event_hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS immutable_ops_update BEFORE UPDATE ON operations
BEGIN SELECT RAISE(ABORT, 'mesh operations are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_ops_delete BEFORE DELETE ON operations
BEGIN SELECT RAISE(ABORT, 'mesh operations are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_evidence_update BEFORE UPDATE ON evidence
BEGIN SELECT RAISE(ABORT, 'mesh evidence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_evidence_delete BEFORE DELETE ON evidence
BEGIN SELECT RAISE(ABORT, 'mesh evidence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_chain_update BEFORE UPDATE ON event_chain
BEGIN SELECT RAISE(ABORT, 'mesh event chain is immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_chain_delete BEFORE DELETE ON event_chain
BEGIN SELECT RAISE(ABORT, 'mesh event chain is immutable'); END;
"""


class ChronicleIntegrityError(ValueError):
    """Persisted bytes or the local append-only bookkeeping disagree."""


def _canonical(value: Any, *, limit: int) -> bytes:
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if not raw or len(raw) > limit:
        raise ValueError("bounded JSON payload required")
    return raw


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validated_op(source: Op | Mapping[str, Any]) -> Op:
    if isinstance(source, Op):
        source = source.to_dict()
    if not isinstance(source, Mapping):
        raise ValueError("operation object required")
    if not all(k in source for k in ("doc_id", "key", "value", "lamport", "node_id")):
        raise ValueError("operation fields incomplete")
    doc_id, key, node_id, lamport = (
        source["doc_id"], source["key"], source["node_id"], source["lamport"]
    )
    if not (
        isinstance(doc_id, str) and 0 < len(doc_id) <= MAX_DOC_ID
        and isinstance(key, str) and 0 < len(key) <= MAX_KEY
        and isinstance(node_id, str) and 0 < len(node_id) <= MAX_NODE_ID
        and all("\x00" not in label for label in (doc_id, key, node_id))
        and type(lamport) is int and 0 < lamport <= MAX_LAMPORT
        and type(source.get("deletion", False)) is bool
    ):
        raise ValueError("invalid operation coordinates")
    value = json.loads(_canonical(source["value"], limit=MAX_OPERATION_BYTES))
    op = Op(
        doc_id=doc_id, key=key, value=value, lamport=lamport, node_id=node_id,
        deletion=source.get("deletion", False), track=OBSERVED,
    )
    if source.get("op_id", op.op_id) != op.op_id:
        raise ValueError("operation id is not bound to canonical content")
    if len(op.raw_bytes()) > MAX_OPERATION_BYTES:
        raise ValueError("operation exceeds byte limit")
    return op


def _receipt_bytes(value: Any) -> bytes | None:
    if value is None:
        return None
    if type(value) is not dict:
        raise ValueError("receipt must be a bounded JSON object")
    return _canonical(value, limit=MAX_RECEIPT_BYTES)


def _entry_hash(seq: int, kind: str, op_id: str, digest: str, prev: str) -> str:
    return _digest(_canonical(
        {"seq": seq, "kind": kind, "op_id": op_id,
         "item_digest": digest, "previous_hash": prev}, limit=2048
    ))


def _current_context(registry: Mapping[str, bytes] | None,
                     revoked: set[str] | None,
                     now: datetime | None) -> tuple[dict[str, bytes] | None, set[str], datetime]:
    if registry is not None and (
        not isinstance(registry, Mapping)
        or any(type(k) is not str or type(v) is not bytes for k, v in registry.items())
    ):
        raise ValueError("independent public-key registry must map node IDs to DER bytes")
    if revoked is not None and (
        type(revoked) is not set or any(type(k) is not str for k in revoked)
    ):
        raise ValueError("revocations must be an independently supplied set")
    now = now or datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("current receipt check requires an aware timestamp")
    # An enrolled-key snapshot without its independent revocation snapshot
    # is insufficient to grant authority. It remains OBSERVED instead.
    trusted = dict(registry) if registry is not None and revoked is not None else None
    return trusted, set(revoked or ()), now.astimezone(timezone.utc)


class MeshChronicle:
    """SQLite WAL node-local evidence plane; one writer lock, atomic batches."""

    def __init__(self, path: str | Path, *, readonly: bool = False) -> None:
        if type(readonly) is not bool:
            raise ValueError("readonly must be a boolean")
        self._readonly = readonly
        if not isinstance(path, (str, Path)):
            raise ValueError("database file path required")
        self.path = str(path)
        if not self.path or self.path == ":memory:" and type(path) is not str:
            raise ValueError("explicit local database path required")
        if self.path != ":memory:":
            p = Path(self.path)
            if p.is_symlink() or not p.parent.is_dir():
                raise ValueError("database parent must exist and path cannot be a symlink")
        if readonly and (self.path == ":memory:" or not Path(self.path).is_file()):
            raise ValueError("readonly requires an existing local database file")
        self._mutex = threading.RLock()
        target = (Path(self.path).resolve().as_uri() + "?mode=ro"
                  if readonly else self.path)
        self._db = sqlite3.connect(target, timeout=10, isolation_level=None,
                                   check_same_thread=False, uri=readonly)
        try:
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute("PRAGMA busy_timeout=10000")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("PRAGMA trusted_schema=OFF")
            if readonly:
                self._db.execute("PRAGMA query_only=ON")
            elif self.path != ":memory:":
                mode = self._db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
                if mode.lower() != "wal":
                    raise ChronicleIntegrityError("local WAL mode unavailable")
            version = self._db.execute("PRAGMA user_version").fetchone()[0]
            if version not in ((SCHEMA_VERSION,) if readonly else (0, SCHEMA_VERSION)):
                raise ChronicleIntegrityError("unsupported database version")
            if not readonly:
                self._db.executescript(DDL)
                if version == 0:
                    self._db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            self.verify_integrity()
        except Exception:
            self._db.close()
            raise

    def close(self) -> None:
        with self._mutex:
            self._db.close()

    def __enter__(self) -> "MeshChronicle":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    @contextmanager
    def _transaction(self):
        if self._readonly:
            raise PermissionError("read-only Chronicle does not allow writes")
        with self._mutex:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self._db.rollback()
                raise
            else:
                self._db.commit()

    def _append_event(self, kind: str, op_id: str, item_digest: str) -> None:
        row = self._db.execute(
            "SELECT seq, event_hash FROM event_chain ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        seq, prev = (row[0] + 1, row[1]) if row else (1, GENESIS)
        h = _entry_hash(seq, kind, op_id, item_digest, prev)
        self._db.execute(
            "INSERT INTO event_chain(seq,event_kind,op_id,item_digest,"
            "previous_hash,event_hash) VALUES(?,?,?,?,?,?)",
            (seq, kind, op_id, item_digest, prev, h),
        )

    def _ingest_one(self, source: Op | Mapping[str, Any], receipt: Any) -> dict[str, Any]:
        op = _validated_op(source)
        envelope = _receipt_bytes(receipt)
        raw = _canonical(op.to_dict(), limit=MAX_OPERATION_BYTES)
        old = self._db.execute(
            "SELECT op_json FROM operations WHERE op_id=?", (op.op_id,)
        ).fetchone()
        inserted = old is None
        if old is not None and old[0] != raw:
            raise ChronicleIntegrityError("operation hash collision or stored-content drift")
        if inserted:
            self._db.execute(
                "INSERT INTO operations(op_id,doc_id,key_name,lamport,node_id,op_json)"
                " VALUES(?,?,?,?,?,?)",
                (op.op_id, op.doc_id, op.key, op.lamport, op.node_id, raw),
            )
            self._append_event("OP", op.op_id, _digest(raw))
        evidence_new = False
        if envelope is not None:
            digest = _digest(envelope)
            old_evidence = self._db.execute(
                "SELECT envelope_json FROM evidence WHERE evidence_digest=?", (digest,)
            ).fetchone()
            if old_evidence is not None and old_evidence[0] != envelope:
                raise ChronicleIntegrityError("receipt digest collision")
            if old_evidence is None:
                count = self._db.execute(
                    "SELECT count(*) FROM evidence WHERE op_id=?", (op.op_id,)
                ).fetchone()[0]
                if count >= MAX_EVIDENCE_PER_OP:
                    raise ValueError("evidence-per-operation cap exceeded")
                self._db.execute(
                    "INSERT INTO evidence(evidence_digest,op_id,envelope_json)"
                    " VALUES(?,?,?)", (digest, op.op_id, envelope),
                )
                self._append_event("EVIDENCE", op.op_id, digest)
                evidence_new = True
            else:
                bound_op = self._db.execute(
                    "SELECT op_id FROM evidence WHERE evidence_digest=?", (digest,)
                ).fetchone()[0]
                if bound_op != op.op_id:
                    raise ChronicleIntegrityError("receipt reused for another operation")
        return {"op_id": op.op_id, "op_new": inserted, "evidence_new": evidence_new,
                "admission": "UNVERIFIED_AT_INGEST", "release_authority": False}

    def ingest(self, op: Op | Mapping[str, Any], receipt: dict | None = None) -> dict:
        """Append data atomically; caller-supplied track is never trusted."""
        with self._transaction():
            return self._ingest_one(op, receipt)

    def ingest_record(self, record: Mapping[str, Any]) -> dict:
        """Accept the existing MeshNode.write / sync record unchanged."""
        if not isinstance(record, Mapping):
            raise ValueError("record mapping required")
        source = record.get("op", record.get("op_obj"))
        if source is None:
            raise ValueError("record operation is missing")
        if "op_obj" in record and "op" in record:
            # Sender disagreement is not an admissible witness.
            if _validated_op(record["op"]).raw_bytes() != _validated_op(
                record["op_obj"]).raw_bytes():
                raise ValueError("record operation representations disagree")
        if record.get("change_hash", _validated_op(source).op_id) != _validated_op(source).op_id:
            raise ValueError("record change hash mismatch")
        return self.ingest(source, record.get("receipt"))

    def ingest_batch(self, records: Iterable[Mapping[str, Any]]) -> list[dict]:
        """Rollback all inputs when ANY member of a bounded sync batch fails."""
        rows = list(records)
        if len(rows) > MAX_BATCH:
            raise ValueError("sync batch too large")
        outputs: list[dict] = []
        with self._transaction():
            for record in rows:
                if not isinstance(record, Mapping) or "op" not in record:
                    raise ValueError("sync record must contain an operation")
                op = _validated_op(record["op"])
                if record.get("change_hash", op.op_id) != op.op_id:
                    raise ValueError("sync record hash mismatch")
                outputs.append(self._ingest_one(op, record.get("receipt")))
        return outputs

    def _rows(self, doc_id: str, *, at_seq: int | None = None):
        if not isinstance(doc_id, str) or not 0 < len(doc_id) <= MAX_DOC_ID:
            raise ValueError("bounded document ID required")
        if at_seq is not None and (type(at_seq) is not int or at_seq < 0):
            raise ValueError("as-of local sequence must be nonnegative")
        with self._mutex:
            if at_seq is None:
                source = self._db.execute(
                    "SELECT op_id,op_json FROM operations WHERE doc_id=? ORDER BY op_id",
                    (doc_id,),
                ).fetchall()
            else:
                source = self._db.execute(
                    "SELECT o.op_id,o.op_json FROM operations o JOIN event_chain e"
                    " ON e.op_id=o.op_id AND e.event_kind='OP' AND e.seq<=?"
                    " WHERE o.doc_id=? ORDER BY o.op_id", (at_seq, doc_id),
                ).fetchall()
            if len(source) > 50_000:
                raise ValueError("local projection cap exceeded")
            pairs = []
            for op_id, raw in source:
                if at_seq is None:
                    evidence = self._db.execute(
                        "SELECT evidence_digest,envelope_json FROM evidence WHERE op_id=?"
                        " ORDER BY evidence_digest", (op_id,),
                    ).fetchall()
                else:
                    evidence = self._db.execute(
                        "SELECT v.evidence_digest,v.envelope_json FROM evidence v JOIN event_chain e"
                        " ON e.item_digest=v.evidence_digest AND e.event_kind='EVIDENCE'"
                        " WHERE v.op_id=? AND e.seq<=? ORDER BY v.evidence_digest",
                        (op_id, at_seq),
                    ).fetchall()
                for digest, payload in evidence:
                    if _digest(payload) != digest:
                        raise ChronicleIntegrityError("stored evidence digest mismatch")
                pairs.append((op_id, raw, [payload for _, payload in evidence]))
        return pairs

    def _classified(
        self, doc_id: str, registry: Mapping[str, bytes] | None,
        revoked: set[str] | None, now: datetime | None,
        at_seq: int | None,
    ) -> tuple[CRDTDocument, list[dict[str, Any]]]:
        trusted, revoked_ids, checked_at = _current_context(registry, revoked, now)
        document = CRDTDocument(doc_id)
        assessments = []
        for op_id, raw, raw_receipts in self._rows(doc_id, at_seq=at_seq):
            try:
                op = _validated_op(json.loads(raw))
                if op.op_id != op_id or _canonical(
                    op.to_dict(), limit=MAX_OPERATION_BYTES) != raw:
                    raise ChronicleIntegrityError("stored operation identity drift")
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                raise ChronicleIntegrityError("stored operation unreadable") from exc
            document.add_op(op)
            statuses = []
            authorized = False
            for raw_receipt in raw_receipts:
                if trusted is None:
                    statuses.append("INDEPENDENT_TRUST_UNAVAILABLE")
                    continue
                try:
                    envelope = json.loads(raw_receipt)
                    gate = receipts.validate_receipt(
                        receipt=envelope,
                        change_raw_bytes=op.raw_bytes(),
                        now_utc=checked_at,
                        revoked_node_ids=revoked_ids,
                        pubkey_registry=trusted,
                        expected_document_id=op.doc_id,
                        expected_node_id=op.node_id,
                    )
                    statuses.append(gate.receipt_status)
                    authorized = authorized or gate.track == AUTHORIZED
                except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
                    statuses.append("RECEIPT_INVALID")
            if authorized:
                # Only current receipt verification against caller-supplied
                # independent trust/revocation state may promote an op.
                document.set_op_track(op_id, AUTHORIZED, validated=True)
            assessments.append({
                "op_id": op_id, "key": op.key, "node_id": op.node_id,
                "lamport": op.lamport,
                "track": AUTHORIZED if authorized else OBSERVED,
                "receipt_statuses": sorted(set(statuses)) if statuses
                                    else ["MISSING_RECEIPT"],
            })
        return document, assessments

    def state(
        self, doc_id: str, *, track: str = OBSERVED,
        registry: Mapping[str, bytes] | None = None,
        revoked: set[str] | None = None,
        now: datetime | None = None,
        at_seq: int | None = None,
    ) -> dict[str, Any]:
        """Replay at a local ingestion boundary; assess authority NOW, not then.

        A past receipt's local sequence NEVER grants past/future authority.
        The OBSERVED view includes nonauthorized evidence for awareness only.
        """
        if track not in (AUTHORIZED, OBSERVED):
            raise ValueError("unknown mesh authority track")
        document, _ = self._classified(doc_id, registry, revoked, now, at_seq)
        return document.view(track)

    def state_digest(
        self, doc_id: str, *, track: str = OBSERVED,
        registry: Mapping[str, bytes] | None = None,
        revoked: set[str] | None = None, now: datetime | None = None,
    ) -> str:
        if track not in (AUTHORIZED, OBSERVED):
            raise ValueError("unknown mesh authority track")
        doc, _ = self._classified(doc_id, registry, revoked, now, None)
        return doc.state_digest(track)

    def explain(
        self, doc_id: str, key: str, *, registry: Mapping[str, bytes] | None = None,
        revoked: set[str] | None = None, now: datetime | None = None,
        at_seq: int | None = None,
    ) -> dict[str, Any]:
        """Bounded, value-free causal witness for one key, no implied approval."""
        if not isinstance(key, str) or not 0 < len(key) <= MAX_KEY:
            raise ValueError("bounded key required")
        document, assessments = self._classified(
            doc_id, registry, revoked, now, at_seq)
        candidates = sorted(
            (row for row in assessments if row["key"] == key),
            key=lambda row: (row["lamport"], row["node_id"], row["op_id"]),
            reverse=True,
        )
        return {
            "schema": "szl.mesh.chronicle-explanation/v1",
            "doc_id": doc_id,
            "key": key,
            "candidate_count": len(candidates),
            "candidates": candidates[:32],
            "truncated": len(candidates) > 32,
            "observed_view_contains_key": key in document.observed_view(),
            "authorized_view_contains_key": key in document.authorized_view(),
            "authority": "REVALIDATED_CURRENT_TRUST" if registry is not None
                         and revoked is not None else "UNAVAILABLE",
            "signing_state": "EVIDENCE_REVALIDATED_NOT_DATABASE_SIGNED",
            "production_release_ready": False,
        }

    def causal_graph(
        self, doc_id: str, *, registry: Mapping[str, bytes] | None = None,
        revoked: set[str] | None = None, now: datetime | None = None,
        at_seq: int | None = None,
    ) -> dict[str, Any]:
        """Bounded causal *claim* graph, not a proof of real causation.

        Receipt from_state_head fields are assertions of the signing node.
        Only a current trusted receipt makes an assertion signer-validated;
        even that does not prove global CRDT history, source parity or BFT.
        No raw values, signatures, or provider tokens appear in the graph.
        """
        rows = self._rows(doc_id, at_seq=at_seq)
        if len(rows) > 256:
            raise ValueError("causal graph node budget exceeded")
        _, assessments = self._classified(doc_id, registry, revoked, now, at_seq)
        trusted, revoked_ids, checked_at = _current_context(registry, revoked, now)
        ids = {op_id for op_id, _, _ in rows}
        nodes = [
            {"op_id": item["op_id"], "key": item["key"],
             "lamport": item["lamport"], "node_id": item["node_id"],
             "track": item["track"]}
            for item in sorted(assessments, key=lambda item: item["op_id"])
        ]
        edges: set[tuple[str, str, str]] = set()
        missing_parents = 0
        for op_id, raw, evidence_rows in rows:
            op = _validated_op(json.loads(raw))
            for evidence_bytes in evidence_rows:
                try:
                    envelope = json.loads(evidence_bytes)
                    stmt = receipts.decode_statement(envelope)
                except (ValueError, KeyError, TypeError, UnicodeError, RecursionError):
                    continue
                if (not isinstance(stmt, dict)
                        or stmt.get("crdt_document_id") != doc_id
                        or stmt.get("change_hash") != op_id
                        or stmt.get("node_id") != op.node_id):
                    continue
                parents = stmt.get("from_state_head")
                if not isinstance(parents, list) or len(parents) > 32:
                    continue
                gate_valid = False
                if trusted is not None:
                    gate_valid = receipts.validate_receipt(
                        receipt=envelope, change_raw_bytes=op.raw_bytes(),
                        now_utc=checked_at, revoked_node_ids=revoked_ids,
                        pubkey_registry=trusted, expected_document_id=doc_id,
                        expected_node_id=op.node_id,
                    ).track == AUTHORIZED
                for parent in parents:
                    if not isinstance(parent, str) or not SHA256.fullmatch(parent):
                        continue
                    if parent == op_id:
                        continue
                    if parent not in ids:
                        missing_parents += 1
                        continue
                    edges.add((parent, op_id, "TRUSTED_SIGNER_ASSERTION"
                               if gate_valid else "UNVERIFIED_ASSERTION"))
                    if len(edges) > 1024:
                        raise ValueError("causal graph edge budget exceeded")
        document = {
            "schema": "szl.mesh.causal-claims/v1",
            "doc_id": doc_id,
            "nodes": nodes,
            "edges": [
                {"from": source, "to": target, "evidence": status,
                 "relation": "SIGNER_ASSERTED_PREVIOUS_HEAD"}
                for source, target, status in sorted(edges)
            ],
            "missing_parent_references": missing_parents,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "coverage": "BOUNDED_LOCAL_EVIDENCE",
            "global_causality_proven": False,
            "byzantine_agreement_proven": False,
            "source_deployment_parity": "UNKNOWN",
            "release_authority": False,
        }
        document["content_sha256"] = _digest(_canonical(
            document, limit=MAX_OPERATION_BYTES))
        document["signature_state"] = "UNSIGNED_LOCAL_STRUCTURAL_HASH"
        return document

    def export(self, doc_id: str) -> list[dict[str, Any]]:
        """Deterministic transport records; not signed database snapshots."""
        records = []
        for _, raw, raw_evidence in self._rows(doc_id):
            op = json.loads(raw)
            if not raw_evidence:
                records.append({"op": op, "receipt": None})
            else:
                for evidence in raw_evidence:
                    records.append({"op": op, "receipt": json.loads(evidence)})
        return records

    def replay_to(self, node: Any) -> dict[str, Any]:
        """Recover OBSERVED in-memory state without restoring signing authority.

        A brand-new MeshNode has a NEW ephemeral identity. This method does
        not persist or recover a private key, enrollment, or signed approval.
        The node's existing Receipt Gate reclassifies every imported receipt.
        """
        from .node import MeshNode

        if not isinstance(node, MeshNode):
            raise ValueError("explicit MeshNode target required")
        if node.enrolled or node._gateway is not None or node.doc.all_ops():
            raise ValueError("recovery target must be empty and unenrolled")
        records = self.export(node.doc_id)
        if len(records) > 50_000:
            raise ValueError("local recovery cap exceeded")
        added = 0
        for row in records:
            op = _validated_op(row["op"])
            result = node.apply_remote({"op_obj": op, "receipt": row["receipt"]})
            added += int(result["newly_added"])
        return {
            "schema": "szl.mesh.chronicle-local-recovery/v1",
            "replayed_records": len(records), "new_ops": added,
            "signing_identity_restored": False,
            "enrollment_restored": False,
            "automatic_execution_authority": False,
        }

    def tip(self) -> dict[str, Any]:
        with self._mutex:
            row = self._db.execute(
                "SELECT seq,event_hash FROM event_chain ORDER BY seq DESC LIMIT 1"
            ).fetchone()
        return {
            "sequence": row[0] if row else 0,
            "hash": row[1] if row else GENESIS,
            "signature_state": "UNSIGNED_LOCAL_HASH_CHAIN",
            "external_anchor": "UNAVAILABLE",
            "release_authority": False,
        }

    def verify_integrity(self) -> dict[str, Any]:
        """Verify local bytes and event chain; NOT external tamper evidence.

        A database administrator can replace the whole file and its hashes.
        External signed checkpoints are intentionally not claimed here.
        """
        with self._mutex:
            if self._db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ChronicleIntegrityError("SQLite physical integrity failed")
            observed = set()
            previous = GENESIS
            expected_seq = 1
            for seq, kind, op_id, item_digest, prev, digest in self._db.execute(
                "SELECT seq,event_kind,op_id,item_digest,previous_hash,event_hash"
                " FROM event_chain ORDER BY seq"
            ):
                if (seq != expected_seq or prev != previous
                        or not SHA256.fullmatch(item_digest)
                        or not SHA256.fullmatch(op_id)
                        or digest != _entry_hash(seq, kind, op_id, item_digest, prev)):
                    raise ChronicleIntegrityError("local append-chain broken")
                if kind == "OP":
                    row = self._db.execute(
                        "SELECT op_json FROM operations WHERE op_id=?", (op_id,)
                    ).fetchone()
                else:
                    row = self._db.execute(
                        "SELECT envelope_json FROM evidence WHERE"
                        " evidence_digest=? AND op_id=?", (item_digest, op_id)
                    ).fetchone()
                if row is None or _digest(row[0]) != item_digest:
                    raise ChronicleIntegrityError("missing or modified event payload")
                if kind == "OP":
                    try:
                        op = _validated_op(json.loads(row[0]))
                    except (ValueError, TypeError, json.JSONDecodeError) as exc:
                        raise ChronicleIntegrityError("invalid stored operation") from exc
                    if op.op_id != op_id or _canonical(
                        op.to_dict(), limit=MAX_OPERATION_BYTES) != row[0]:
                        raise ChronicleIntegrityError("operation content drift")
                identity = (kind, item_digest)
                if identity in observed:
                    raise ChronicleIntegrityError("duplicate local event entry")
                observed.add(identity)
                expected_seq += 1
                previous = digest
            for op_id, raw in self._db.execute("SELECT op_id,op_json FROM operations"):
                if ("OP", _digest(raw)) not in observed:
                    raise ChronicleIntegrityError("operation lacks event witness")
                if _validated_op(json.loads(raw)).op_id != op_id:
                    raise ChronicleIntegrityError("operation hash mismatch")
            for digest, raw in self._db.execute(
                "SELECT evidence_digest,envelope_json FROM evidence"
            ):
                if _digest(raw) != digest or ("EVIDENCE", digest) not in observed:
                    raise ChronicleIntegrityError("receipt lacks event witness")
            return {
                "status": "LOCAL_INTEGRITY_VERIFIED",
                "events": expected_seq - 1, "head_hash": previous,
                "external_anchor": "UNAVAILABLE", "signed": False,
            }
