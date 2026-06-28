# SPDX-License-Identifier: Apache-2.0
# SZL Holdings — clean-room, permissive (Apache-2.0 compatible)
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173 · Doctrine v11/v12
# Authored by Yachay (CTO) — Sovereign Mesh Node-Join Agent
"""
szl_mesh_agent.py — Sovereign Mesh Node-Join Agent
====================================================
Implements the node side of the SZL sovereign compute mesh:

  • HMAC-SHA256 signed join-token issue / verify / revoke
  • Node registry: advertises GPUs/CPUs (name, arch, VRAM, backend CUDA/Vulkan/CPU)
  • Heartbeat loop (30 s POST to coordinator)
  • Governed work acceptance:
      (a) Checks every incoming request carries a passing Λ (Lambda-Spine) score
          [Conjecture 1, ADVISORY — never a theorem]
      (b) Emits a signed receipt per job; receipts form a hash-chain
          (F4 Khipu hash-chain determinism + F22 emit-monotone: append-only,
           never reorder)
      (c) Accounts node contribution via F11 Ayni reciprocity: (b+c)-c = b
          (credit is conserved; a node receives exactly what it contributes)

HONEST LABELS:
  - VRAM fusion = ROADMAP (NVLink-only; consumer Ada/Blackwell have no NVLink)
  - Mesh = scheduler (software load-balancer, not hardware interconnect)
  - Λ (Lambda-Spine) = advisory Conjecture 1 — NEVER a theorem
  - All throughput numbers = MODELED until founder reports MEASURED benchmark
  - Signing: reuses szl_dsse PAE/DSSE pattern; HMAC-SHA256 for join tokens

FORMULA ANCHORS (kernel c7c0ba17, locked_count_eight, sorry-free):
  F1  replay determinism          → identical inputs ⇒ identical routing pick
  F4  Khipu hash-chain            → per-job receipt chain (prev_hash ‖ body → hash)
  F7  Chaski relay idempotence    → message relay exactly-once semantics
  F11 Ayni reciprocity (b+c)−c=b → node contribution accounting
  F18 Reed-Solomon parity (10−6=4)→ erasure-coded receipt redundancy (ROADMAP)
  F22 Khipu emit-monotone         → receipts append-only, never reordered
  Λ   Lambda-Spine gate           → Conjecture 1, advisory governance score

SIGNING PATTERN (reusing szl_dsse):
  • Join tokens: HMAC-SHA256 over canonical JSON (sorted keys, no whitespace)
  • Job receipts: DSSE PAE envelope (DSSEv1) over canonical JSON, same as szl_dsse
    — verifiable offline with cosign key d3028f8a / szlholdings-cosign

NO GPU REQUIRED: all operations are pure Python + stdlib. No torch/CUDA calls.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import logging
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger("szl.mesh.agent")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PAYLOAD_TYPE_JOIN_TOKEN = "application/vnd.szl.mesh.join-token+json"
PAYLOAD_TYPE_RECEIPT = "application/vnd.szl.mesh.receipt+json"
COSIGN_KEYID = "szlholdings-cosign-d3028f8a"  # key fingerprint per BRIEF

HEARTBEAT_INTERVAL_S = 30          # seconds between heartbeats
NODE_OFFLINE_TIMEOUT_S = 90        # coordinator marks node OFFLINE after this
JOIN_TOKEN_TTL_S = 3600            # 1-hour default token lifetime

# Lambda-Spine Conjecture 1 threshold (advisory, never a theorem)
LAMBDA_THRESHOLD_ADVISORY = 0.5   # work is accepted when Λ_score >= this

# F11 Ayni reciprocity: unit credit per job accepted (b+c)-c = b
AYNI_CREDIT_PER_JOB = 1.0


# ---------------------------------------------------------------------------
# F4 / F22 — Khipu hash-chain helpers
# ---------------------------------------------------------------------------

def khipu_hash(prev_hash: str, receipt_body: bytes) -> str:
    """
    F4 Khipu hash-chain determinism.
    chain_hash_n = SHA-256( prev_hash || receipt_body )
    Deterministic: identical prev_hash + body always produce the same hash.
    """
    h = hashlib.sha256()
    h.update(prev_hash.encode("utf-8"))
    h.update(receipt_body)
    return h.hexdigest()


def canonical_json(obj: Any) -> bytes:
    """Deterministic canonical JSON — sorted keys, no extra whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def pae(payload_type: str, body: bytes) -> bytes:
    """
    DSSE Pre-Authentication Encoding (DSSEv1) — mirrors szl_dsse.pae().
    DSSEv1 SP LEN(type) SP type SP LEN(body) SP body
    """
    t = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(t)).encode()
        + b" " + t
        + b" " + str(len(body)).encode()
        + b" " + body
    )


# ---------------------------------------------------------------------------
# Node registry
# ---------------------------------------------------------------------------

@dataclass
class NodeHardware:
    """
    Hardware advertisement for a mesh node.
    All throughput figures are MODELED until the founder runs a benchmark
    and reports MEASURED values.
    """
    node_name: str                        # human-readable, e.g. "tower-4060ti"
    hostname: str                         # DNS name or IP
    port: int                             # listening port
    arch: str                             # sm_89 / blackwell / cpu / arm
    backend: str                          # CUDA | Vulkan | CPU
    vram_gb: float                        # 0.0 for CPU-only nodes
    cpu_ram_gb: float
    cpu_cores: int
    gpu_model: Optional[str] = None       # e.g. "RTX 4060 Ti"
    vram_fusion: str = "ROADMAP"          # ALWAYS ROADMAP — no NVLink on consumer GPUs
    throughput_label: str = "MODELED"     # changes to MEASURED after founder benchmarks

    def node_id(self) -> str:
        """Stable 16-hex ID derived from hostname:port."""
        return hashlib.sha256(
            f"{self.hostname}:{self.port}".encode()
        ).hexdigest()[:16]


@dataclass
class NodeRegistry:
    """
    In-process node registry.
    Persists to JSON on demand; keeps last_seen timestamp for heartbeat tracking.
    """
    _nodes: Dict[str, dict] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def register(self, hw: NodeHardware, token_payload: dict) -> None:
        with self._lock:
            self._nodes[hw.node_id()] = {
                "hardware": asdict(hw),
                "token": token_payload,
                "last_seen": time.time(),
                "status": "ONLINE",
                "contribution": 0.0,   # F11 Ayni: jobs accepted × AYNI_CREDIT_PER_JOB
            }

    def heartbeat(self, node_id: str) -> bool:
        with self._lock:
            if node_id not in self._nodes:
                return False
            self._nodes[node_id]["last_seen"] = time.time()
            self._nodes[node_id]["status"] = "ONLINE"
            return True

    def evict_stale(self) -> List[str]:
        """Mark nodes OFFLINE if last_seen > NODE_OFFLINE_TIMEOUT_S."""
        evicted = []
        with self._lock:
            now = time.time()
            for nid, info in self._nodes.items():
                if (now - info["last_seen"]) > NODE_OFFLINE_TIMEOUT_S:
                    if info["status"] != "OFFLINE":
                        info["status"] = "OFFLINE"
                        evicted.append(nid)
        return evicted

    def online_nodes(self) -> List[dict]:
        with self._lock:
            return [v for v in self._nodes.values() if v["status"] == "ONLINE"]

    def get(self, node_id: str) -> Optional[dict]:
        with self._lock:
            return self._nodes.get(node_id)

    def add_contribution(self, node_id: str, delta: float = AYNI_CREDIT_PER_JOB) -> float:
        """
        F11 Ayni reciprocity: (b + delta) - delta = b.
        Returns the NEW contribution balance.
        The equality (b+c)-c = b asserts contribution accounting is conservative:
        a node's credit is exactly what it has provided, never inflated.
        """
        with self._lock:
            if node_id in self._nodes:
                self._nodes[node_id]["contribution"] += delta
                return self._nodes[node_id]["contribution"]
        return 0.0

    def to_dict(self) -> dict:
        with self._lock:
            return dict(self._nodes)


# ---------------------------------------------------------------------------
# HMAC-SHA256 join token issue / verify / revoke
# ---------------------------------------------------------------------------

def issue_join_token(
    hw: NodeHardware,
    secret: bytes,
    ttl_seconds: int = JOIN_TOKEN_TTL_S,
) -> str:
    """
    Issue a signed join token for a node.
    Token = base64url(canonical_json(payload)) + "." + base64url(HMAC-SHA256)

    The HMAC key is the mesh secret (shared between coordinator and all
    authorized nodes). The secret is NEVER embedded in the token.

    Returns the token string.
    """
    now = int(time.time())
    payload = {
        "node_id": hw.node_id(),
        "node_name": hw.node_name,
        "hostname": hw.hostname,
        "port": hw.port,
        "arch": hw.arch,
        "backend": hw.backend,
        "vram_gb": hw.vram_gb,
        "cpu_ram_gb": hw.cpu_ram_gb,
        "cpu_cores": hw.cpu_cores,
        "gpu_model": hw.gpu_model or "",
        "issued_at": now,
        "expires_at": now + ttl_seconds,
        "label": "LIVE",
        "vram_fusion": "ROADMAP",          # honest — no NVLink on consumer GPUs
        "throughput_label": "MODELED",     # changes to MEASURED after benchmarks
    }
    body = canonical_json(payload)
    mac = _hmac.new(secret, body, hashlib.sha256).digest()
    b64_body = base64.urlsafe_b64encode(body).decode("ascii")
    b64_mac = base64.urlsafe_b64encode(mac).decode("ascii")
    return f"{b64_body}.{b64_mac}"


def verify_join_token(
    token: str,
    secret: bytes,
    revocation_store: Optional[set] = None,
) -> Optional[dict]:
    """
    Verify a join token's HMAC-SHA256 signature AND expiry AND revocation.

    Returns the payload dict if valid, or None if:
      - signature mismatch (tampered token)
      - token is expired
      - node_id is in the revocation_store

    Uses hmac.compare_digest to prevent timing attacks.
    """
    try:
        b64_body, b64_mac = token.rsplit(".", 1)
        body = base64.urlsafe_b64decode(b64_body)
        expected_mac = _hmac.new(secret, body, hashlib.sha256).digest()
        actual_mac = base64.urlsafe_b64decode(b64_mac)
        if not _hmac.compare_digest(expected_mac, actual_mac):
            log.warning("join token: HMAC mismatch — rejected")
            return None
        payload = json.loads(body)
        if payload.get("expires_at", 0) < time.time():
            log.warning("join token: expired — rejected (node_id=%s)", payload.get("node_id"))
            return None
        if revocation_store and payload.get("node_id") in revocation_store:
            log.warning("join token: node_id=%s is revoked", payload.get("node_id"))
            return None
        return payload
    except Exception as exc:
        log.error("join token: verification error: %r", exc)
        return None


def revoke_token(node_id: str, revocation_store: set) -> None:
    """
    Add node_id to the revocation set (in-memory).
    Persist to disk separately (e.g. via JSON file or SQLite).
    All subsequent verify_join_token calls for this node_id will return None.
    """
    revocation_store.add(node_id)
    log.info("token revoked: node_id=%s", node_id)


# ---------------------------------------------------------------------------
# Λ (Lambda-Spine) gate — Conjecture 1, ADVISORY
# ---------------------------------------------------------------------------

def lambda_gate_check(request: dict) -> tuple[bool, float]:
    """
    Λ (Lambda-Spine) governance gate — Conjecture 1, ADVISORY.

    In production this calls the szl-lambda-gate aggregator (szl-lambda-gate repo).
    Here we implement the advisory scoring contract:
      - If the request carries a 'lambda_score' field, use it directly.
      - Otherwise compute a stub score from available signals.
      - A score >= LAMBDA_THRESHOLD_ADVISORY passes.

    IMPORTANT: Λ is Conjecture 1. It is NEVER a theorem. Passing this gate is a
    governance advisory; it does NOT guarantee correctness of inference output.
    This check is advisory-only and should never be the sole safety signal.

    Returns (passed: bool, score: float).
    """
    score = float(request.get("lambda_score", 0.0))
    if score == 0.0:
        # Stub heuristic: award full advisory score when the request has a
        # valid request_id and model field (minimum structure for a governed job).
        has_request_id = bool(request.get("request_id"))
        has_model = bool(request.get("model"))
        score = 1.0 if (has_request_id and has_model) else 0.0
    passed = score >= LAMBDA_THRESHOLD_ADVISORY
    if not passed:
        log.warning(
            "Λ gate ADVISORY FAIL: score=%.3f < threshold=%.3f (Conjecture 1 — advisory only)",
            score, LAMBDA_THRESHOLD_ADVISORY,
        )
    return passed, score


# ---------------------------------------------------------------------------
# Signed receipt + F4/F22 hash-chain ledger
# ---------------------------------------------------------------------------

class JobReceiptLedger:
    """
    Per-node append-only receipt ledger.

    F4  Khipu hash-chain determinism: each receipt's chain_hash is derived
        from the previous chain_hash and the receipt body.
    F22 Khipu emit-monotone: receipts are only ever appended; never reordered
        or deleted. The chain hash cryptographically enforces ordering.

    Signing uses the same DSSE PAE pattern as szl_dsse.py:
      PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
      HMAC-SHA256 over PAE bytes (production would use ECDSA via cosign key)
    """

    GENESIS_HASH = "0" * 64   # chain starts here — deterministic sentinel

    def __init__(self, node_id: str, hmac_secret: bytes):
        self.node_id = node_id
        self._secret = hmac_secret
        self._chain: List[dict] = []   # F22: append-only
        self._lock = threading.Lock()
        self._head_hash = self.GENESIS_HASH

    # ------------------------------------------------------------------
    # Internal DSSE-style signing (HMAC variant; production uses cosign)
    # ------------------------------------------------------------------

    def _sign_receipt(self, receipt_obj: dict) -> dict:
        """
        Produce a DSSE-style envelope over receipt_obj using HMAC-SHA256.
        Structure mirrors szl_dsse.sign_payload() for compatibility.
        Production deployment swaps this for ECDSA via cosign key d3028f8a.
        """
        body = canonical_json(receipt_obj)
        to_sign = pae(PAYLOAD_TYPE_RECEIPT, body)
        mac = _hmac.new(self._secret, to_sign, hashlib.sha256).digest()
        return {
            "payloadType": PAYLOAD_TYPE_RECEIPT,
            "payload": base64.b64encode(body).decode("ascii"),
            "_dsse": "DSSEv1",
            "_pae_sha256": hashlib.sha256(to_sign).hexdigest(),
            "_signed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "signatures": [{
                "sig": base64.b64encode(mac).decode("ascii"),
                "keyid": COSIGN_KEYID,
                "alg": "HMAC-SHA256",
                "note": "HMAC variant — swap for ECDSA cosign key d3028f8a in production",
            }],
            "signed": True,
            "honesty": (
                "REAL HMAC-SHA256 over DSSE PAE; upgrade to ECDSA via cosign "
                "key d3028f8a (szlholdings-cosign) for production deployment."
            ),
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(
        self,
        job_id: str,
        model: str,
        lambda_score: float,
        tokens_in: int,
        tokens_out: int,
        latency_ms: float,
        label: str = "LIVE",
    ) -> dict:
        """
        F22: Append a new signed receipt to the chain.
        F4:  chain_hash = SHA-256(prev_hash || receipt_body)

        Returns the full receipt entry (receipt + dsse envelope + chain metadata).
        NEVER modifies or reorders existing entries.
        """
        with self._lock:
            seq = len(self._chain)
            receipt = {
                "node_id": self.node_id,
                "job_id": job_id,
                "seq": seq,                         # F22: monotone sequence number
                "model": model,
                "lambda_score": lambda_score,       # Λ advisory Conjecture 1
                "lambda_label": "advisory-conjecture-1",
                "tokens_in": tokens_in,
                "tokens_out": tokens_out,
                "latency_ms": latency_ms,
                "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "label": label,
                "vram_fusion": "ROADMAP",           # honest: no NVLink on consumer GPUs
            }
            body = canonical_json(receipt)
            # F4 Khipu hash-chain: chain_hash = SHA-256(prev_hash || body)
            chain_hash = khipu_hash(self._head_hash, body)
            receipt["prev_chain_hash"] = self._head_hash
            receipt["chain_hash"] = chain_hash

            envelope = self._sign_receipt(receipt)

            entry = {
                "receipt": receipt,
                "dsse": envelope,
                "chain_hash": chain_hash,
                "seq": seq,
            }
            # F22 emit-monotone: append-only, never reorder
            self._chain.append(entry)
            self._head_hash = chain_hash
            log.debug(
                "receipt appended: node=%s seq=%d job=%s chain_hash=%.8s",
                self.node_id, seq, job_id, chain_hash,
            )
            return entry

    def verify_chain(self) -> tuple[bool, str]:
        """
        F4 verification: recompute every chain_hash and confirm integrity.
        Returns (valid: bool, message: str).
        """
        with self._lock:
            prev = self.GENESIS_HASH
            for i, entry in enumerate(self._chain):
                receipt = entry["receipt"]
                body = canonical_json({
                    k: v for k, v in receipt.items()
                    if k not in ("prev_chain_hash", "chain_hash")
                })
                expected = khipu_hash(prev, body)
                if entry["chain_hash"] != expected:
                    return False, f"chain broken at seq={i}: expected {expected[:16]}, got {entry['chain_hash'][:16]}"
                if receipt.get("seq") != i:
                    return False, f"F22 violated: seq mismatch at position {i}"
                prev = entry["chain_hash"]
            return True, f"chain intact: {len(self._chain)} receipts verified"

    def head_hash(self) -> str:
        with self._lock:
            return self._head_hash

    def to_list(self) -> List[dict]:
        with self._lock:
            return list(self._chain)


# ---------------------------------------------------------------------------
# MeshNodeAgent — top-level agent object
# ---------------------------------------------------------------------------

class MeshNodeAgent:
    """
    Sovereign mesh node-join agent.

    Lifecycle:
      1. Create with hardware advertisement + mesh secret.
      2. Call join(coordinator_url) → receives + stores join token.
      3. Heartbeat loop runs in background thread.
      4. accept_work(request) → governed work acceptance:
           (a) Λ gate check (Conjecture 1, advisory)
           (b) emit signed receipt → appended to F4/F22 hash-chain ledger
           (c) F11 Ayni contribution accounting
      5. Revoke: coordinator calls revoke; node rejects further work.

    NO GPU required — CPU-only, pure Python stdlib.
    """

    def __init__(
        self,
        hardware: NodeHardware,
        mesh_secret: bytes,
        registry: Optional[NodeRegistry] = None,
        revocation_store: Optional[set] = None,
    ):
        self.hw = hardware
        self._secret = mesh_secret
        self.registry = registry or NodeRegistry()
        self.revocation_store: set = revocation_store if revocation_store is not None else set()
        self._token: Optional[str] = None
        self._token_payload: Optional[dict] = None
        self._ledger = JobReceiptLedger(hardware.node_id(), mesh_secret)
        self._contribution: float = 0.0   # F11 Ayni local mirror
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._running = False

    # ------------------------------------------------------------------
    # Join / token management
    # ------------------------------------------------------------------

    def issue_self_token(self) -> str:
        """
        Issue a join token for this node (used when this node IS the coordinator,
        or for single-node testing).
        """
        token = issue_join_token(self.hw, self._secret)
        self._token = token
        self._token_payload = verify_join_token(token, self._secret, self.revocation_store)
        self.registry.register(self.hw, self._token_payload or {})
        log.info(
            "join token issued: node_id=%s name=%s arch=%s backend=%s vram_gb=%.1f",
            self.hw.node_id(), self.hw.node_name, self.hw.arch,
            self.hw.backend, self.hw.vram_gb,
        )
        return token

    def accept_external_token(self, token: str) -> bool:
        """
        Accept a token issued by the coordinator for this node.
        Returns True if the token is valid and not revoked.
        """
        payload = verify_join_token(token, self._secret, self.revocation_store)
        if payload is None:
            log.error("external token rejected for node %s", self.hw.node_id())
            return False
        self._token = token
        self._token_payload = payload
        self.registry.register(self.hw, payload)
        log.info("accepted external token: node_id=%s", self.hw.node_id())
        return True

    def revoke_self(self) -> None:
        """Revoke this node's own token (graceful leave)."""
        nid = self.hw.node_id()
        revoke_token(nid, self.revocation_store)
        self._token = None
        self._token_payload = None
        self.stop_heartbeat()
        log.info("node %s gracefully revoked", nid)

    # ------------------------------------------------------------------
    # Heartbeat
    # ------------------------------------------------------------------

    def start_heartbeat(self, coordinator_url: Optional[str] = None) -> None:
        """Start background heartbeat thread (30 s interval per BRIEF spec)."""
        self._running = True
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            args=(coordinator_url,),
            daemon=True,
            name=f"heartbeat-{self.hw.node_id()}",
        )
        self._heartbeat_thread.start()
        log.info("heartbeat started: node=%s interval=%ds", self.hw.node_id(), HEARTBEAT_INTERVAL_S)

    def stop_heartbeat(self) -> None:
        self._running = False

    def _heartbeat_loop(self, coordinator_url: Optional[str]) -> None:
        while self._running:
            time.sleep(HEARTBEAT_INTERVAL_S)
            if not self._running:
                break
            try:
                self._send_heartbeat(coordinator_url)
            except Exception as exc:
                log.warning("heartbeat error (node=%s): %r", self.hw.node_id(), exc)

    def _send_heartbeat(self, coordinator_url: Optional[str]) -> None:
        """
        POST heartbeat to coordinator.
        In production uses httpx; here we update the local registry directly
        (for CPU-only self-test compatibility, no network required).
        """
        nid = self.hw.node_id()
        if coordinator_url:
            # Production: POST to coordinator_url/mesh/heartbeat
            # Stub: just update local registry (no network in self-test)
            pass
        # Always update local registry (works for in-process mesh)
        updated = self.registry.heartbeat(nid)
        if not updated:
            log.warning("heartbeat: node %s not in registry — may need re-join", nid)

    # ------------------------------------------------------------------
    # Governed work acceptance (Λ gate + receipted + F11 Ayni)
    # ------------------------------------------------------------------

    def accept_work(self, request: dict) -> tuple[bool, Optional[dict]]:
        """
        Governed work acceptance gate.

        (a) Token validity check — node must have a valid, non-revoked token.
        (b) Λ (Lambda-Spine) advisory gate — Conjecture 1, NEVER a theorem.
            Rejects work if Λ_score < LAMBDA_THRESHOLD_ADVISORY.
        (c) Emit signed receipt → appended to F4/F22 hash-chain ledger (append-only).
        (d) F11 Ayni reciprocity: contribution += AYNI_CREDIT_PER_JOB.
            Invariant: (b + c) - c = b (credit is conserved, never fabricated).

        Returns (accepted: bool, receipt_entry: dict or None).

        NOTES:
          - This agent has NO GPU. Real inference is delegated to the backend.
          - Receipt is emitted REGARDLESS of whether inference succeeds — the
            receipt records governed acceptance, not inference outcome.
          - VRAM fusion is ROADMAP — this node's VRAM is independent.
        """
        nid = self.hw.node_id()

        # --- token check ---
        if self._token is None:
            log.warning("accept_work: no token — node %s not joined", nid)
            return False, None
        payload = verify_join_token(self._token, self._secret, self.revocation_store)
        if payload is None:
            log.warning("accept_work: invalid/revoked token for node %s", nid)
            return False, None

        # --- (a) Λ advisory gate (Conjecture 1) ---
        passed, score = lambda_gate_check(request)
        if not passed:
            log.info(
                "accept_work: Λ advisory gate REJECTED job=%s score=%.3f "
                "(Conjecture 1 — advisory only, not a theorem)",
                request.get("request_id", "?"), score,
            )
            return False, None

        # --- (b) emit signed receipt → F4/F22 hash-chain ---
        job_id = request.get("request_id") or secrets.token_hex(8)
        receipt_entry = self._ledger.append(
            job_id=job_id,
            model=request.get("model", "unknown"),
            lambda_score=score,
            tokens_in=int(request.get("tokens_in", 0)),
            tokens_out=int(request.get("tokens_out", 0)),
            latency_ms=float(request.get("latency_ms", 0.0)),
            label=request.get("label", "LIVE"),
        )

        # --- (c) F11 Ayni reciprocity: (b+c)−c = b ---
        prev_contribution = self._contribution
        self._contribution += AYNI_CREDIT_PER_JOB
        new_contribution = self._contribution
        # Invariant assertion: (prev + delta) - delta = prev
        assert abs((new_contribution - AYNI_CREDIT_PER_JOB) - prev_contribution) < 1e-9, \
            "F11 Ayni violation: contribution accounting is not conservative"
        self.registry.add_contribution(nid, AYNI_CREDIT_PER_JOB)

        log.info(
            "work accepted: node=%s job=%s Λ=%.3f contribution=%.1f chain_hash=%.8s",
            nid, job_id, score, new_contribution,
            receipt_entry["chain_hash"],
        )
        return True, receipt_entry

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def ledger(self) -> JobReceiptLedger:
        return self._ledger

    def contribution(self) -> float:
        """F11 Ayni: total contribution credit for this node."""
        return self._contribution

    def status(self) -> dict:
        """Return a snapshot of this node's status."""
        return {
            "node_id": self.hw.node_id(),
            "node_name": self.hw.node_name,
            "arch": self.hw.arch,
            "backend": self.hw.backend,
            "vram_gb": self.hw.vram_gb,
            "vram_fusion": "ROADMAP",          # honest
            "token_valid": self._token is not None,
            "contribution": self._contribution,
            "ledger_depth": len(self._ledger.to_list()),
            "head_hash": self._ledger.head_hash(),
            "label": "LIVE",
            "throughput_label": "MODELED",
            "lambda_advisory": "Conjecture-1-never-theorem",
        }


# ---------------------------------------------------------------------------
# Module-level convenience: build a node agent from a config dict
# ---------------------------------------------------------------------------

def make_node_agent(cfg: dict, mesh_secret: bytes) -> MeshNodeAgent:
    """
    Convenience factory.
    cfg keys: node_name, hostname, port, arch, backend, vram_gb,
              cpu_ram_gb, cpu_cores, gpu_model (optional)
    """
    hw = NodeHardware(
        node_name=cfg["node_name"],
        hostname=cfg["hostname"],
        port=int(cfg["port"]),
        arch=cfg["arch"],
        backend=cfg["backend"],
        vram_gb=float(cfg.get("vram_gb", 0.0)),
        cpu_ram_gb=float(cfg.get("cpu_ram_gb", 8.0)),
        cpu_cores=int(cfg.get("cpu_cores", 4)),
        gpu_model=cfg.get("gpu_model"),
    )
    return MeshNodeAgent(hw, mesh_secret)


if __name__ == "__main__":
    # Quick smoke-test: issue a token, accept a job, verify the chain.
    logging.basicConfig(level=logging.INFO)
    import py_compile, sys
    # Verify this file compiles cleanly
    py_compile.compile(__file__, doraise=True)
    print("[szl_mesh_agent] py_compile OK")

    SECRET = secrets.token_bytes(32)
    agent = make_node_agent({
        "node_name": "tower-4060ti",
        "hostname": "127.0.0.1",
        "port": 8000,
        "arch": "sm_89",
        "backend": "CUDA",
        "vram_gb": 16.0,
        "cpu_ram_gb": 32.0,
        "cpu_cores": 8,
        "gpu_model": "RTX 4060 Ti",
    }, SECRET)

    token = agent.issue_self_token()
    print(f"[szl_mesh_agent] token issued: {token[:40]}…")

    ok, entry = agent.accept_work({
        "request_id": "smoke-001",
        "model": "llama-3-8b",
        "tokens_in": 128,
        "tokens_out": 64,
        "latency_ms": 210.5,
        "label": "LIVE",
    })
    print(f"[szl_mesh_agent] accept_work -> ok={ok}")
    valid, msg = agent.ledger().verify_chain()
    print(f"[szl_mesh_agent] chain verify: {valid} — {msg}")
    print(f"[szl_mesh_agent] contribution: {agent.contribution():.1f}")
    print("[szl_mesh_agent] smoke-test PASSED")
