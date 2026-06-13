"""
szl_mesh.harness — in-process multi-node mesh harness.

Spins up N MeshNode instances against a shared FormationGateway, enrolls them
(doctrine-gated), lets each write receipted CRDT state transitions, and gossips
every op+receipt to all peers IN A RANDOMISED ORDER. Because the CRDT merge is
commutative/associative/idempotent, all nodes converge to byte-identical state
regardless of delivery order — that is the real, runnable proof the mesh works.

Doctrine v11 LOCKED 749/14/163 · Kernel commit c7c0ba17 · SLSA L1.
"""

from __future__ import annotations

import random
from typing import Dict, List, Optional

from .enrollment import FormationGateway
from .node import MeshNode


class MeshHarness:
    """A collection of in-process nodes sharing one formation + CRDT doc."""

    def __init__(
        self,
        formation_id: str,
        doc_id: str,
        formation_key: bytes,
        seed: int = 0,
    ) -> None:
        self.formation_id = formation_id
        self.doc_id = doc_id
        self.formation_key = formation_key
        self.gateway = FormationGateway(formation_id, formation_key)
        self.nodes: List[MeshNode] = []
        self._rng = random.Random(seed)
        self._broadcast_log: List[Dict] = []

    def add_node(self, name: str, hardware_vendor: str = ""):
        node = MeshNode(name=name, doc_id=self.doc_id)
        result = node.enroll(
            self.gateway, self.formation_key, hardware_vendor=hardware_vendor
        )
        if result.success:
            self.nodes.append(node)
        return node, result

    def write(
        self, node: MeshNode, key: str, value, transition_class: str = "PLATFORM_STATUS"
    ) -> Dict:
        """Node writes a receipted op; record it for later gossip."""
        record = node.write(key, value, transition_class=transition_class)
        self._broadcast_log.append({"origin": node.node_id, "record": record})
        return record

    def gossip(self, shuffle: bool = True) -> None:
        """
        Deliver every broadcast record to every node except its origin, in a
        randomised order, to prove order-independent convergence.
        """
        deliveries = []
        for entry in self._broadcast_log:
            for node in self.nodes:
                if node.node_id == entry["origin"]:
                    continue
                deliveries.append((node, entry["record"]))
        if shuffle:
            self._rng.shuffle(deliveries)
        for node, record in deliveries:
            node.apply_remote(record)

    def converged(self, track: str) -> bool:
        """True iff all nodes share an identical state digest for `track`."""
        digests = {n.state_digest(track) for n in self.nodes}
        return len(digests) == 1

    def digests(self, track: str) -> Dict[str, str]:
        return {n.name: n.state_digest(track) for n in self.nodes}
