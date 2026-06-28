# MESH_RUNBOOK.md — SZL Sovereign Mesh Operator Guide
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SZL Holdings — clean-room, permissive (Apache-2.0 compatible) -->
<!-- © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173 -->
<!-- Doctrine v11/v12 | Sign-off: Stephen Lutar -->

---

## Honest Labels (read before operating)

| Label | Meaning |
|---|---|
| **LIVE** | Running on your metal right now |
| **MEASURED** | Founder has run a real benchmark and reported the number |
| **MODELED** | Calculated estimate; may differ from real hardware |
| **ROADMAP** | Not yet built; requires missing hardware or future work |

**Critical honest caveats:**
- **VRAM fusion = ROADMAP.** RTX 4060 Ti (sm\_89) and RTX 5050 (Blackwell) have **no NVLink**. Consumer Ada and Blackwell GPUs never had NVLink. Cross-node "VRAM fusion" (presenting 16 GB + 8 GB as a single 24 GB pool) is NVLink-only — data-center H100/B200 class hardware only. Our mesh is a **scheduler**, not hardware VRAM fusion.
- **Λ (Lambda-Spine) = advisory Conjecture 1.** It is **NEVER a theorem**. The governance gate score is advisory-only; it is not a proof of inference correctness.
- **All throughput numbers = MODELED** until you run the benchmark (see §5) and update the label to MEASURED.
- **Mesh = scheduler.** The mesh routes requests to independent GPU/CPU nodes. It does not create a unified GPU address space.

---

## 1. Prerequisites

### On every node (tower, laptop, CPU box)

```bash
# Python 3.11+ required
python3 --version

# Install dependencies (no GPU needed for the mesh agent layer)
pip install cryptography httpx   # cryptography for DSSE; httpx for async heartbeat

# Verify the mesh agent compiles
python3 -m py_compile /path/to/szl_mesh_agent.py
python3 -m py_compile /path/to/szl_mesh_coordinator.py
```

### Generate a mesh secret (do this ONCE, store securely)

```bash
# On the coordinator machine (tower or a dedicated box)
python3 -c "import secrets; print(secrets.token_hex(32))" > /etc/szl/mesh_secret.hex
chmod 600 /etc/szl/mesh_secret.hex

# Export as environment variable on every node
export SZL_MESH_SECRET=$(cat /etc/szl/mesh_secret.hex)
```

The mesh secret is the HMAC-SHA256 key for all join tokens. Keep it offline; rotate on breach.

---

## 2. Running a Node

### A. Tower (RTX 4060 Ti, 16 GB VRAM) — CUDA backend

```python
# tower_node.py
import os, secrets
from szl_mesh_agent import NodeHardware, MeshNodeAgent

SECRET_HEX = os.environ["SZL_MESH_SECRET"]
SECRET = bytes.fromhex(SECRET_HEX)

hw = NodeHardware(
    node_name   = "tower-4060ti",
    hostname    = "192.168.1.10",    # your actual LAN IP
    port        = 8000,
    arch        = "sm_89",           # RTX 4060 Ti — Ada Lovelace
    backend     = "CUDA",
    vram_gb     = 16.0,
    cpu_ram_gb  = 32.0,              # adjust to your actual RAM
    cpu_cores   = 8,
    gpu_model   = "RTX 4060 Ti",
    vram_fusion = "ROADMAP",         # always ROADMAP — no NVLink
    throughput_label = "MODELED",    # change to MEASURED after benchmark
)

agent = MeshNodeAgent(hw, SECRET)
token = agent.issue_self_token()     # or accept_external_token(token) if coordinator issues
agent.start_heartbeat()

print(f"Tower node running. node_id={hw.node_id()}")
print(f"Join token (first 40 chars): {token[:40]}...")
```

```bash
python3 tower_node.py
```

### B. Laptop (RTX 5050, 8 GB VRAM) — CUDA backend

```python
# laptop_node.py
import os
from szl_mesh_agent import NodeHardware, MeshNodeAgent

SECRET = bytes.fromhex(os.environ["SZL_MESH_SECRET"])

hw = NodeHardware(
    node_name   = "laptop-5050",
    hostname    = "192.168.1.20",    # your laptop's LAN IP
    port        = 8000,
    arch        = "blackwell",       # RTX 5050 — Blackwell consumer
    backend     = "CUDA",
    vram_gb     = 8.0,
    cpu_ram_gb  = 16.0,
    cpu_cores   = 4,
    gpu_model   = "RTX 5050",
    vram_fusion = "ROADMAP",
    throughput_label = "MODELED",
)

agent = MeshNodeAgent(hw, SECRET)
token = agent.issue_self_token()
agent.start_heartbeat()
print(f"Laptop node running. node_id={hw.node_id()}")
```

### C. CPU-only box (no GPU)

```python
# cpu_node.py
import os
from szl_mesh_agent import NodeHardware, MeshNodeAgent

SECRET = bytes.fromhex(os.environ["SZL_MESH_SECRET"])

hw = NodeHardware(
    node_name   = "cpu-box",
    hostname    = "192.168.1.30",
    port        = 8000,
    arch        = "cpu",
    backend     = "CPU",
    vram_gb     = 0.0,               # no GPU
    cpu_ram_gb  = 64.0,
    cpu_cores   = 16,
    vram_fusion = "ROADMAP",
    throughput_label = "MODELED",
)

agent = MeshNodeAgent(hw, SECRET)
token = agent.issue_self_token()
agent.start_heartbeat()
print(f"CPU node running. node_id={hw.node_id()}")
```

---

## 3. Running the Coordinator

```python
# coordinator.py
import os
from szl_mesh_agent import NodeHardware
from szl_mesh_coordinator import MeshCoordinator

SECRET = bytes.fromhex(os.environ["SZL_MESH_SECRET"])

coord = MeshCoordinator(
    mesh_secret          = SECRET,
    total_model_layers   = 32,     # set to actual model layer count
    token_ttl_seconds    = 3600,   # 1-hour token TTL
)

# Join nodes (in production: call coord.join_node() from each node's HTTP request)
from szl_mesh_agent import NodeHardware

hw_tower = NodeHardware(
    node_name="tower-4060ti", hostname="192.168.1.10", port=8000,
    arch="sm_89", backend="CUDA", vram_gb=16.0, cpu_ram_gb=32.0, cpu_cores=8,
)
hw_laptop = NodeHardware(
    node_name="laptop-5050", hostname="192.168.1.20", port=8000,
    arch="blackwell", backend="CUDA", vram_gb=8.0, cpu_ram_gb=16.0, cpu_cores=4,
)

token_t, tile_t = coord.join_node(hw_tower)
token_l, tile_l = coord.join_node(hw_laptop)

print(f"Tower:  token issued, layers {tile_t.layer_start}-{tile_t.layer_end}")
print(f"Laptop: token issued, layers {tile_l.layer_start}-{tile_l.layer_end}")
print(f"Tile status: {coord.tile_status()}")
```

---

## 4. Token Issue and Revocation

### Issue a token manually

```python
import os
from szl_mesh_agent import NodeHardware, issue_join_token

SECRET = bytes.fromhex(os.environ["SZL_MESH_SECRET"])

hw = NodeHardware(
    node_name="new-node", hostname="192.168.1.50", port=8000,
    arch="cpu", backend="CPU", vram_gb=0.0, cpu_ram_gb=32.0, cpu_cores=8,
)
token = issue_join_token(hw, SECRET, ttl_seconds=3600)
print(f"Token: {token}")
```

### Verify a token

```python
from szl_mesh_agent import verify_join_token
import os

SECRET = bytes.fromhex(os.environ["SZL_MESH_SECRET"])
token = "<paste token here>"

payload = verify_join_token(token, SECRET)
if payload:
    print(f"Valid: node_id={payload['node_id']} expires={payload['expires_at']}")
else:
    print("INVALID or expired token")
```

### Revoke a node

```python
# Via coordinator (preferred — also marks tile DOWN)
coord.revoke_node(node_id="<16-hex node_id>")

# Manual (updates revocation store only)
from szl_mesh_agent import revoke_token
revocation_store = set()    # pass your shared set
revoke_token("<node_id>", revocation_store)
```

After revocation:
- The coordinator marks the tile `DOWN` — it will not receive new dispatch.
- Any `verify_join_token()` call with the revoked `node_id` in `revocation_store` returns `None`.
- The node's `accept_work()` calls will be rejected.
- On restart, the node must re-join and receive a fresh token.

---

## 5. Capturing MEASURED Throughput

These steps change the label from **MODELED** to **MEASURED** for your specific hardware.

### Tower benchmark (RTX 4060 Ti, CUDA)

```bash
# 1. Start vLLM on the tower (CPU-only flag removed once vLLM is installed)
vllm serve meta-llama/Llama-3.1-8B-Instruct \
  --port 8000 \
  --gpu-memory-utilization 0.90 \
  --max-model-len 8192 \
  2>&1 | tee tower_vllm.log

# 2. Run benchmark (install first: pip install vllm openai)
python3 -m vllm.benchmarks.benchmark_throughput \
  --model meta-llama/Llama-3.1-8B-Instruct \
  --num-prompts 200 \
  --input-len 512 \
  --output-len 128 \
  --backend openai-chat \
  --host 127.0.0.1 --port 8000 \
  2>&1 | tee tower_benchmark.txt

# 3. Record the result
grep "Throughput" tower_benchmark.txt
# Example output: "Throughput: 42.3 requests/s, 2157.0 tokens/s"
```

Once you have the number, update `hw.throughput_label = "MEASURED"` in your node script and record the value in your notes.

### Laptop benchmark (RTX 5050, CUDA)

Same procedure on the laptop. Expected MODELED: ~25–30 tokens/s for 8B Q4 on 8 GB VRAM.

### Mesh routing benchmark (2-node)

```bash
# With both nodes running, run the mesh benchmark against the coordinator
python3 - <<'EOF'
import time
from szl_mesh_coordinator import MeshCoordinator
# ... (join both nodes as shown in §3)
# Then dispatch 100 requests and measure wall time
start = time.perf_counter()
for i in range(100):
    coord.dispatch({"request_id": f"bench-{i}", "model": "llama-3-8b", "label": "LIVE"})
elapsed = time.perf_counter() - start
print(f"100 dispatches in {elapsed:.3f}s = {100/elapsed:.1f} dispatches/s")
EOF
```

---

## 6. Laptop-Leaves Degradation Behavior

When the laptop disconnects (closes lid, switches to Wi-Fi, loses power):

1. **Heartbeat timeout (90 s):** The coordinator's `evict_stale_tiles()` marks the laptop tile `DOWN` with `down_reason = "heartbeat timeout: Xs since last seen"`.

2. **Routing behavior:**
   - All new `dispatch()` calls skip the DOWN tile.
   - If the tower is still UP: all traffic routes to the tower. **No fabrication, no panic.**
   - If both nodes are DOWN: `dispatch()` returns `{"dispatched": False, "degraded": True, ...}` with an honest reason string listing the DOWN nodes.

3. **What you'll see in the coordinator status:**
   ```python
   coord.tile_status()
   # → [..., {"node_name": "laptop-5050", "status": "DOWN",
   #          "down_reason": "heartbeat timeout: 95s since last seen", ...}]
   ```

4. **Laptop returns:**
   - Laptop restarts its node script → calls `issue_self_token()` (or requests a new token from coordinator).
   - Coordinator receives heartbeat → tile status flips to `UP`.
   - Routing resumes to the laptop within one dispatch cycle.

5. **Never fabricated:** The coordinator never pretends the laptop is UP, never invents a successful dispatch to a DOWN node. The only path is honest degradation to available nodes.

---

## 7. Receipt Chain Inspection

```python
# Inspect the node's F4/F22 receipt chain
chain = agent.ledger().to_list()
for entry in chain:
    r = entry["receipt"]
    print(f"  seq={r['seq']} job={r['job_id']} Λ={r['lambda_score']:.2f} hash={r['chain_hash'][:12]}…")

# Verify chain integrity (F4)
valid, msg = agent.ledger().verify_chain()
print(f"Chain valid: {valid} — {msg}")
```

```python
# Inspect coordinator routing ledger
coord_chain = coord.routing_ledger().to_list()
valid, msg = coord.routing_ledger().verify_chain()
print(f"Routing chain valid: {valid} — {msg}")
```

---

## 8. Self-Tests

```bash
cd /home/user/workspace/team/mesh/code
python3 test_mesh.py
```

Expected output: all tests PASS. Any FAIL indicates a regression.

The test suite (no GPU, no network required) covers:
- Token issue, verify, tamper rejection, expiry
- Two-node join + job dispatch
- F4/F22 receipt hash-chain integrity + append-only invariant
- F11 Ayni reciprocity accounting
- Token revocation (node rejected post-revoke)
- Node-down degradation (honest DEGRADED result, no fabrication)
- F1 replay determinism (same input → same node pick)
- F7 Chaski idempotence (duplicate request_id rejected)
- py_compile on all three Python files

---

## 9. Formula Reference (ground truth, kernel c7c0ba17)

| Formula | Name | Role in mesh | Status |
|---|---|---|---|
| F1 | Replay determinism | `f1_seeded_pick()`: same request_id + candidates → same node | Proven, locked |
| F4 | Khipu hash-chain | Per-node receipt chain: `SHA-256(prev_hash ‖ body)` | Proven, locked |
| F7 | Chaski idempotence | Relay dedup: request_id seen → ignore duplicate | Proven, locked |
| F11 | Ayni reciprocity | `(b+c)−c = b`: contribution is conserved, never inflated | Proven, locked |
| F18 | Reed-Solomon parity | Erasure-coded receipt redundancy across nodes | Proven, ROADMAP impl |
| F22 | Khipu emit-monotone | Receipts append-only, seq strictly monotone, never reorder | Proven, locked |
| Λ | Lambda-Spine | Advisory governance gate — **Conjecture 1, NEVER a theorem** | Advisory |
| Khipu BFT | 3-of-4 witness | Multi-party receipt agreement — **Conjecture 2, ROADMAP** | ROADMAP |

---

*Sign-off: Stephen Lutar, SZL Holdings — 2026-06*
