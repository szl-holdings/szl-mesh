# Spec 08: Relational-Graph Mesh Topology

**Invention 8 — topology lens (additive)**
**Doctrine:** v11 LOCKED `749/14/163` · Kernel commit `c7c0ba17`
**Status:** Design + kernel-checked structural witness · Λ = Conjecture 1 (NOT theorem) · resilience claim = OPEN hypothesis

---

## 1. Provenance — inspired by, not copied from

You, Leskovec, He & Xie, *Graph Structure of Neural Networks*, ICML 2020
([arXiv:2007.06559](https://arxiv.org/abs/2007.06559)). They model a neural
network as a **relational graph**: nodes hold features, and one network layer is
one **round of message exchange**

```
x_v^{(r+1)} = AGG^{(r)}( { f^{(r)}(x_u) : u ∈ N(v) } )
```

They show *empirically* that test accuracy is a smooth function of two graph
statistics — **clustering coefficient C** and **average path length L** — with a
"sweet spot" near `C ∈ [0.43, 0.50]`, `L ∈ [1.82, 2.28]`, a region that
resembles the macaque cortex. (No theorems; the result is empirical.)

## 2. The SZL adaptation — our own

We adopt the **mathematical lens**, not the empirical claim. The SZL UDS mesh
*is already* a relational graph:

| Relational-graph concept | SZL mesh instantiation |
|---|---|
| node | an organ (sentra, amaru, rosie, killinchu, a11oy) |
| edge | a signed cross-organ span channel (`sentra.gate.*`, `amaru.sync.*`, `rosie.decision.*`, `killinchu.courier.*`, `a11oy.graph.*`) |
| round of message exchange | one corroboration round: each organ aggregates its neighbors' signed state |
| `AGG` | the doctrine-gated aggregation (deny-by-default floor, F4) |
| `f` (message fn) | the DSSE-signed span payload transform |

This reframes Specs 03 (skip-layer aggregation) and 04 (Byzantine corroboration)
as **message-exchange rounds over a fixed relational graph**, giving us two
topology statistics to reason about and optimize: **C** (local redundancy) and
**L** (global reach / corroboration latency).

## 3. Kernel-checked structural facts (NEW)

The SZL mesh topology — a11oy as hub-to-all plus a sentra–amaru–rosie–killinchu
corroboration ring — has these **machine-checked** properties (Mathlib-free,
bare Lean kernel, zero `sorry`; see
`lutar-lean Showcase/Frontier/RelationalMeshWitness.lean`, PR #238):

- **`no_isolated_organ`** — every organ has degree ≥ 2 (resilience floor: no
  single edge cut orphans an organ).
- **`a11oy_is_hub`** — a11oy has degree 4.
- **`diameter_le_two`** — every organ pair is within 2 hops ⇒ the `L` statistic
  is ceilinged at 2 (fast cross-organ corroboration).
- **`positive_clustering`** — ≥ 4 triangles (each ring edge closes through the
  hub) ⇒ `C > 0` (local redundancy).
- **`round_deterministic`** — a round of message exchange is a pure function of
  (graph, state): replayable. (Honest witness; **not** the locked F22 itself.)

## 4. What is OPEN (honesty doctrine v11)

- **"Topology shapes mesh resilience" is an OPEN engineering hypothesis**, NOT a
  theorem and NOT one of the locked-8. We do **not** claim the You-et-al accuracy
  sweet-spot transfers to SZL trust/governance resilience. To test it honestly we
  would: enumerate candidate organ topologies, measure a *defined* mesh-resilience
  metric (e.g. corroboration quorum survival under f Byzantine organs, tied to
  Spec 04 + Conjecture 2), and look for a smooth C/L relationship — reported as
  measured data with SAMPLE/SIMULATED labels, never as a proven law.
- BFT safety stays **Conjecture 2**; Λ stays **Conjecture 1**. Locked-proven set
  stays **EXACTLY 8**.

## 5. Why this matters

It gives the mesh a principled design vocabulary: when we add a 6th organ or
rewire spans, we can ask "what does this do to C and L?" and keep the proven
structural floor (connectivity, diameter, determinism) intact by construction —
verified in the kernel, not asserted.
