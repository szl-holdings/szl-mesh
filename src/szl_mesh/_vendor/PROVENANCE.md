# Vendored: khipu-consensus (READ-ONLY mirror of the REAL engine)

Source of truth: https://github.com/szl-holdings/khipu-consensus  (branch `main`)
Path: `python/khipu_consensus/`

This is a byte-identical, READ-ONLY vendored copy so `szl_mesh.quorum` tests run
hermetically. It is NOT modified and NOT a reimplementation. Prefer the installed
`khipu-consensus` package when available; this vendor is the fallback.

Verified sha256:
  python/khipu_consensus/__init__.py = 7b33c053bed58a94ecb8d83b33295ff0a067fc20645e5e72bc4da6eca1980a77
  testdata/vectors.json              = 86236cdde8f9ccb2d64f5d9011dcb4db141575b7bfd54ae24985bbeeb3587270

## DCO remediation note
The merge commit 340b3dc3 ("Merge dev2/quorum-wiring: wire real khipu-consensus
3-of-4 quorum into szl-mesh") landed on main without a Signed-off-by trailer,
turning the CI `DCO Trailers` gate red while every other job (proto lint, smoke
test, markdown, SLSA L1) passed. The merge content (quorum.py, vendored
khipu_consensus, tests) is unaffected. Per standard DCO practice — and because
main is a protected, no-force-push branch with sibling work in flight — the
sign-off is remediated forward by this commit rather than by rewriting history.
The DCO gate itself is unchanged (no test disabled, no bot-skip widened).