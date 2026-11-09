#!/usr/bin/env python3
"""szl-anatomy — the living anatomy, made reproducible.

Back end: reads ONLY the public chain (no secrets, no local state):
  /healthz          — liveness
  /api/mesh         — the mesh registry (nodes, roles, feed directions)
  /api/brain        — the brain's latest cycle receipt + promoted version
  /api/receipts     — the full receipt chain
  /api/census       — the measured-honesty census legs
  /api/benchmark    — the silicon-sweep legs (joules/token measured)
  /api/graph        — the estate graph
Front end: one page — the organism rendered live from the chain.

Run:  uvicorn app:app --port 7860   (or the Dockerfile)
Prove: every number on the page is fetched from the public dataset at request
time. If the chain is unreachable, the page fails closed. Reproduce: anyone
with Python can run this and see the same organism we do.
"""
import json, urllib.request
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

DS = "SZLHOLDINGS/frontier-54-runs"
HF = "https://huggingface.co"
app = FastAPI(title="szl-anatomy", version="1.0.0")

def _get(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": "szl-anatomy/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())

def _tree(sub=""):
    return _get(f"{HF}/api/datasets/{DS}/tree/main/{sub}?recursive=true")

def _file(path):
    return _get(f"{HF}/datasets/{DS}/resolve/main/{path}")

def _fail_closed(e):
    raise HTTPException(status_code=503, detail={
        "error": "chain_unavailable",
        "honesty": "This page serves receipts only. It fails closed rather than showing cached or fabricated data.",
        "cause": str(e)[:120]})

@app.get("/healthz")
def healthz():
    return {"ok": True, "service": "szl-anatomy", "version": app.version}

@app.get("/api/mesh")
def mesh():
    try:
        return _file("mesh/mesh.json")
    except Exception as e:
        _fail_closed(e)

@app.get("/api/brain")
def brain():
    try:
        receipts = [f["path"] for f in _tree("receipts") if f["path"].endswith(".json")]
        cycles = sorted([p for p in receipts if "brain-cycle" in p])
        if not cycles:
            return {"status": "NO_CYCLES_YET", "honesty": "the brain has not completed a cycle; no receipt exists, so no state is claimed."}
        latest = _file(cycles[-1])
        return {"latest_cycle_receipt": latest, "receipt_path": cycles[-1]}
    except Exception as e:
        _fail_closed(e)

@app.get("/api/receipts")
def receipts():
    try:
        files = sorted(f["path"] for f in _tree("receipts") if f["path"].endswith(".json"))
        rows = []
        for p in files:
            try: rows.append({"path": p, "data": _file(p)})
            except Exception: rows.append({"path": p, "data": None, "status": "UNREADABLE"})
        return {"count": len(rows), "receipts": rows}
    except Exception as e:
        _fail_closed(e)

@app.get("/api/census")
def census():
    try:
        legs = [f["path"] for f in _tree("census") if f["path"].endswith(".json")]
        return {"legs": [_file(p) for p in legs]}
    except Exception as e:
        _fail_closed(e)

@app.get("/api/benchmark")
def benchmark():
    try:
        legs = [f["path"] for f in _tree("benchmark") if f["path"].endswith(".json")]
        return {"legs": [_file(p) for p in legs]}
    except Exception as e:
        _fail_closed(e)

@app.get("/api/graph")
def graph():
    try:
        return _get(f"{HF}/datasets/SZLHOLDINGS/estate-graph/resolve/main/estate-graph.json")
    except Exception as e:
        _fail_closed(e)

app.mount("/", StaticFiles(directory="/app/static", html=True), name="static")
