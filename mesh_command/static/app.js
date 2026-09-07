(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);
  const sample = {
    snapshots: [
      {
        node_id: "field-alpha",
        clock: { values: { "field-alpha": 4, "relay-one": 1 } },
        registers: [
          { key: "mission.phase", value: "observe", logical_time: 4, writer: "field-alpha", tombstone: false },
          { key: "contact.alpha", value: { confidence: 0.62, state: "declared" }, logical_time: 3, writer: "field-alpha", tombstone: false }
        ]
      },
      {
        node_id: "field-bravo",
        clock: { values: { "field-bravo": 3, "relay-one": 1 } },
        registers: [
          { key: "mission.phase", value: "hold", logical_time: 4, writer: "field-bravo", tombstone: false },
          { key: "contact.bravo", value: { confidence: 0.71, state: "declared" }, logical_time: 3, writer: "field-bravo", tombstone: false }
        ]
      },
      {
        node_id: "relay-one",
        clock: { values: { "relay-one": 2, "field-alpha": 2, "field-bravo": 1 } },
        registers: [
          { key: "mission.phase", value: "observe", logical_time: 3, writer: "relay-one", tombstone: false },
          { key: "relay.window", value: "2026-09-07T12:00:00Z", logical_time: 2, writer: "relay-one", tombstone: false }
        ]
      }
    ],
    include_tombstones: false
  };

  async function requestJSON(url, options = {}) {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(url, {
        ...options,
        credentials: "same-origin",
        cache: "no-store",
        signal: controller.signal,
        headers: { "Accept": "application/json", ...(options.headers || {}) }
      });
      const payload = await response.json().catch(() => ({ detail: "Non-JSON response" }));
      if (!response.ok) throw new Error(payload.detail || `HTTP ${response.status}`);
      return payload;
    } finally {
      window.clearTimeout(timeout);
    }
  }

  const create = (tag, className, value) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined) node.textContent = String(value);
    return node;
  };

  function reset() {
    $("#snapshots").value = JSON.stringify(sample, null, 2);
    $("#output").textContent = "Waiting for a bounded merge.";
    $("#merge-state").textContent = "NOT RUN";
    $("#conflict-count").textContent = "—";
    $("#receipt-short").textContent = "—";
    const receipt = $("#receipt");
    receipt.className = "receipt empty";
    receipt.textContent = "Run the deterministic proof to inspect merged clocks, selected registers, conflicts, and the committed output digest.";
  }

  function renderTopology(payload) {
    const root = $("#topology");
    root.replaceChildren();
    const nodes = Array.isArray(payload.nodes) ? payload.nodes : [];
    const edges = Array.isArray(payload.edges) ? payload.edges : [];
    $("#node-count").textContent = nodes.length;
    $("#link-count").textContent = edges.filter((edge) => edge.state === "AVAILABLE").length;
    for (const item of nodes) {
      const card = create("div", "topology-card");
      card.setAttribute("role", "listitem");
      const copy = create("span");
      copy.append(create("strong", "", item.id));
      copy.append(create("small", "", `${item.role} · ${item.authority}`));
      card.append(copy);
      card.append(create("span", `state ${String(item.link).toLowerCase()}`, item.link));
      root.append(card);
    }
  }

  function renderReceipt(payload) {
    const root = $("#receipt");
    root.className = "receipt";
    root.replaceChildren();
    const list = create("dl");
    const rows = [
      ["Algorithm", payload.algorithm],
      ["Merged clock", JSON.stringify(payload.merged_clock)],
      ["Registers", payload.registers?.length ?? 0],
      ["Conflicts", payload.conflicts?.length ?? 0],
      ["Input digest", payload.receipt?.input_digest || "UNAVAILABLE"],
      ["Output digest", payload.receipt?.output_digest || "UNAVAILABLE"],
      ["Network", payload.network_state],
      ["Execution authority", String(payload.execution_authority)]
    ];
    for (const [key, value] of rows) {
      const wrap = create("div");
      wrap.append(create("dt", "", key));
      wrap.append(create("dd", "", value));
      list.append(wrap);
    }
    root.append(list);
  }

  async function loadTopology() {
    $("#runtime").textContent = "SOURCE · CHECKING";
    try {
      const [topology, source, readiness] = await Promise.all([
        requestJSON("/api/topology"),
        requestJSON("/api/source"),
        requestJSON("/readyz")
      ]);
      renderTopology(topology);
      $("#revision").textContent = `revision ${source.revision || "UNAVAILABLE"}`;
      $("#runtime").textContent = readiness.status === "ready" ? "READY · SIMULATION ONLY" : "NOT READY";
    } catch (error) {
      $("#runtime").textContent = `UNAVAILABLE · ${error.message}`;
      $("#topology").textContent = "Topology evidence unavailable.";
    }
  }

  async function merge() {
    const output = $("#output");
    const state = $("#merge-state");
    let body;
    try {
      body = JSON.parse($("#snapshots").value);
    } catch (error) {
      state.textContent = "INVALID JSON";
      output.textContent = error.message;
      return;
    }
    state.textContent = "MERGING";
    output.textContent = "Computing deterministic convergence…";
    try {
      const payload = await requestJSON("/api/simulate/merge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      output.textContent = JSON.stringify(payload, null, 2);
      state.textContent = "RECEIPT VERIFIED";
      $("#conflict-count").textContent = payload.conflicts?.length ?? 0;
      $("#receipt-short").textContent = `${payload.receipt.output_digest.slice(0, 12)}…`;
      renderReceipt(payload);
    } catch (error) {
      state.textContent = "BLOCKED";
      output.textContent = error.message;
    }
  }

  $("#run-demo").addEventListener("click", merge);
  $("#refresh").addEventListener("click", loadTopology);
  $("#reset").addEventListener("click", reset);
  reset();
  loadTopology();
})();
