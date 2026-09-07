"use strict";

const NS = "http://www.w3.org/2000/svg";
const state = { scenarios: new Map(), latest: null };
const $ = (selector) => document.querySelector(selector);

function node(tag, attrs = {}) {
  const element = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) element.setAttribute(key, value);
  return element;
}

function svgNode(tag, attrs = {}) {
  const element = document.createElementNS(NS, tag);
  for (const [key, value] of Object.entries(attrs)) element.setAttribute(key, value);
  return element;
}

function pretty(value) {
  return JSON.stringify(value ?? null, null, 2);
}

function drawMesh(replicas, converged = null) {
  const svg = $("#mesh-svg");
  svg.replaceChildren();
  const count = Math.max(2, Math.min(8, Number(replicas) || 2));
  const center = { x: 320, y: 210 };
  const radiusX = 230;
  const radiusY = 145;
  const positions = Array.from({ length: count }, (_, index) => {
    const angle = -Math.PI / 2 + (index * Math.PI * 2) / count;
    return {
      x: center.x + Math.cos(angle) * radiusX,
      y: center.y + Math.sin(angle) * radiusY,
    };
  });

  for (let from = 0; from < positions.length; from += 1) {
    for (let to = from + 1; to < positions.length; to += 1) {
      const line = svgNode("line", {
        x1: positions[from].x,
        y1: positions[from].y,
        x2: positions[to].x,
        y2: positions[to].y,
        class: "mesh-link",
      });
      line.style.animationDelay = `${(from + to) * 90}ms`;
      svg.append(line);
    }
  }

  positions.forEach((position, index) => {
    const group = svgNode("g", { class: `mesh-node ${converged === true ? "is-converged" : converged === false ? "is-diverged" : ""}` });
    const halo = svgNode("circle", { cx: position.x, cy: position.y, r: 31, class: "node-halo" });
    const body = svgNode("circle", { cx: position.x, cy: position.y, r: 19, class: "node-body" });
    const label = svgNode("text", { x: position.x, y: position.y + 49, "text-anchor": "middle", class: "node-label" });
    label.textContent = `R${index + 1}`;
    group.append(halo, body, label);
    svg.append(group);
  });
}

function setScenario(scenario) {
  $("#doc-id").value = scenario.doc_id;
  $("#replicas").value = String(scenario.replicas);
  $("#operations").value = pretty(scenario.operations);
  drawMesh(scenario.replicas, null);
}

function renderChecks(checks = {}) {
  const host = $("#checks");
  host.replaceChildren();
  const labels = {
    same_operation_set_converged: "Same operation set converged",
    replay_idempotent: "Replay remained idempotent",
    sample_merge_commutative: "Sample merge commuted",
    sample_merge_associative: "Sample merge associated",
  };
  for (const [key, label] of Object.entries(labels)) {
    const row = node("div", { class: `check-row ${checks[key] ? "pass" : "fail"}` });
    const symbol = node("span", { class: "check-symbol", "aria-hidden": "true" });
    symbol.textContent = checks[key] ? "✓" : "×";
    const copy = node("span");
    copy.textContent = label;
    row.append(symbol, copy);
    host.append(row);
  }
}

function renderReplicaLedger(rows = []) {
  const host = $("#replica-grid");
  host.replaceChildren();
  for (const row of rows) {
    const card = node("article", { class: "replica-card", tabindex: "0" });
    const head = node("div", { class: "replica-head" });
    const title = node("h3");
    title.textContent = row.replica;
    const count = node("span", { class: "pill" });
    count.textContent = `${row.operation_count} ops`;
    head.append(title, count);

    const authorized = node("code");
    authorized.textContent = `A ${String(row.authorized_digest).slice(0, 14)}`;
    const observed = node("code");
    observed.textContent = `O ${String(row.observed_digest).slice(0, 14)}`;
    const heads = node("small");
    heads.textContent = `${row.heads?.length ?? 0} winning heads`;
    card.append(head, authorized, observed, heads);
    host.append(card);
  }
}

function renderResult(result) {
  state.latest = result;
  const final = result.reconciled_replicas ?? [];
  const first = final[0] ?? {};
  const converged = result.status === "CONVERGED";
  $("#metric-replicas").textContent = String(result.replica_count ?? "—");
  $("#metric-ops").textContent = String(result.unique_operation_count ?? "—");
  $("#metric-heads").textContent = String(first.heads?.length ?? "—");
  $("#metric-state").textContent = result.status ?? "UNAVAILABLE";
  $("#metric-state").dataset.state = converged ? "pass" : "fail";
  $("#receipt").textContent = `sha256:${String(result.receipt_sha256 ?? "UNAVAILABLE").slice(0, 18)}`;
  $("#authorized-view").textContent = pretty(first.authorized_view ?? {});
  $("#observed-view").textContent = pretty(first.observed_view ?? {});
  renderChecks(result.checks);
  renderReplicaLedger(final);
  drawMesh(result.replica_count, converged);
}

async function loadSource() {
  try {
    const response = await fetch("/api/source", { cache: "no-store", headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const source = await response.json();
    $("#source-revision").textContent = source.revision ? `source ${String(source.revision).slice(0, 12)}` : "source revision unavailable";
  } catch (error) {
    $("#source-revision").textContent = "source readback unavailable";
  }
}

async function loadScenarios() {
  const service = $("#service-state");
  try {
    const response = await fetch("/api/scenarios", { cache: "no-store", headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    const select = $("#scenario-select");
    select.replaceChildren();
    for (const item of payload.items ?? []) {
      state.scenarios.set(item.slug, item.scenario);
      const option = node("option", { value: item.slug });
      option.textContent = item.slug.replaceAll("-", " ");
      select.append(option);
    }
    const first = state.scenarios.values().next().value;
    if (first) setScenario(first);
    service.textContent = "Source ready";
    service.dataset.state = "ready";
  } catch (error) {
    service.textContent = "Source unavailable";
    service.dataset.state = "error";
  }
}

$("#load-preset").addEventListener("click", () => {
  const scenario = state.scenarios.get($("#scenario-select").value);
  if (scenario) setScenario(scenario);
});

$("#replicas").addEventListener("input", (event) => drawMesh(event.target.value, null));

$("#simulate").addEventListener("click", async () => {
  const service = $("#service-state");
  service.textContent = "Reconciling finite scenario";
  service.dataset.state = "busy";
  try {
    const operations = JSON.parse($("#operations").value);
    const payload = {
      doc_id: $("#doc-id").value,
      replicas: Number($("#replicas").value),
      operations,
    };
    const response = await fetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(payload),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail ?? `HTTP ${response.status}`);
    renderResult(result);
    service.textContent = result.status === "CONVERGED" ? "Scenario converged" : "Scenario diverged";
    service.dataset.state = result.status === "CONVERGED" ? "ready" : "error";
  } catch (error) {
    service.textContent = "Scenario rejected";
    service.dataset.state = "error";
    $("#receipt").textContent = String(error.message || error);
    renderChecks({});
  }
});

renderChecks({});
drawMesh(4, null);
Promise.all([loadSource(), loadScenarios()]);
