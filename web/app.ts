/**
 * web/app.ts — the M5 visualization (vanilla TS + SVG, no framework).
 *
 * Reads STRAIGHT off the kernel: run() / counterfactual() produce the two
 * timelines; reconstruct(t) gives state as-of the scrubbed tick; nodeState()
 * colours each node. The time-scrubber is just reconstruct() under a slider —
 * the "Memory River". Both panels share the slider so you watch them diverge.
 *
 * Imports only browser-safe modules (kernel). No lan.ts / node:dgram here.
 */

import {
  type Event,
  type NodeId,
  type NodeState,
  type Observation,
  type State,
  type Timeline,
  STAR,
  counterfactual,
  diff,
  makeId,
  nodeState,
  reconstruct,
  run,
  verdict,
} from "../src/kernel";

// ── the canonical scenario: two floods on the hub, Bravo ──
const scenario: Observation[] = [
  { id: makeId("PacketFlood", "Bravo", 1), t: 1, kind: "PacketFlood", node: "Bravo", rate: 8000 },
  { id: makeId("PacketFlood", "Bravo", 2), t: 2, kind: "PacketFlood", node: "Bravo", rate: 9500 },
];

const actual = run(scenario);
const cf = counterfactual(scenario, { do: { "Quarantine:Bravo": false } });
const divergence = diff(actual.timeline, cf.timeline);

const maxTick = Math.max(
  ...actual.timeline.map((e) => e.t),
  ...cf.timeline.map((e) => e.t),
  1,
);

// ── star layout positions (Bravo in the centre) ──
const W = 360;
const H = 230;
const POS: Record<NodeId, { x: number; y: number }> = {
  Bravo: { x: W / 2, y: H / 2 },
  Alpha: { x: W / 2, y: 44 },
  Charlie: { x: 70, y: H - 50 },
  Delta: { x: W - 70, y: H - 50 },
};

const COLOR: Record<NodeState, string> = {
  HEALTHY: "var(--healthy)",
  ALERT: "var(--alert)",
  EXPOSED: "var(--exposed)",
  ISOLATED: "var(--isolated)",
  SCARRED: "var(--scarred)",
};

const SVGNS = "http://www.w3.org/2000/svg";
const el = (id: string) => document.getElementById(id)!;

function fmt(e: Event): string {
  switch (e.kind) {
    case "PacketFlood": return `FLOOD ${e.node} (${e.rate}/s)`;
    case "HeartbeatLost": return `heartbeat-lost ${e.node}`;
    case "SignatureInvalid": return `bad-sig ${e.node}`;
    case "RouteFailure": return `route-fail ${e.from}→${e.to}`;
    case "Heartbeat": return `heartbeat ${e.node}`;
    case "TrustDrop": return `trust-- ${e.node}`;
    case "TrustRegen": return `trust++ ${e.node}`;
    case "Quarantine": return `QUARANTINE ${e.node}`;
    case "Reroute": return `reroute ${e.from}→${e.to}`;
    case "Spread": return `SPREAD ${e.from}→${e.to}`;
    case "Recovery": return `recovery ${e.node}`;
    case "Collapse": return `COLLAPSE (network)`;
  }
}

const OBS = new Set(["PacketFlood", "HeartbeatLost", "SignatureInvalid", "RouteFailure", "Heartbeat"]);
const isInfected = (s: State, n: NodeId) => s.infected.has(n) && !s.recovered.has(n);

function drawMesh(state: State): SVGSVGElement {
  const svg = document.createElementNS(SVGNS, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);

  // edges (undirected, de-duplicated)
  const seen = new Set<string>();
  for (const [from, tos] of Object.entries(STAR.edges)) {
    for (const to of tos) {
      const key = [from, to].sort().join("-");
      if (seen.has(key)) continue;
      seen.add(key);
      const a = POS[from], b = POS[to];
      if (!a || !b) continue;
      const line = document.createElementNS(SVGNS, "line");
      line.setAttribute("x1", `${a.x}`); line.setAttribute("y1", `${a.y}`);
      line.setAttribute("x2", `${b.x}`); line.setAttribute("y2", `${b.y}`);
      line.setAttribute("stroke", "var(--edge)"); line.setAttribute("stroke-width", "2");
      svg.appendChild(line);
    }
  }

  // nodes
  for (const n of STAR.nodes) {
    const p = POS[n]; if (!p) continue;
    const st = nodeState(state, n);
    const infected = isInfected(state, n);
    const fill = infected ? "var(--dead)" : COLOR[st];

    const c = document.createElementNS(SVGNS, "circle");
    c.setAttribute("cx", `${p.x}`); c.setAttribute("cy", `${p.y}`);
    c.setAttribute("r", "20");
    c.setAttribute("fill", fill);
    c.setAttribute("fill-opacity", "0.85");
    c.setAttribute("stroke", "#0d1117"); c.setAttribute("stroke-width", "2");
    svg.appendChild(c);

    const label = document.createElementNS(SVGNS, "text");
    label.setAttribute("x", `${p.x}`); label.setAttribute("y", `${p.y - 26}`);
    label.setAttribute("text-anchor", "middle"); label.setAttribute("class", "node-label");
    label.textContent = n;
    svg.appendChild(label);

    const trust = document.createElementNS(SVGNS, "text");
    trust.setAttribute("x", `${p.x}`); trust.setAttribute("y", `${p.y + 4}`);
    trust.setAttribute("text-anchor", "middle"); trust.setAttribute("class", "node-trust");
    trust.textContent = (state.trust[n] ?? 1).toFixed(1);
    svg.appendChild(trust);
  }
  return svg;
}

function renderPanel(rootId: string, title: string, tag: string, timeline: Timeline, t: number) {
  const root = el(rootId);
  root.innerHTML = "";
  const state = reconstruct(timeline, t);

  const h = document.createElement("h2");
  h.textContent = title;
  const v = document.createElement("span");
  const dead = !state.alive;
  v.className = `verdict ${dead ? "v-collapsed" : "v-survived"}`;
  v.textContent = dead ? "COLLAPSED" : "SURVIVED";
  h.appendChild(v);
  root.appendChild(h);

  const tagEl = document.createElement("div");
  tagEl.className = "tag";
  tagEl.textContent = tag;
  root.appendChild(tagEl);

  root.appendChild(drawMesh(state));

  const log = document.createElement("div");
  log.className = "log";
  for (const e of timeline.filter((e) => e.t <= t)) {
    const row = document.createElement("div");
    const cls = OBS.has(e.kind) ? "obs" : e.kind === "Spread" || e.kind === "Collapse" ? "bad" : "dec";
    row.className = cls;
    row.textContent = `t${e.t}  ${fmt(e)}`;
    log.appendChild(row);
  }
  root.appendChild(log);
}

function render(t: number) {
  el("tickval").textContent = `${t}`;
  renderPanel("panel-actual", "ACTUAL", "policy intact", actual.timeline, t);
  renderPanel("panel-cf", "COUNTERFACTUAL", "do(Quarantine:Bravo = false)", cf.timeline, t);
  const d = el("diverge");
  d.textContent =
    t >= divergence.divergedAt && divergence.divergedAt >= 0
      ? `▲ timelines diverge at t${divergence.divergedAt} — same inputs, different policy, opposite fate.`
      : "";
}

const scrub = el("scrub") as HTMLInputElement;
scrub.max = `${maxTick}`;
scrub.value = `${maxTick}`;
el("tickmax").textContent = `${maxTick}`;
scrub.addEventListener("input", () => render(Number(scrub.value)));
render(maxTick);
