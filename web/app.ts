/**
 * web/app.ts — Chimera interactive sandbox (vanilla TS + SVG, no framework).
 *
 * You are the operator. Click a node to attack it. The network reacts live, and
 * Chimera replays the SAME attack with the auto-defense switched off — so you can
 * SEE, in plain English, whether your defense is what saved the network.
 *
 * Everything is read straight off the pure kernel: run() / counterfactual() /
 * reconstruct() / nodeState() / explain(). No bespoke logic lives here.
 *
 * Imports only browser-safe modules (the kernel). No lan.ts / node:dgram.
 */

import {
  type Event,
  type Intervention,
  type NodeId,
  type NodeState,
  type Observation,
  type State,
  type Timeline,
  STAR,
  explain,
  makeId,
  nodeState,
  reconstruct,
  run,
} from "../src/kernel";

// ── interventions ──
const NO_DEFENSE: Intervention = {
  do: Object.fromEntries(STAR.nodes.map((n) => [`Quarantine:${n}`, false])),
};

// ── mutable UI state ──
let attacks: Observation[] = [];
let defenseOn = true;
let playTick = 0;
let timer: ReturnType<typeof setInterval> | null = null;
let selected: string | null = null;

// ── layout ──
const W = 420, H = 340;
const POS: Record<NodeId, { x: number; y: number }> = {
  Bravo: { x: W / 2, y: H / 2 },
  Alpha: { x: W / 2, y: 56 },
  Charlie: { x: 86, y: H - 64 },
  Delta: { x: W - 86, y: H - 64 },
};
const COLOR: Record<NodeState, string> = {
  HEALTHY: "var(--healthy)", ALERT: "var(--alert)", EXPOSED: "var(--exposed)",
  ISOLATED: "var(--isolated)", SCARRED: "var(--scarred)",
};
const SVGNS = "http://www.w3.org/2000/svg";
const $ = (id: string) => document.getElementById(id)!;
const isInfected = (s: State, n: NodeId) => s.infected.has(n) && !s.recovered.has(n);

function fmt(e: Event): string {
  switch (e.kind) {
    case "PacketFlood": return `attack flood → ${e.node}`;
    case "HeartbeatLost": return `lost heartbeat → ${e.node}`;
    case "SignatureInvalid": return `bad signature → ${e.node}`;
    case "RouteFailure": return `route failure ${e.from}→${e.to}`;
    case "Heartbeat": return `clean heartbeat → ${e.node}`;
    case "TrustDrop": return `trust dropped on ${e.node}`;
    case "TrustRegen": return `trust recovering on ${e.node}`;
    case "Quarantine": return `🛡️ QUARANTINED ${e.node} (defense acted)`;
    case "Reroute": return `rerouted ${e.from}→${e.to}`;
    case "Spread": return `☣️ infection SPREAD ${e.from}→${e.to}`;
    case "Recovery": return `✅ ${e.node} recovered`;
    case "Collapse": return `💀 NETWORK COLLAPSED`;
  }
}

// ── core compute ──
function compute() {
  const withDef = run(attacks);
  const withoutDef = run(attacks, NO_DEFENSE);
  const chosen = defenseOn ? withDef : withoutDef;
  return { withDef, withoutDef, chosen };
}

// ── rendering ──
function drawMesh(state: State) {
  const svg = $("mesh");
  svg.innerHTML = "";
  // edges
  const seen = new Set<string>();
  for (const [from, tos] of Object.entries(STAR.edges)) {
    for (const to of tos) {
      const key = [from, to].sort().join("-");
      if (seen.has(key)) continue; seen.add(key);
      const a = POS[from], b = POS[to]; if (!a || !b) continue;
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
    const g = document.createElementNS(SVGNS, "g");
    g.setAttribute("class", "nodewrap");
    g.addEventListener("click", () => attack(n));

    const c = document.createElementNS(SVGNS, "circle");
    c.setAttribute("class", "node");
    c.setAttribute("cx", `${p.x}`); c.setAttribute("cy", `${p.y}`);
    c.setAttribute("r", infected ? "26" : "23");
    c.setAttribute("fill", fill); c.setAttribute("fill-opacity", "0.9");
    c.setAttribute("stroke", "#0d1117"); c.setAttribute("stroke-width", "2.5");
    g.appendChild(c);

    const label = text(p.x, p.y - 30, n, "node-label"); g.appendChild(label);
    const tr = text(p.x, p.y + 1, `trust ${(state.trust[n] ?? 1).toFixed(1)}`, "node-trust"); g.appendChild(tr);
    const stt = text(p.x, p.y + 14, st, "node-state"); stt.setAttribute("fill", fill); g.appendChild(stt);
    svg.appendChild(g);
  }
}
function text(x: number, y: number, s: string, cls: string) {
  const t = document.createElementNS(SVGNS, "text");
  t.setAttribute("x", `${x}`); t.setAttribute("y", `${y}`);
  t.setAttribute("text-anchor", "middle"); t.setAttribute("class", cls);
  t.textContent = s; return t;
}

function renderLog(timeline: Timeline, upto: number) {
  const log = $("log"); log.innerHTML = "";
  const shown = timeline.filter((e) => e.t <= upto);
  if (!shown.length) { log.innerHTML = `<div class="row">No events yet — attack a node.</div>`; return; }
  for (const e of shown) {
    const row = document.createElement("div");
    const cls = e.kind === "Spread" || e.kind === "Collapse" ? "bad"
      : (e.kind === "PacketFlood" || e.kind === "SignatureInvalid" || e.kind === "Heartbeat"
         || e.kind === "HeartbeatLost" || e.kind === "RouteFailure") ? "obs" : "dec";
    row.className = `row ${cls}${selected === e.id ? " sel" : ""}`;
    row.textContent = `t${e.t}  ${fmt(e)}`;
    row.addEventListener("click", () => { selected = e.id; explainEvent(timeline, e); renderAll(false); });
    log.appendChild(row);
  }
}

function explainEvent(timeline: Timeline, e: Event) {
  const why = $("why");
  const roots = explain(timeline, e.id);
  if ((e as { causedBy?: unknown }).causedBy === undefined) {
    why.innerHTML = `<b>${fmt(e)}</b> — this is a raw observation (an input from the world). It wasn't caused by anything inside the system; it's the trigger.`;
    return;
  }
  if (!roots.length) { why.innerHTML = `<b>${fmt(e)}</b> — no upstream observations recorded.`; return; }
  why.innerHTML = `<b>${fmt(e)}</b> happened because of: ` + roots.map((r) => fmt(r)).join(", ") + ".";
}

function renderAll(resetWhy = true) {
  const { withDef, withoutDef, chosen } = compute();
  const maxT = chosen.timeline.reduce((m, e) => Math.max(m, e.t), 0);
  if (playTick > maxT) playTick = maxT;
  const state = reconstruct(chosen.timeline, playTick);

  drawMesh(state);
  renderLog(chosen.timeline, playTick);

  // scrubber
  const scrub = $("scrub") as HTMLInputElement;
  scrub.max = `${maxT}`; scrub.value = `${playTick}`;
  $("tick").textContent = `${playTick}`; $("tickmax").textContent = `${maxT}`;

  // banner (plain English, reflects the CURRENT defense setting at the end state)
  const finalState = reconstruct(chosen.timeline, maxT);
  const banner = $("banner");
  if (!attacks.length) {
    banner.className = "banner idle";
    banner.textContent = "Network healthy — no attack yet. Click a node to begin.";
  } else if (finalState.alive) {
    banner.className = "banner survived";
    banner.innerHTML = `✅ SURVIVED<small>With auto-defense ${defenseOn ? "ON" : "OFF"}, the network held.</small>`;
  } else {
    banner.className = "banner collapsed";
    banner.innerHTML = `💀 COLLAPSED<small>With auto-defense ${defenseOn ? "ON" : "OFF"}, the network fell.</small>`;
  }

  // the punchline: does the defense actually change the outcome?
  const punch = $("punch");
  const s = (tl: Timeline) => reconstruct(tl, tl.reduce((m, e) => Math.max(m, e.t), 0)).alive;
  const aliveWith = s(withDef.timeline), aliveWithout = s(withoutDef.timeline);
  if (attacks.length && aliveWith !== aliveWithout) {
    punch.className = "punch show";
    punch.innerHTML = `🔑 <b>Your defense is the difference.</b> Same attack — ` +
      `with defense → <b class="s">${aliveWith ? "SURVIVED" : "COLLAPSED"}</b>, ` +
      `without it → <b class="c">${aliveWithout ? "SURVIVED" : "COLLAPSED"}</b>. ` +
      `<i>That is the proof your intervention mattered.</i>`;
  } else if (attacks.length) {
    punch.className = "punch show";
    punch.innerHTML = `This attack ends the same way with or without the defense (` +
      `<b>${aliveWith ? "SURVIVED" : "COLLAPSED"}</b>) — try hitting the <b>center</b> node twice to see the defense matter.`;
  } else {
    punch.className = "punch";
  }

  if (resetWhy && !selected) $("why").textContent = "Click any event above to trace what caused it.";
}

// ── actions ──
function attack(n: NodeId) {
  if (attacks.length >= 16) return;
  const t = attacks.length + 1;
  attacks.push({ id: makeId("PacketFlood", `${n}.${t}`, t), t, kind: "PacketFlood", node: n, rate: 9000 });
  selected = null;
  play();
}

function launchDemo() {
  attacks = [
    { id: makeId("PacketFlood", "Bravo.1", 1), t: 1, kind: "PacketFlood", node: "Bravo", rate: 8000 },
    { id: makeId("PacketFlood", "Bravo.2", 2), t: 2, kind: "PacketFlood", node: "Bravo", rate: 9500 },
  ];
  selected = null;
  play();
}

function play() {
  if (timer) clearInterval(timer);
  const { chosen } = compute();
  const maxT = chosen.timeline.reduce((m, e) => Math.max(m, e.t), 0);
  playTick = 0; renderAll();
  timer = setInterval(() => {
    playTick++;
    if (playTick >= maxT) { playTick = maxT; if (timer) clearInterval(timer); timer = null; }
    renderAll(false);
  }, 650);
}

function reset() {
  if (timer) clearInterval(timer);
  attacks = []; playTick = 0; selected = null; renderAll();
}

function toggleDefense() {
  defenseOn = !defenseOn;
  $("defLabel").textContent = `Auto-defense: ${defenseOn ? "ON" : "OFF"}`;
  $("defSwitch").className = `switch ${defenseOn ? "on" : ""}`;
  play();
}

// ── wire up ──
$("demo").addEventListener("click", launchDemo);
$("replay").addEventListener("click", play);
$("reset").addEventListener("click", reset);
$("defSwitch").addEventListener("click", toggleDefense);
$("defLabel").addEventListener("click", toggleDefense);
($("scrub") as HTMLInputElement).addEventListener("input", (ev) => {
  if (timer) { clearInterval(timer); timer = null; }
  playTick = Number((ev.target as HTMLInputElement).value);
  renderAll(false);
});

renderAll();
