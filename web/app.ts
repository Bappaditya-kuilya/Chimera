/**
 * web/app.ts — Chimera web app (vanilla TS + SVG, no framework).
 *
 * Two modes:
 *   • Analyze my data (flagship): drop a real nginx/Apache/JSON/CSV log; Chimera
 *     shows what happened, the defensive decision it made, WHY, and what would have
 *     happened without it — all client-side (logs never leave the browser).
 *   • Live sandbox: click-to-attack demo for instant onboarding.
 *
 * Everything reads straight off the pure kernel. Browser-safe imports only.
 */

import {
  type Event,
  type Intervention,
  type NodeId,
  type NodeState,
  type State,
  type Timeline,
  type Topology,
  STAR,
  counterfactual,
  explain,
  makeId,
  nodeState,
  reconstruct,
  run,
  verdict,
} from "../src/kernel";
import { type AnalyzeResult, analyzeLog } from "../src/sources/log-formats";

const $ = (id: string) => document.getElementById(id)!;
const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c] as string);
const SVGNS = "http://www.w3.org/2000/svg";
const PARAMS = { trustDrop: 0.3, compromised: 0.5, collapseAt: 3, regen: 0.1 };
const COLOR: Record<NodeState, string> = {
  HEALTHY: "var(--healthy)", ALERT: "var(--alert)", EXPOSED: "var(--exposed)",
  ISOLATED: "var(--isolated)", SCARRED: "var(--scarred)",
};
const isInfected = (s: State, n: NodeId) => s.infected.has(n) && !s.recovered.has(n);
const W = 440, H = 300;

// ───────────────────────── shared rendering ─────────────────────────
function layout(topo: Topology): Map<NodeId, { x: number; y: number }> {
  const deg = (n: NodeId) => (topo.edges[n]?.length ?? 0);
  const hub = [...topo.nodes].sort((a, b) => deg(b) - deg(a))[0]!;
  const leaves = topo.nodes.filter((n) => n !== hub);
  const pos = new Map<NodeId, { x: number; y: number }>();
  pos.set(hub, { x: W / 2, y: H / 2 });
  const r = Math.min(120, 80 + leaves.length * 4);
  leaves.forEach((n, i) => {
    const a = (i / Math.max(1, leaves.length)) * Math.PI * 2 - Math.PI / 2;
    pos.set(n, { x: W / 2 + Math.cos(a) * r, y: H / 2 + Math.sin(a) * r * 0.78 });
  });
  return pos;
}

function short(n: NodeId): string {
  return n.length > 15 ? n.slice(0, 14) + "…" : n;
}

function svgText(x: number, y: number, s: string, cls: string, fill?: string) {
  const t = document.createElementNS(SVGNS, "text");
  t.setAttribute("x", `${x}`); t.setAttribute("y", `${y}`);
  t.setAttribute("text-anchor", "middle"); t.setAttribute("class", cls);
  if (fill) t.setAttribute("fill", fill);
  t.textContent = s; return t;
}

function drawMesh(svg: SVGElement, topo: Topology, state: State, onClick?: (n: NodeId) => void) {
  svg.innerHTML = "";
  const pos = layout(topo);
  const seen = new Set<string>();
  for (const [from, tos] of Object.entries(topo.edges)) {
    for (const to of tos) {
      const key = [from, to].sort().join("|");
      if (seen.has(key)) continue; seen.add(key);
      const a = pos.get(from), b = pos.get(to); if (!a || !b) continue;
      const line = document.createElementNS(SVGNS, "line");
      line.setAttribute("x1", `${a.x}`); line.setAttribute("y1", `${a.y}`);
      line.setAttribute("x2", `${b.x}`); line.setAttribute("y2", `${b.y}`);
      line.setAttribute("stroke", "var(--edge)"); line.setAttribute("stroke-width", "1.6");
      svg.appendChild(line);
    }
  }
  const big = topo.nodes.length <= 5;
  for (const n of topo.nodes) {
    const p = pos.get(n)!; const st = nodeState(state, n, PARAMS);
    const fill = isInfected(state, n) ? "var(--dead)" : COLOR[st];
    const g = document.createElementNS(SVGNS, "g");
    g.setAttribute("class", "nodewrap" + (onClick ? " click" : ""));
    if (onClick) g.addEventListener("click", () => onClick(n));
    const c = document.createElementNS(SVGNS, "circle");
    c.setAttribute("class", "node");
    c.setAttribute("cx", `${p.x}`); c.setAttribute("cy", `${p.y}`);
    c.setAttribute("r", `${big ? 21 : 15}`);
    c.setAttribute("fill", fill); c.setAttribute("fill-opacity", "0.9");
    c.setAttribute("stroke", "#0d1117"); c.setAttribute("stroke-width", "2");
    g.appendChild(c);
    g.appendChild(svgText(p.x, p.y - (big ? 28 : 22), short(n), "nlabel"));
    g.appendChild(svgText(p.x, p.y + 3, `${(state.trust[n] ?? 1).toFixed(1)}`, "nsub"));
    svg.appendChild(g);
  }
}

function fmt(e: Event): string {
  switch (e.kind) {
    case "PacketFlood": return `flood attack on ${short(e.node)} (${e.rate}/s)`;
    case "HeartbeatLost": return `lost heartbeat — ${short(e.node)}`;
    case "SignatureInvalid": return `bad signatures — ${short(e.node)}`;
    case "RouteFailure": return `route failure ${short(e.from)}→${short(e.to)}`;
    case "Heartbeat": return `clean traffic — ${short(e.node)}`;
    case "TrustDrop": return `trust dropped on ${short(e.node)}`;
    case "TrustRegen": return `trust recovering — ${short(e.node)}`;
    case "Quarantine": return `🛡️ BLOCKED / quarantined ${short(e.node)}`;
    case "Reroute": return `rerouted ${short(e.from)}→${short(e.to)}`;
    case "Spread": return `☣️ infection spread ${short(e.from)}→${short(e.to)}`;
    case "Recovery": return `✅ ${short(e.node)} recovered`;
    case "Collapse": return `💀 system COLLAPSED`;
  }
}
const evClass = (e: Event) =>
  e.kind === "Spread" || e.kind === "Collapse" ? "bad"
  : ["PacketFlood", "SignatureInvalid", "Heartbeat", "HeartbeatLost", "RouteFailure"].includes(e.kind) ? "obs" : "dec";

function renderLog(host: HTMLElement, tl: Timeline, upto: number, onPick: (e: Event) => void, sel?: string) {
  host.innerHTML = "";
  const shown = tl.filter((e) => e.t <= upto);
  if (!shown.length) { host.innerHTML = `<div class="e">no events yet</div>`; return; }
  for (const e of shown) {
    const d = document.createElement("div");
    d.className = `e ${evClass(e)}${sel === e.id ? " sel" : ""}`;
    d.textContent = `t${e.t}  ${fmt(e)}`;
    d.addEventListener("click", () => onPick(e));
    host.appendChild(d);
  }
}

// ───────────────────────── tabs ─────────────────────────
let sandboxStarted = false;
function showTab(which: "analyze" | "sandbox") {
  $("mode-analyze").classList.toggle("hidden", which !== "analyze");
  $("mode-sandbox").classList.toggle("hidden", which !== "sandbox");
  $("tab-analyze").classList.toggle("active", which === "analyze");
  $("tab-sandbox").classList.toggle("active", which === "sandbox");
  if (which === "sandbox" && !sandboxStarted) { sandboxStarted = true; sbDemo(); }
}
$("tab-analyze").addEventListener("click", () => showTab("analyze"));
$("tab-sandbox").addEventListener("click", () => showTab("sandbox"));

// ───────────────────────── ANALYZE MODE ─────────────────────────
const SAMPLE_LOG = [
  '198.51.100.10 - - [10/Oct/2024:13:55:01 -0700] "GET / HTTP/1.1" 200 1043 "-" "Mozilla/5.0"',
  '198.51.100.11 - - [10/Oct/2024:13:55:02 -0700] "GET /about HTTP/1.1" 200 2210 "-" "Mozilla/5.0"',
  '198.51.100.23 - - [10/Oct/2024:13:55:02 -0700] "GET /api HTTP/1.1" 200 884 "-" "curl/8.4"',
  '198.51.100.10 - - [10/Oct/2024:13:55:03 -0700] "GET /style.css HTTP/1.1" 200 5012 "-" "Mozilla/5.0"',
  '198.51.100.11 - - [10/Oct/2024:13:55:04 -0700] "GET /logo.png HTTP/1.1" 200 12044 "-" "Mozilla/5.0"',
  '198.51.100.23 - - [10/Oct/2024:13:55:05 -0700] "GET /api HTTP/1.1" 200 884 "-" "curl/8.4"',
  ...Array.from({ length: 6 }, () => '203.0.113.7 - - [10/Oct/2024:13:55:05 -0700] "POST /login HTTP/1.1" 401 31 "-" "python-requests/2.31"'),
  ...Array.from({ length: 6 }, () => '203.0.113.7 - - [10/Oct/2024:13:55:06 -0700] "POST /login HTTP/1.1" 401 31 "-" "python-requests/2.31"'),
  '198.51.100.10 - - [10/Oct/2024:13:55:07 -0700] "GET /contact HTTP/1.1" 200 1500 "-" "Mozilla/5.0"',
].join("\n");

const drop = $("drop"), fileInput = $("file") as HTMLInputElement, paste = $("paste") as HTMLTextAreaElement;
$("pick").addEventListener("click", (e) => { e.stopPropagation(); fileInput.click(); });
drop.addEventListener("click", () => fileInput.click());
$("sample").addEventListener("click", (e) => { e.stopPropagation(); paste.value = SAMPLE_LOG; analyze(SAMPLE_LOG, "sample.log"); });
$("analyze").addEventListener("click", () => analyze(paste.value, "pasted.log"));
fileInput.addEventListener("change", async () => {
  const f = fileInput.files?.[0]; if (!f) return;
  const text = await f.text(); paste.value = text.slice(0, 4000); analyze(text, f.name);
});
["dragover", "dragenter"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("hover"); }));
["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, () => drop.classList.remove("hover")));
drop.addEventListener("drop", async (e) => {
  e.preventDefault();
  const f = (e as DragEvent).dataTransfer?.files?.[0]; if (!f) return;
  const text = await f.text(); paste.value = text.slice(0, 4000); analyze(text, f.name);
});

function el(tag: string, cls?: string, html?: string): HTMLElement {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html !== undefined) e.innerHTML = html;
  return e;
}

function analyze(text: string, filename: string) {
  const report = $("report"); report.innerHTML = "";
  if (!text.trim()) { report.appendChild(el("div", "card muted", "Paste or drop a log first.")); return; }

  const res = analyzeLog(text, filename);
  const cfg = { topology: res.topology, params: PARAMS };

  if (!res.observations.length) {
    report.appendChild(el("div", "verdict neutral",
      `<span class="big">✅ No attack signals found</span>` +
      `<div class="sub">Parsed ${res.summary.lines} ${res.format} record(s) from ${res.summary.clients.length} client(s). Nothing in this log rises to an attack.</div>`));
    return;
  }

  const actual = run(res.observations, undefined, cfg);
  const attacker = res.summary.busiestClient!;
  const iv: Intervention = { do: { [`Quarantine:${attacker}`]: false } };
  const cf = counterfactual(res.observations, iv, cfg);
  const aAlive = verdict(actual.state) === "SURVIVED";
  const cAlive = verdict(cf.state) === "SURVIVED";
  const quarantines = actual.timeline.filter((e) => e.kind === "Quarantine");

  // verdict banner + proof
  const banner = el("div", "verdict " + (aAlive ? "survived" : "collapsed"));
  banner.appendChild(el("div", "big", aAlive ? "✅ SURVIVED — your defense held" : "💀 COLLAPSED — the defense was overwhelmed"));
  banner.appendChild(el("div", "sub",
    `Parsed ${res.summary.lines} ${res.format} records · ${res.summary.clients.length} clients · ` +
    `${res.summary.floods} flood-second(s). Attacker: ${attacker}.`));
  if (aAlive && !cAlive) {
    banner.appendChild(el("div", "proof",
      `🔑 <b>Blocking ${attacker} is what saved you.</b> Replaying the same log without that block → <b class="c">COLLAPSED</b>. <i>That is proof the intervention mattered.</i>`));
  } else if (aAlive && cAlive) {
    banner.className = "verdict neutral";
    banner.querySelector(".big")!.textContent = "✅ No real incident";
    banner.appendChild(el("div", "proof", `This traffic resolves <b class="s">SURVIVED</b> with or without intervention — it wasn't a genuine threat.`));
  }
  report.appendChild(banner);

  // grid: steps + mesh
  const grid = el("div", "grid2");
  const steps = el("div", "card steps");
  // 1 what happened
  const s1 = el("div", "step"); s1.appendChild(el("h4", undefined, "1 · What happened"));
  s1.appendChild(el("p", undefined,
    `${attacker} sent a burst of traffic across ${res.summary.floods} second(s)` +
    (res.summary.badSigs ? ` plus ${res.summary.badSigs} auth-failure burst(s)` : "") +
    `, attacking the server.`));
  steps.appendChild(s1);
  // 2 decision
  const s2 = el("div", "step"); s2.appendChild(el("h4", undefined, "2 · The decision Chimera's defense made"));
  s2.appendChild(el("p", undefined, quarantines.length
    ? `Auto-defense ` + quarantines.map((q) => `<span class="pill q">blocked ${short((q as any).node)}</span>`).join(" ")
    : `No defensive action was required.`));
  steps.appendChild(s2);
  // 3 why
  const s3 = el("div", "step"); s3.appendChild(el("h4", undefined, "3 · Why it made that decision"));
  if (quarantines.length) {
    const roots = explain(actual.timeline, quarantines[0]!.id);
    s3.appendChild(el("p", undefined, `Because of: ` + roots.map((r) => `<span class="pill bad">${fmt(r)}</span>`).join(" ") + ` — trust fell below the safe threshold.`));
  } else s3.appendChild(el("p", "muted", "—"));
  steps.appendChild(s3);
  // 4 without
  const s4 = el("div", "step"); s4.appendChild(el("h4", undefined, "4 · What would've happened without the block"));
  const spread = [...reconstruct(cf.timeline, cf.timeline.reduce((m, e) => Math.max(m, e.t), 0)).infected].sort();
  s4.appendChild(el("p", undefined, cAlive
    ? `Still <b style="color:var(--healthy)">SURVIVED</b> — the block wasn't decisive here.`
    : `<b style="color:var(--dead)">COLLAPSED</b> — infection would have spread to ${spread.map(short).join(", ")}.`));
  steps.appendChild(s4);
  grid.appendChild(steps);

  // mesh + scrubber + log
  const vis = el("div", "card");
  const maxT = actual.timeline.reduce((m, e) => Math.max(m, e.t), 0);
  vis.innerHTML =
    `<svg id="an-mesh" viewBox="0 0 ${W} ${H}"></svg>` +
    `<div class="tickbar"><span>replay</span><input type="range" id="an-scrub" min="0" max="${maxT}" value="${maxT}"/>` +
    `<span>t<span id="an-tick">${maxT}</span>/${maxT}</span></div>` +
    `<div class="log" id="an-log"></div><div class="why" id="an-why">Click an event to see why it happened.</div>`;
  grid.appendChild(vis);
  report.appendChild(grid);

  let selId: string | undefined;
  const draw = (t: number) => {
    drawMesh($("an-mesh"), res.topology, reconstruct(actual.timeline, t));
    $("an-tick").textContent = `${t}`;
    renderLog($("an-log"), actual.timeline, t, (e) => {
      selId = e.id;
      const roots = explain(actual.timeline, e.id);
      $("an-why").innerHTML = (e as any).causedBy === undefined
        ? `<b>${fmt(e)}</b> — a raw observation from the log (the trigger).`
        : roots.length ? `<b>${fmt(e)}</b> was caused by: ${roots.map(fmt).join(", ")}.` : `<b>${fmt(e)}</b>`;
      draw(Number(($("an-scrub") as HTMLInputElement).value));
    }, selId);
  };
  ($("an-scrub") as HTMLInputElement).addEventListener("input", (ev) => draw(Number((ev.target as HTMLInputElement).value)));
  draw(maxT);
  report.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// ───────────────────────── SANDBOX MODE ─────────────────────────
let attacks: import("../src/kernel").Observation[] = [];
let defenseOn = true, playTick = 0, sel: string | null = null;
let timer: ReturnType<typeof setInterval> | null = null;
const NO_DEFENSE: Intervention = { do: Object.fromEntries(STAR.nodes.map((n) => [`Quarantine:${n}`, false])) };

function sbCompute() {
  const withDef = run(attacks), withoutDef = run(attacks, NO_DEFENSE);
  return { withDef, withoutDef, chosen: defenseOn ? withDef : withoutDef };
}
function sbRender(resetWhy = true) {
  const { withDef, withoutDef, chosen } = sbCompute();
  const maxT = chosen.timeline.reduce((m, e) => Math.max(m, e.t), 0);
  if (playTick > maxT) playTick = maxT;
  drawMesh($("sb-mesh"), STAR, reconstruct(chosen.timeline, playTick), sbAttack);
  const scrub = $("sb-scrub") as HTMLInputElement; scrub.max = `${maxT}`; scrub.value = `${playTick}`;
  $("sb-tick").textContent = `${playTick}`; $("sb-tmax").textContent = `${maxT}`;
  renderLog($("sb-log"), chosen.timeline, playTick, (e) => {
    sel = e.id; const roots = explain(chosen.timeline, e.id);
    $("sb-why").innerHTML = (e as any).causedBy === undefined
      ? `<b>${fmt(e)}</b> — a raw observation (the trigger).`
      : roots.length ? `<b>${fmt(e)}</b> caused by: ${roots.map(fmt).join(", ")}.` : `<b>${fmt(e)}</b>`;
    sbRender(false);
  }, sel ?? undefined);

  const fs = reconstruct(chosen.timeline, maxT);
  const banner = $("sb-banner");
  if (!attacks.length) { banner.className = "verdict neutral"; banner.innerHTML = `<span class="big">Click a node to attack it</span><div class="sub">Hit the center node twice — or press “Launch demo attack”.</div>`; }
  else if (fs.alive) { banner.className = "verdict survived"; banner.innerHTML = `<span class="big">✅ SURVIVED</span><div class="sub">With auto-defense ${defenseOn ? "ON" : "OFF"}.</div>`; }
  else { banner.className = "verdict collapsed"; banner.innerHTML = `<span class="big">💀 COLLAPSED</span><div class="sub">With auto-defense ${defenseOn ? "ON" : "OFF"}.</div>`; }

  const alive = (tl: Timeline) => reconstruct(tl, tl.reduce((m, e) => Math.max(m, e.t), 0)).alive;
  if (attacks.length && alive(withDef.timeline) !== alive(withoutDef.timeline)) {
    banner.appendChild(el("div", "proof", `🔑 Your defense is the difference: with it → <b class="s">${alive(withDef.timeline) ? "SURVIVED" : "COLLAPSED"}</b>, without it → <b class="c">${alive(withoutDef.timeline) ? "SURVIVED" : "COLLAPSED"}</b>.`));
  }
  if (resetWhy && !sel) $("sb-why").textContent = "Click any event to trace what caused it.";
}
function sbAttack(n: NodeId) {
  if (attacks.length >= 16) return;
  const t = attacks.length + 1;
  attacks.push({ id: makeId("PacketFlood", `${n}.${t}`, t), t, kind: "PacketFlood", node: n, rate: 9000 });
  sel = null; sbPlay();
}
function sbDemo() {
  attacks = [
    { id: makeId("PacketFlood", "Bravo.1", 1), t: 1, kind: "PacketFlood", node: "Bravo", rate: 8000 },
    { id: makeId("PacketFlood", "Bravo.2", 2), t: 2, kind: "PacketFlood", node: "Bravo", rate: 9500 },
  ];
  sel = null; sbPlay();
}
function sbPlay() {
  if (timer) clearInterval(timer);
  const { chosen } = sbCompute();
  const maxT = chosen.timeline.reduce((m, e) => Math.max(m, e.t), 0);
  playTick = 0; sbRender();
  timer = setInterval(() => {
    playTick++;
    if (playTick >= maxT) { playTick = maxT; if (timer) clearInterval(timer); timer = null; }
    sbRender(false);
  }, 600);
}
$("sb-demo").addEventListener("click", sbDemo);
$("sb-replay").addEventListener("click", sbPlay);
$("sb-reset").addEventListener("click", () => { if (timer) clearInterval(timer); attacks = []; playTick = 0; sel = null; sbRender(); });
$("sb-toggle").addEventListener("click", () => {
  defenseOn = !defenseOn;
  $("sb-deflabel").textContent = `Auto-defense: ${defenseOn ? "ON" : "OFF"}`;
  $("sb-switch").className = `switch ${defenseOn ? "on" : ""}`;
  sbPlay();
});
($("sb-scrub") as HTMLInputElement).addEventListener("input", (ev) => {
  if (timer) { clearInterval(timer); timer = null; }
  playTick = Number((ev.target as HTMLInputElement).value); sbRender(false);
});

// initial state: show the sample analysis so a first-time visitor sees value instantly.
analyze(SAMPLE_LOG, "sample.log");
sbRender();
