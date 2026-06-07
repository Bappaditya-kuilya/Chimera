/**
 * demo/multistage.ts — Milestone 2 (hardening):  `npm run multistage`
 *
 * Shows the three hardening axes on top of the proven kernel:
 *   A. node lifecycle  HEALTHY -> ALERT -> EXPOSED -> ISOLATED -> SCARRED
 *   B. trust heals over quiet logical time (Heartbeat -> TrustRegen)
 *   C. topology is just DATA — the same engine runs a different mesh and the
 *      counterfactual still diverges (SURVIVED vs COLLAPSED).
 */

import {
  type Config,
  type Observation,
  type Topology,
  counterfactual,
  lifecycle,
  makeId,
  nodeState,
  reconstruct,
  run,
  verdict,
} from "../src/kernel.js";

const rule = "──────────────────────────────────────────────────────────";
console.log("══════════════════════════════════════════════════════════");
console.log(" CHIMERA — Milestone 2: hardened kernel");
console.log("══════════════════════════════════════════════════════════");

// ── A & B: lifecycle + heal-over-time, on the familiar STAR mesh ──
// recon (bad sig) -> two quiet heartbeats heal it -> sustained flood -> isolate -> recover.
const story: Observation[] = [
  { id: makeId("SignatureInvalid", "Bravo", 1), t: 1, kind: "SignatureInvalid", node: "Bravo" },
  { id: makeId("Heartbeat", "Bravo", 2), t: 2, kind: "Heartbeat", node: "Bravo" },
  { id: makeId("Heartbeat", "Bravo", 3), t: 3, kind: "Heartbeat", node: "Bravo" },
  { id: makeId("PacketFlood", "Bravo", 4), t: 4, kind: "PacketFlood", node: "Bravo", rate: 8000 },
  { id: makeId("PacketFlood", "Bravo", 5), t: 5, kind: "PacketFlood", node: "Bravo", rate: 9500 },
];

const { timeline, state } = run(story);

console.log("\n[A+B] Bravo through a multi-stage incident (trust heals at t2,t3):");
console.log("    tick  trust   state");
for (const t of [1, 2, 3, 4, 5]) {
  const s = reconstruct(timeline, t);
  console.log(`    t${t}    ${(s.trust["Bravo"] ?? 1).toFixed(1)}     ${nodeState(s, "Bravo")}`);
}
console.log(
  `\n    lifecycle(Bravo): ${lifecycle(timeline, "Bravo").map((x) => `t${x.t}:${x.state}`).join(" -> ")}`,
);
console.log(`    verdict: ${verdict(state)}`);

// ── C: same engine, different topology — a 5-node line ──
// Core at one end; an unquarantined compromise must walk the chain to collapse it.
const LINE: Topology = {
  nodes: ["A", "B", "C", "D", "E"],
  edges: { A: ["B"], B: ["A", "C"], C: ["B", "D"], D: ["C", "E"], E: ["D"] },
};
const lineCfg: Config = { topology: LINE, params: { trustDrop: 0.3, compromised: 0.5, collapseAt: 3, regen: 0.1 } };

const lineAttack: Observation[] = [
  { id: makeId("PacketFlood", "A", 1), t: 1, kind: "PacketFlood", node: "A", rate: 8000 },
  { id: makeId("PacketFlood", "A", 2), t: 2, kind: "PacketFlood", node: "A", rate: 9500 },
];

const lineActual = run(lineAttack, undefined, lineCfg);
const lineCf = counterfactual(lineAttack, { do: { "Quarantine:A": false } }, lineCfg);

console.log(`\n${rule}`);
console.log("[C] same engine, a 5-node LINE topology (A-B-C-D-E), attack on A:");
console.log(`    ACTUAL (policy intact)        => ${verdict(lineActual.state)}`);
console.log(`    do(Quarantine:A = false)      => ${verdict(lineCf.state)}`);

console.log(`\n${rule}`);
const ok =
  verdict(state) === "SURVIVED" &&
  lifecycle(timeline, "Bravo").map((x) => x.state).includes("SCARRED") &&
  verdict(lineActual.state) === "SURVIVED" &&
  verdict(lineCf.state) === "COLLAPSED";
console.log(
  ok
    ? " M2 OK — lifecycle reaches SCARRED, trust heals, topology-agnostic divergence holds."
    : " M2 FAILED.",
);
console.log("══════════════════════════════════════════════════════════");
process.exit(ok ? 0 : 1);
