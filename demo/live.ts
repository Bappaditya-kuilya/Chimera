/**
 * demo/live.ts — Milestone 3:  `npm run live`
 *
 * The "Causal Security Runtime" pivot, made concrete:
 *   - real APP-LAYER telemetry (message rates, bad signatures, quiet intervals)
 *     flows through LiveSignalSource -> Observations
 *   - CausalRuntime folds them LIVE, one at a time, maintaining authoritative state
 *   - a counterfactual is then run as a clearly-branded SIMULATION that does NOT
 *     touch the live timeline (the mode split that prevents false confidence).
 */

import { nodeState, reconstruct } from "../src/kernel.js";
import { LiveSignalSource, type Signal } from "../src/source.js";
import { CausalRuntime } from "../src/runtime.js";

const rule = "──────────────────────────────────────────────────────────";
console.log("══════════════════════════════════════════════════════════");
console.log(" CHIMERA — Milestone 3: live runtime + Live/Demonstration split");
console.log("══════════════════════════════════════════════════════════");

// A live source mapping real telemetry -> observations, driving the runtime.
const source = new LiveSignalSource();
const rt = new CausalRuntime(source);
rt.start();

console.log(`\n[LIVE] mode=${rt.mode}  (acting on observed signals)\n`);

// Telemetry as it would actually arrive from the app layer over time.
const stream: Signal[] = [
  { kind: "quiet", node: "Bravo" }, //          clean interval
  { kind: "message-rate", node: "Bravo", perSec: 1200 }, // normal traffic -> no observation
  { kind: "message-rate", node: "Bravo", perSec: 8000 }, // burst -> PacketFlood
  { kind: "message-rate", node: "Bravo", perSec: 9500 }, // sustained -> PacketFlood -> isolate
];

for (const sig of stream) {
  const produced = source.feed(sig);
  const tag =
    sig.kind === "message-rate"
      ? `message-rate ${sig.node} ${sig.perSec}/s`
      : `${sig.kind} ${"node" in sig ? sig.node : ""}`;
  const reaction = rt
    .snapshot()
    .timeline.filter((e) => "node" in e && e.node === "Bravo")
    .slice(-2);
  void produced;
  console.log(
    `  signal: ${tag.padEnd(28)} -> Bravo is ${nodeState(snapshotState(rt), "Bravo").padEnd(8)} verdict ${rt.verdict}`,
  );
}

console.log(`\n  LIVE verdict: ${rt.verdict}  (decided purely from observed signals)`);

// ── the do()-operator as an explicit SIMULATION ──
console.log(`\n${rule}`);
const sim = rt.simulate({ do: { "Quarantine:Bravo": false } });
console.log(`[${sim.brand}] do(Quarantine:Bravo = false) on the recorded live log:`);
console.log(`    basedOnMode: ${sim.basedOnMode}`);
console.log(`    => ${sim.verdict}   (this is a SIMULATION, not the live timeline)`);
console.log(`\n    live verdict is still: ${rt.verdict}  (simulation never mutated live state)`);

console.log(`\n${rule}`);
const ok = rt.verdict === "SURVIVED" && sim.brand === "SIMULATION" && sim.verdict === "COLLAPSED";
console.log(
  ok
    ? " M3 OK — live SURVIVED from observed signals; counterfactual COLLAPSED, branded SIMULATION."
    : " M3 FAILED.",
);
console.log("══════════════════════════════════════════════════════════");
rt.stop();
process.exit(ok ? 0 : 1);

// small helper: reconstruct current live state for display
function snapshotState(runtime: CausalRuntime) {
  const tl = runtime.snapshot().timeline;
  const maxT = tl.reduce((m, e) => Math.max(m, e.t), 0);
  return reconstruct(tl, maxT);
}
