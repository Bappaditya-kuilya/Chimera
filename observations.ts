/**
 * CHIMERA KERNEL — counterfactual proof harness.
 *
 * The engine now lives in ./src/kernel.ts (importable, tested, wired to identity).
 * This file is unchanged in behaviour: `npx tsx observations.ts` still runs the
 * original proof that identical observations yield SURVIVED vs do(quarantine=false)
 * -> COLLAPSED, deterministically. It is the canonical, documented entrypoint.
 */

import {
  type Event,
  type Observation,
  type Timeline,
  counterfactual,
  diff,
  explain,
  makeId,
  reconstruct,
  run,
  verdict,
} from "./src/kernel.js";

function fmt(e: Event): string {
  switch (e.kind) {
    case "PacketFlood":
      return `FLOOD       ${e.node} (rate ${e.rate})`;
    case "HeartbeatLost":
      return `HEARTBEAT?  ${e.node}`;
    case "SignatureInvalid":
      return `BADSIG      ${e.node}`;
    case "RouteFailure":
      return `ROUTEFAIL   ${e.from}->${e.to}`;
    case "TrustDrop":
      return `  trust--   ${e.node}`;
    case "Quarantine":
      return `  QUARANTINE ${e.node}`;
    case "Reroute":
      return `  reroute   ${e.from}->${e.to}`;
    case "Spread":
      return `  SPREAD    ${e.from}->${e.to}`;
    case "Recovery":
      return `  recovery  ${e.node}`;
    case "Collapse":
      return `  COLLAPSE  (network)`;
  }
}

function printTimeline(title: string, tl: Timeline): void {
  console.log(`\n${title}`);
  for (const e of tl) console.log(`  t${e.t}  ${fmt(e)}`);
}

// Identical ground-truth observations for every run below.
const scenario: Observation[] = [
  { id: makeId("PacketFlood", "Bravo", 1), t: 1, kind: "PacketFlood", node: "Bravo", rate: 8000 },
  { id: makeId("PacketFlood", "Bravo", 2), t: 2, kind: "PacketFlood", node: "Bravo", rate: 9500 },
];

let pass = true;
const check = (label: string, got: unknown, want: unknown) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  pass &&= ok;
  console.log(
    `  [${ok ? "PASS" : "FAIL"}] ${label}: ${JSON.stringify(got)}${ok ? "" : ` (want ${JSON.stringify(want)})`}`,
  );
};

console.log("══════════════════════════════════════════════════════════");
console.log(" CHIMERA KERNEL — counterfactual proof");
console.log("══════════════════════════════════════════════════════════");

const actual = run(scenario);
const cf = counterfactual(scenario, { do: { "Quarantine:Bravo": false } });

printTimeline("ACTUAL TIMELINE  (policy intact):", actual.timeline);
console.log(`  => ${verdict(actual.state)}`);

printTimeline("COUNTERFACTUAL  do(Quarantine:Bravo = false):", cf.timeline);
console.log(`  => ${verdict(cf.state)}`);

const d = diff(actual.timeline, cf.timeline);
console.log(`\nDIVERGENCE at t${d.divergedAt}:`);
console.log(`  actual takes: ${d.onlyInA.map(fmt).map((s) => s.trim()).join(" -> ")}`);
console.log(`  cf takes:     ${d.onlyInB.map(fmt).map((s) => s.trim()).join(" -> ")}`);

const qid = makeId("Quarantine", "Bravo", 2);
console.log(`\nEXPLAIN ${qid}:`);
console.log(`  justified by: ${explain(actual.timeline, qid).map((o) => o.id).join(", ")}`);

console.log(`\nRECONSTRUCT state @ t1 (mid-incident):`);
const s1 = reconstruct(actual.timeline, 1);
console.log(`  trust=${JSON.stringify(s1.trust)} infected=${[...s1.infected]} quarantined=${[...s1.quarantined]}`);

console.log("\n──────────────────────── assertions ──────────────────────");
check("actual verdict", verdict(actual.state), "SURVIVED");
check("counterfactual verdict", verdict(cf.state), "COLLAPSED");

// Negative control: FORCING the real decision changes nothing.
const forcedTrue = counterfactual(scenario, { do: { "Quarantine:Bravo": true } });
check("negative control (force quarantine=true)", verdict(forcedTrue.state), "SURVIVED");

// Determinism: same inputs -> byte-identical timeline across runs.
check(
  "determinism (two runs byte-identical)",
  JSON.stringify(run(scenario).timeline) === JSON.stringify(run(scenario).timeline),
  true,
);

// "What if the attack never came?" — remove the exogenous floods.
const noAttack = counterfactual(scenario, { remove: scenario.map((o) => o.id) });
check("remove all observations -> nothing happens", verdict(noAttack.state), "SURVIVED");

console.log("\n══════════════════════════════════════════════════════════");
console.log(pass ? " ALL CHECKS PASSED — Chimera is a kernel." : " SOME CHECKS FAILED.");
console.log("══════════════════════════════════════════════════════════");

process.exit(pass ? 0 : 1);
