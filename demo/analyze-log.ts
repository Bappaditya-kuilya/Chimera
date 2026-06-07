/**
 * demo/analyze-log.ts — Milestone 9:  `npm run analyze [path-to-access.log]`
 *
 * Real data in, causal verdict out. Point it at an nginx/Apache access log; Chimera
 * derives the topology and the attack from the log itself, then answers the question
 * no log viewer can: "did blocking that client actually save the server?"
 */

import { readFileSync } from "node:fs";
import { counterfactual, reconstruct, run, verdict } from "../src/kernel.js";
import { parseAccessLog } from "../src/sources/access-log.js";

const path = process.argv[2] ?? "fixtures/access.log";
const text = readFileSync(path, "utf8");

console.log("══════════════════════════════════════════════════════════");
console.log(` CHIMERA — Milestone 9: causal analysis of a REAL access log`);
console.log(`           ${path}`);
console.log("══════════════════════════════════════════════════════════");

const { observations, topology, summary } = parseAccessLog(text);

console.log(`\n  parsed ${summary.lines} log lines from ${summary.clients.length} clients`);
console.log(`  clients: ${summary.clients.join(", ")}`);
console.log(`  detected ${summary.floods} flood-seconds, ${summary.badSigs} auth-failure bursts`);
console.log(`  busiest client: ${summary.busiestClient}`);

if (!observations.length) {
  console.log("\n  no attack signals in this log — nothing to analyze.");
  process.exit(0);
}

// ACTUAL: the server's real auto-defense (quarantine a flooding client) is in force.
const actual = run(observations, undefined, { topology, params: { trustDrop: 0.3, compromised: 0.5, collapseAt: 3, regen: 0.1 } });

// COUNTERFACTUAL: what if we had NOT blocked the busiest attacker?
const attacker = summary.busiestClient!;
const cf = counterfactual(
  observations,
  { do: { [`Quarantine:${attacker}`]: false } },
  { topology, params: { trustDrop: 0.3, compromised: 0.5, collapseAt: 3, regen: 0.1 } },
);

console.log(`\n  ── verdict ──`);
console.log(`  WITH auto-defense (blocked ${attacker}):        ${verdict(actual.state)}`);
console.log(`  WITHOUT blocking ${attacker} (counterfactual):  ${verdict(cf.state)}`);

const a = verdict(actual.state), c = verdict(cf.state);
console.log(`\n  ${a !== c
  ? `🔑 Blocking ${attacker} is what saved the server. Left unblocked, the same traffic → ${c}.`
  : `Both outcomes are ${a}: this traffic wasn't severe enough for the block to change the result.`}`);

// show the moment of divergence on real data
const final = reconstruct(cf.timeline, cf.timeline.reduce((m, e) => Math.max(m, e.t), 0));
if (!final.alive) {
  console.log(`  Without the block, infection spread to: ${[...final.infected].sort().join(", ")}`);
}

console.log("\n══════════════════════════════════════════════════════════");
process.exit(0);
