/**
 * demo/host.ts — Milestone 9:  `npm run host`
 *
 * Chimera reading THIS machine's real network telemetry (via systeminformation),
 * not a script. Whatever your box is actually doing right now drives the runtime.
 */

import { reconstruct, verdict } from "../src/kernel.js";
import { CausalRuntime } from "../src/runtime.js";
import { HostMetricsSource } from "../src/sources/host-metrics.js";

console.log("══════════════════════════════════════════════════════════");
console.log(" CHIMERA — Milestone 9: live host metrics (systeminformation)");
console.log("══════════════════════════════════════════════════════════");

// Low threshold so ordinary traffic is visible in the demo (clearly labelled).
const source = new HostMetricsSource({ rxBytesPerSec: 1 });
const ifaces = await source.interfaces();
console.log(`\n  real network interfaces on this host: ${ifaces.join(", ")}`);

const rt = new CausalRuntime(source, {
  topology: { nodes: ifaces, edges: Object.fromEntries(ifaces.map((i) => [i, ifaces.filter((x) => x !== i)])) },
  params: { trustDrop: 0.3, compromised: 0.5, collapseAt: 3, regen: 0.1 },
});

source.subscribe((o) => rt.ingest(o));

console.log("\n  sampling real throughput (2 samples, 1s apart)…");
await source.sample(); // first sample primes the per-second deltas
await new Promise((r) => setTimeout(r, 1000));
const obs = await source.sample();

console.log(`\n  observations derived from real traffic this second: ${obs.length}`);
for (const o of obs) if (o.kind === "PacketFlood") console.log(`    ${o.node}: ${o.rate} bytes/s inbound -> flood signal`);
if (!obs.length) console.log("    (no inbound traffic crossed the threshold — host looks idle/healthy)");

const tl = rt.snapshot().timeline;
const maxT = tl.reduce((m, e) => Math.max(m, e.t), 0);
console.log(`\n  network verdict: ${verdict(reconstruct(tl, maxT))}  (from real signals)`);
console.log("\n  → this is the same engine as the demos, fed by your actual machine.");
console.log("══════════════════════════════════════════════════════════");
process.exit(0);
