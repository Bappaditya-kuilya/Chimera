/**
 * demo/serve.ts — Milestone 10:  `npm run serve`
 *
 * Runs Chimera as a real service: a live CausalRuntime behind HTTP + WebSocket,
 * also serving the interactive UI. Other systems POST real observations and get a
 * live, explainable verdict back; the UI and any WS client see decisions stream in.
 */

import { startServer } from "../src/server.js";
import { CausalRuntime } from "../src/runtime.js";
import { LiveSignalSource } from "../src/source.js";

const rt = new CausalRuntime(new LiveSignalSource()); // live mode; feed it via HTTP
const { url } = await startServer(rt, { port: 8787, webDir: "web" });

console.log("══════════════════════════════════════════════════════════");
console.log(" CHIMERA — live service");
console.log("══════════════════════════════════════════════════════════");
console.log(`\n  UI + API:  ${url}\n`);
console.log("  try it:");
console.log(`    curl ${url}/api/state`);
console.log(`    curl -X POST ${url}/api/observe -d '{"id":"PacketFlood:Bravo@t1","t":1,"kind":"PacketFlood","node":"Bravo","rate":8000}'`);
console.log(`    curl -X POST ${url}/api/observe -d '{"id":"PacketFlood:Bravo@t2","t":2,"kind":"PacketFlood","node":"Bravo","rate":9500}'`);
console.log(`    curl ${url}/api/state          # -> SURVIVED (auto-defense quarantined Bravo)`);
console.log(`    curl -X POST ${url}/api/simulate -d '{"do":{"Quarantine:Bravo":false}}'  # -> SIMULATION: COLLAPSED`);
console.log("\n  (Ctrl-C to stop)\n");
