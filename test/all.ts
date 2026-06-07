/**
 * test/all.ts — runs every Phase-0 suite. `npm test`.
 */

import { runSuites } from "./harness.js";
import * as identity from "./identity.test.js";
import * as ingest from "./ingest.test.js";
import * as kernel from "./kernel.test.js";
import * as discovery from "./discovery.test.js";
import * as hardening from "./hardening.test.js";

console.log("══════════════════════════════════════════════════════════");
console.log(" CHIMERA — test suite (kernel · identity · ingest · discovery · hardening)");
console.log("══════════════════════════════════════════════════════════");

runSuites([identity, ingest, kernel, discovery, hardening]);
