/**
 * test/all.ts — runs every Phase-0 suite. `npm test`.
 */

import { runSuites } from "./harness.js";
import * as identity from "./identity.test.js";
import * as ingest from "./ingest.test.js";
import * as kernel from "./kernel.test.js";
import * as discovery from "./discovery.test.js";

console.log("══════════════════════════════════════════════════════════");
console.log(" CHIMERA — Phase 0 test suite (identity · ingest · kernel · discovery)");
console.log("══════════════════════════════════════════════════════════");

runSuites([identity, ingest, kernel, discovery]);
