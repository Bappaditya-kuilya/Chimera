/**
 * test/all.ts — runs every Phase-0 suite. `npm test`.
 */

import { runSuites } from "./harness.js";
import * as identity from "./identity.test.js";
import * as ingest from "./ingest.test.js";
import * as kernel from "./kernel.test.js";
import * as discovery from "./discovery.test.js";
import * as hardening from "./hardening.test.js";
import * as runtime from "./runtime.test.js";
import * as lan from "./lan.test.js";
import * as replay from "./replay.test.js";
import * as vault from "./vault.test.js";
import * as properties from "./properties.test.js";
import * as accessLog from "./access-log.test.js";
import * as server from "./server.test.js";

console.log("══════════════════════════════════════════════════════════");
console.log(" CHIMERA — full test suite");
console.log("══════════════════════════════════════════════════════════");

runSuites([identity, ingest, kernel, discovery, hardening, runtime, lan, replay, vault, properties, accessLog, server]);
