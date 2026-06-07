/**
 * demo/persist.ts — Milestone 7:  `npm run persist`
 *
 * A node survives a restart without leaking its identity, and an attacker can't
 * replay captured traffic:
 *   1. build an identity + web of trust + a signed observation log
 *   2. seal it to an encrypted Genome Vault (secret key under a passphrase)
 *   3. "restart" — reload from disk; identity/trust/log come back intact
 *   4. a wrong passphrase fails loudly; the secret is never on disk in clear
 *   5. a captured signed observation, resent, is rejected by the replay guard
 */

import { tmpdir } from "node:os";
import { join } from "node:path";
import { readFileSync, rmSync } from "node:fs";
import { type Observation, makeId } from "../src/kernel.js";
import { bytesToHex } from "../src/crypto.js";
import { identityFromSeed, safetyNumber, toPairingManifest } from "../src/identity.js";
import { TrustStore } from "../src/trust-store.js";
import { ReplayGuard, ingest, signObservation } from "../src/ingest.js";
import { loadVault, saveVault } from "../src/vault.js";

const seed = (n: number) => new Uint8Array(32).fill(n);
const rule = "──────────────────────────────────────────────────────────";
console.log("══════════════════════════════════════════════════════════");
console.log(" CHIMERA — Milestone 7: persistence (Genome Vault) + replay defence");
console.log("══════════════════════════════════════════════════════════");

const me = identityFromSeed("Bravo", seed(2));
const peer = identityFromSeed("Alpha", seed(1));
const trust = new TrustStore();
trust.add(toPairingManifest(peer, 100));

const obs: Observation = { id: makeId("PacketFlood", "Bravo", 1), t: 1, kind: "PacketFlood", node: "Bravo", rate: 8000 };
const log = [signObservation(obs, me)];

const path = join(tmpdir(), "chimera-demo-vault.json");
const PASS = "correct horse battery staple";

console.log(`\n[1] node identity ${me.nick}  ${safetyNumber(me.fp, 6)} …`);
console.log(`    trusts: ${trust.list().map((p) => p.nick).join(", ")};  log has ${log.length} signed obs`);

saveVault(path, { identity: me, trust, log }, PASS);
const onDisk = readFileSync(path, "utf8");
console.log(`\n[2] sealed to encrypted vault (${onDisk.length} bytes on disk)`);
console.log(`    secret key in plaintext on disk? ${onDisk.includes(bytesToHex(me.keypair.secretKey))}  (must be false)`);

console.log(`\n[3] --- simulating a restart: reload from disk ---`);
const back = loadVault(path, PASS);
console.log(`    identity restored: ${back.identity.fp === me.fp}`);
console.log(`    secret key restored: ${bytesToHex(back.identity.keypair.secretKey) === bytesToHex(me.keypair.secretKey)}`);
console.log(`    web of trust restored: ${back.trust.has(peer.fp)};  log entries: ${back.log.length}`);

console.log(`\n[4] wrong passphrase:`);
let rejected = false;
try { loadVault(path, "hunter2"); } catch { rejected = true; }
console.log(`    load rejected: ${rejected}  (AES-GCM auth tag failed)`);

console.log(`\n[5] replay defence:`);
back.trust.add(toPairingManifest(back.identity, 1)); // a node trusts its own sensor identity
const guard = new ReplayGuard();
const first = ingest(log, back.trust, guard);
const replayed = ingest(log, back.trust, guard); // attacker resends captured traffic
console.log(`    first delivery accepted: ${first.accepted.length}`);
console.log(`    captured resend -> ${replayed.rejected[0]?.reason} (rejected: ${replayed.accepted.length === 0})`);

console.log(`\n${rule}`);
const ok =
  back.identity.fp === me.fp &&
  back.trust.has(peer.fp) &&
  rejected &&
  !onDisk.includes(bytesToHex(me.keypair.secretKey)) &&
  replayed.accepted.length === 0;
console.log(ok ? " M7 OK — identity persists encrypted; wrong key & replays both rejected." : " M7 FAILED.");
console.log("══════════════════════════════════════════════════════════");
rmSync(path, { force: true });
process.exit(ok ? 0 : 1);
