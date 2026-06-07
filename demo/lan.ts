/**
 * demo/lan.ts — Milestone 4:  `npm run lan`
 *
 * Two peers find each other on a LAN with NO signaling server and NO internet —
 * just UDP multicast beacons. Then the key point: discovery is not trust. A peer
 * heard over the (hostile) link is only a CANDIDATE until its safety number is
 * confirmed out of band, exactly as in M1.
 */

import { identityFromSeed, safetyNumber, toPairingManifest } from "../src/identity.js";
import { TrustStore } from "../src/trust-store.js";
import { LanDiscovery } from "../src/lan.js";

const seed = (n: number) => new Uint8Array(32).fill(n);
const wait = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const rule = "──────────────────────────────────────────────────────────";

console.log("══════════════════════════════════════════════════════════");
console.log(" CHIMERA — Milestone 4: real LAN discovery (UDP multicast)");
console.log("══════════════════════════════════════════════════════════");

const port = 49777;
const alice = identityFromSeed("Alice", seed(11));
const bob = identityFromSeed("Bob", seed(12));

const aliceLan = new LanDiscovery({ port });
const bobLan = new LanDiscovery({ port });
const trust = new TrustStore(); // Bob's web of trust

bobLan.onPeer((m) => {
  console.log(`\n[Bob] heard a beacon on the LAN:`);
  console.log(`      ${m.nick}   ${safetyNumber(m.fp, 6)} …`);
  console.log(`      candidate? ${!trust.has(m.fp)}  (NOT trusted yet — discovery != trust)`);
  // out-of-band step: Bob confirms the safety number with Alice in person, then:
  trust.add(m);
  console.log(`      ✓ safety number confirmed out of band -> added to web of trust`);
});

await aliceLan.start();
await bobLan.start();

console.log(`\n[Alice] beaconing her manifest on udp/${port} multicast …`);
await aliceLan.announce(toPairingManifest(alice, 1000));
await wait(300);

console.log(`\n${rule}`);
const ok = trust.has(alice.fp) && !trust.has(bob.fp);
console.log(
  ok
    ? " M4 OK — peers discovered over real UDP multicast; trust still gated out of band."
    : " M4 FAILED.",
);
console.log("══════════════════════════════════════════════════════════");

await aliceLan.stop();
await bobLan.stop();
process.exit(ok ? 0 : 1);
