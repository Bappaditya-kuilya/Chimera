/**
 * demo/phase0.ts — Phase 0 end to end:  `npm run demo`
 *
 * Tells the whole story in one run:
 *   1. peers mint cryptographic identities (ed25519)
 *   2. they pair OFFLINE via QR / out-of-band safety numbers — no signaling server
 *   3. attack reports arrive SIGNED; the web of trust gates them
 *   4. a Sybil node and a forged report are rejected before the kernel sees them
 *   5. the authenticated facts drive the proven kernel: SURVIVED
 *   6. do(quarantine=false) on the SAME authenticated facts: COLLAPSED
 */

import { type Observation, counterfactual, makeId, run, verdict } from "../src/kernel.js";
import { encodePairing, identityFromSeed, safetyNumber, toPairingManifest } from "../src/identity.js";
import { TrustStore } from "../src/trust-store.js";
import { ingest, signObservation } from "../src/ingest.js";
import { OutOfBandChannel, QRDiscovery } from "../src/discovery.js";

const seed = (n: number) => new Uint8Array(32).fill(n);
const rule = "──────────────────────────────────────────────────────────";
const issuedAt = 1_717_000_000; // fixed "issuance time" — demo stays deterministic

console.log("══════════════════════════════════════════════════════════");
console.log(" CHIMERA — Phase 0: identity, Sybil resistance, offline pairing");
console.log("══════════════════════════════════════════════════════════");

// ── 1. identities ─────────────────────────────────────────────────
// Each node is an ed25519 keypair. Bravo is our local node; the others are peers.
const bravo = identityFromSeed("Bravo", seed(2)); // local node + flood sensor
const alpha = identityFromSeed("Alpha", seed(1));
const charlie = identityFromSeed("Charlie", seed(3));
const mallory = identityFromSeed("Mallory", seed(99)); // attacker — never paired

console.log("\n[1] identities minted (ed25519). Fingerprint = sha256(pubkey):");
for (const id of [bravo, alpha, charlie, mallory]) {
  console.log(`    ${id.nick.padEnd(8)} ${safetyNumber(id.fp, 6)} …`);
}

// ── 2. offline pairing over a QR / out-of-band channel ────────────
// No server. Each peer shows a QR; Bravo scans it and vouches after eyeballing
// the safety number. Generating keys is free — being vouched-for is not (Sybil).
console.log("\n[2] offline pairing (QR / out-of-band, no signaling server):");
const channel = new OutOfBandChannel();
const trust = new TrustStore();

const localDisco = new QRDiscovery(channel);
localDisco.start();
localDisco.onPeer((m) => {
  trust.add(m); // operator confirmed the safety number in person -> vouch
  console.log(`    paired  ${m.nick.padEnd(8)} ${safetyNumber(m.fp, 6)} …  ✓ in web of trust`);
});

// Alpha and Charlie present their QR codes; Mallory is NOT invited to pair.
for (const peer of [alpha, charlie]) {
  const qr = new QRDiscovery(channel);
  qr.announce(toPairingManifest(peer, issuedAt));
}
// Bravo trusts its own identity too (it is the local sensor).
trust.add(toPairingManifest(bravo, issuedAt));
console.log(`    trusted peers: ${trust.list().map((p) => p.nick).join(", ")}  (Mallory excluded)`);

console.log("\n    a pairing QR payload looks like (camera-scannable / paste-able):");
console.log(`    ${encodePairing(toPairingManifest(alpha, issuedAt)).slice(0, 72)} …`);

// ── 3 & 4. signed attack reports, with adversarial noise ──────────
// The proof scenario's two floods on Bravo — now each is SIGNED by its reporter.
// Mallory tries to inject a fake flood to weaponize the trust matrix; someone
// also replays a tampered copy of a real report. Both must die at the gate.
const realFloods: Observation[] = [
  { id: makeId("PacketFlood", "Bravo", 1), t: 1, kind: "PacketFlood", node: "Bravo", rate: 8000 },
  { id: makeId("PacketFlood", "Bravo", 2), t: 2, kind: "PacketFlood", node: "Bravo", rate: 9500 },
];

const inbox = [
  ...realFloods.map((o) => signObservation(o, bravo)), // genuine, from a trusted sensor
  signObservation(
    { id: makeId("PacketFlood", "Alpha", 1), t: 1, kind: "PacketFlood", node: "Alpha", rate: 9999 },
    mallory,
  ), // Sybil: attacker fabricates an attack on Alpha to get it quarantined
  tamper(signObservation(realFloods[1]!, bravo)), // forged: bytes flipped after signing
];

console.log("\n[3] inbox: 4 signed reports arrive (2 genuine, 1 Sybil, 1 tampered)");
const { accepted, rejected } = ingest(inbox, trust);

console.log("\n[4] ingest gate verifies every report against the web of trust:");
for (const o of accepted) console.log(`    ACCEPT  ${fmtObs(o)}`);
for (const r of rejected) {
  const who = trust.get(r.signed.author)?.nick ?? `unknown(${r.signed.author.slice(0, 6)}…)`;
  console.log(`    REJECT  ${fmtObs(r.signed.obs).padEnd(34)} from ${who.padEnd(18)} — ${r.reason}`);
}

// ── 5 & 6. authenticated facts drive the proven kernel ────────────
console.log(`\n${rule}`);
console.log("[5] only authenticated facts reach the pure kernel:");
const actual = run(accepted);
console.log(`    ACTUAL (policy intact)            => ${verdict(actual.state)}`);

console.log("\n[6] counterfactual on the SAME authenticated facts:");
const cf = counterfactual(accepted, { do: { "Quarantine:Bravo": false } });
console.log(`    do(Quarantine:Bravo = false)      => ${verdict(cf.state)}`);

console.log(`\n${rule}`);
const ok =
  verdict(actual.state) === "SURVIVED" &&
  verdict(cf.state) === "COLLAPSED" &&
  accepted.length === 2 &&
  rejected.length === 2;
console.log(
  ok
    ? " PHASE 0 OK — Sybil & forged reports rejected; authenticated SURVIVED vs COLLAPSED holds."
    : " PHASE 0 FAILED.",
);
console.log("══════════════════════════════════════════════════════════");
process.exit(ok ? 0 : 1);

// ── helpers ──
function fmtObs(o: Observation): string {
  switch (o.kind) {
    case "PacketFlood":
      return `FLOOD ${o.node} (rate ${o.rate})`;
    case "RouteFailure":
      return `ROUTEFAIL ${o.from}->${o.to}`;
    default:
      return `${o.kind} ${"node" in o ? o.node : ""}`;
  }
}
function tamper(s: ReturnType<typeof signObservation>): ReturnType<typeof signObservation> {
  return { ...s, obs: { ...s.obs, rate: 1 } as Observation }; // mutate after signing -> sig breaks
}
