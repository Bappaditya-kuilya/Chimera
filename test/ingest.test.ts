import { type Suite } from "./harness.js";
import { seed } from "./harness.js";
import { type Observation } from "../src/kernel.js";
import { identityFromSeed, toPairingManifest } from "../src/identity.js";
import { TrustStore } from "../src/trust-store.js";
import { ingest, signObservation } from "../src/ingest.js";

export const name = "ingest gate (Sybil / forgery / integrity)";

const flood = (t: number): Observation => ({
  id: `PacketFlood:Bravo@t${t}`,
  t,
  kind: "PacketFlood",
  node: "Bravo",
  rate: 8000 + t,
});

export const suite: Suite["suite"] = (t) => {
  const alpha = identityFromSeed("Alpha", seed(1)); // vouched-for sensor
  const mallory = identityFromSeed("Mallory", seed(99)); // attacker, never paired

  const trust = new TrustStore();
  trust.add(toPairingManifest(alpha, 100));

  // signing is deterministic (ed25519 / RFC 8032)
  t.eq(
    "signing is deterministic",
    signObservation(flood(1), alpha).sig,
    signObservation(flood(1), alpha).sig,
  );

  const genuine = signObservation(flood(1), alpha);
  const sybil = signObservation(flood(2), mallory); // unknown author
  const forged = { ...genuine, sig: flipHex(genuine.sig) }; // bad signature
  const tampered = { ...genuine, obs: { ...genuine.obs, rate: 1 } as Observation }; // sig no longer matches

  const r = ingest([genuine, sybil, forged, tampered], trust);

  t.eq("only the genuine observation is accepted", r.accepted.length, 1);
  t.eq("accepted obs is unmodified", r.accepted[0], genuine.obs);

  const reasons = Object.fromEntries(r.rejected.map((x) => [x.signed.author.slice(0, 6), x.reason]));
  t.eq("unknown author -> Sybil rejection", reasons[mallory.fp.slice(0, 6)], "unknown-author");
  t.eq("forged + tampered -> bad-signature", r.rejected.filter((x) => x.reason === "bad-signature").length, 2);

  // revocation closes the gate again
  trust.remove(alpha.fp);
  t.eq("after revocation, even genuine is rejected", ingest([genuine], trust).accepted.length, 0);
};

function flipHex(h: string): string {
  return h.slice(0, -1) + (h.endsWith("0") ? "1" : "0");
}
