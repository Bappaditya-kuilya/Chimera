import { type Suite } from "./harness.js";
import { seed } from "./harness.js";
import { type Observation, makeId } from "../src/kernel.js";
import { identityFromSeed, toPairingManifest } from "../src/identity.js";
import { TrustStore } from "../src/trust-store.js";
import { ReplayGuard, ingest, signObservation } from "../src/ingest.js";

export const name = "M7 replay protection";

const flood = (t: number): Observation => ({
  id: makeId("PacketFlood", "Bravo", t),
  t,
  kind: "PacketFlood",
  node: "Bravo",
  rate: 8000,
});

export const suite: Suite["suite"] = (t) => {
  const sensor = identityFromSeed("Bravo", seed(2));
  const trust = new TrustStore();
  trust.add(toPairingManifest(sensor, 1));
  const guard = new ReplayGuard();

  const a = signObservation(flood(1), sensor);
  const b = signObservation(flood(2), sensor);

  // first delivery: both accepted
  const first = ingest([a, b], trust, guard);
  t.eq("fresh observations accepted", first.accepted.length, 2);

  // exact resend of a genuine, validly-signed observation -> replay
  const replayed = ingest([a], trust, guard);
  t.eq("captured-and-resent is rejected", replayed.accepted.length, 0);
  t.eq("...with reason replay", replayed.rejected[0]?.reason, "replay");

  // an older-tick observation after a newer one -> stale (can't rewrite the past)
  const old = signObservation(flood(1), sensor); // tick 1, but we've already seen tick 2
  // different id so it's not a duplicate; force a distinct id at same tick
  const oldDistinct = { ...old, obs: { ...old.obs, id: "PacketFlood:Bravo.b@t1" } };
  const reSigned = signObservation(oldDistinct.obs, sensor);
  const stale = ingest([reSigned], trust, guard);
  t.eq("stale (older tick) is rejected", stale.accepted.length, 0);
  t.eq("...with reason stale", stale.rejected[0]?.reason, "stale");

  // without a guard, ingest stays backward-compatible (no freshness checks)
  const noGuard = ingest([a, a], trust);
  t.eq("no guard -> no replay checks (back-compat)", noGuard.accepted.length, 2);

  // monotonic can be disabled while still catching exact duplicates
  const g2 = new ReplayGuard({ monotonic: false });
  const t2 = new TrustStore(); t2.add(toPairingManifest(sensor, 1));
  ingest([b], t2, g2); // see tick 2 first
  t.eq("non-monotonic allows older tick", ingest([a], t2, g2).accepted.length, 1);
  t.eq("non-monotonic still blocks exact replay", ingest([a], t2, g2).rejected[0]?.reason, "replay");
};
