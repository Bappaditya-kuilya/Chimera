import { type Suite } from "./harness.js";
import { seed } from "./harness.js";
import { type Observation, counterfactual, explain, makeId, run, verdict } from "../src/kernel.js";
import { identityFromSeed, toPairingManifest } from "../src/identity.js";
import { TrustStore } from "../src/trust-store.js";
import { ingest, signObservation } from "../src/ingest.js";

export const name = "kernel through the authenticated pipeline";

export const suite: Suite["suite"] = (t) => {
  // The exact proof scenario, but every observation now arrives SIGNED and is
  // verified before it touches the pure fold. The verdicts must be unchanged.
  const sensor = identityFromSeed("Bravo", seed(2));
  const trust = new TrustStore();
  trust.add(toPairingManifest(sensor, 100));

  const raw: Observation[] = [
    { id: makeId("PacketFlood", "Bravo", 1), t: 1, kind: "PacketFlood", node: "Bravo", rate: 8000 },
    { id: makeId("PacketFlood", "Bravo", 2), t: 2, kind: "PacketFlood", node: "Bravo", rate: 9500 },
  ];
  const { accepted } = ingest(raw.map((o) => signObservation(o, sensor)), trust);
  t.eq("both signed floods authenticate", accepted.length, 2);

  const actual = run(accepted);
  const cf = counterfactual(accepted, { do: { "Quarantine:Bravo": false } });

  t.eq("authenticated actual -> SURVIVED", verdict(actual.state), "SURVIVED");
  t.eq("authenticated do(quarantine=false) -> COLLAPSED", verdict(cf.state), "COLLAPSED");

  // negative control + determinism survive the identity layer
  const forcedTrue = counterfactual(accepted, { do: { "Quarantine:Bravo": true } });
  t.eq("force quarantine=true changes nothing", verdict(forcedTrue.state), "SURVIVED");
  t.eq(
    "determinism preserved",
    JSON.stringify(run(accepted).timeline),
    JSON.stringify(run(accepted).timeline),
  );

  // explainability intact: the quarantine traces back to the two floods
  const qid = makeId("Quarantine", "Bravo", 2);
  t.eq(
    "explain(quarantine) -> the two floods",
    explain(actual.timeline, qid).map((o) => o.id),
    [makeId("PacketFlood", "Bravo", 1), makeId("PacketFlood", "Bravo", 2)],
  );

  // a Sybil's flood never reaches the kernel: drop it, network is fine
  t.eq("no authenticated input -> SURVIVED", verdict(run([]).state), "SURVIVED");
};
