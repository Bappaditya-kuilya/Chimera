import { type Suite } from "./harness.js";
import { type Observation, makeId, run, verdict } from "../src/kernel.js";
import { LiveSignalSource, ScriptedSource, type Signal } from "../src/source.js";
import { CausalRuntime } from "../src/runtime.js";

export const name = "M3 runtime (live source · mode split · equivalence)";

export const suite: Suite["suite"] = (t) => {
  const scenario: Observation[] = [
    { id: makeId("PacketFlood", "Bravo", 1), t: 1, kind: "PacketFlood", node: "Bravo", rate: 8000 },
    { id: makeId("PacketFlood", "Bravo", 2), t: 2, kind: "PacketFlood", node: "Bravo", rate: 9500 },
  ];

  // ── incremental runtime == batch run() (one source of truth: fold) ──
  const rt = new CausalRuntime(new ScriptedSource(scenario));
  rt.start();
  const batch = run(scenario);
  t.eq(
    "runtime timeline == batch run() timeline",
    JSON.stringify(rt.snapshot().timeline),
    JSON.stringify(batch.timeline),
  );
  t.eq("live verdict matches batch", rt.verdict, verdict(batch.state));
  t.eq("scripted source is demo mode", rt.mode, "demo");

  // ── simulate() is always SIMULATION and never mutates live state ──
  const before = rt.verdict;
  const sim = rt.simulate({ do: { "Quarantine:Bravo": false } });
  t.eq("simulate is branded SIMULATION", sim.brand, "SIMULATION");
  t.eq("simulate carries the source mode", sim.basedOnMode, "demo");
  t.eq("counterfactual verdict diverges", sim.verdict, "COLLAPSED");
  t.eq("live state untouched by simulate", rt.verdict, before);
  t.eq("live verdict still SURVIVED", rt.verdict, "SURVIVED");

  // ── LiveSignalSource maps app-layer telemetry deterministically ──
  const live = new LiveSignalSource();
  t.eq("high message-rate -> PacketFlood", live.feed({ kind: "message-rate", node: "Bravo", perSec: 8000 })?.kind, "PacketFlood");
  t.eq("normal message-rate -> no observation", live.feed({ kind: "message-rate", node: "Bravo", perSec: 1200 }), null);
  t.eq("bad-signature -> SignatureInvalid", live.feed({ kind: "bad-signature", node: "Alpha" })?.kind, "SignatureInvalid");
  t.eq("route-flap -> RouteFailure", live.feed({ kind: "route-flap", from: "Alpha", to: "Bravo" })?.kind, "RouteFailure");
  t.eq("quiet -> Heartbeat", live.feed({ kind: "quiet", node: "Bravo" })?.kind, "Heartbeat");
  t.eq("live source is live mode", live.mode, "live");

  // ── a full LIVE run from telemetry survives; its counterfactual collapses ──
  const src = new LiveSignalSource();
  const liveRt = new CausalRuntime(src);
  liveRt.start();
  const stream: Signal[] = [
    { kind: "message-rate", node: "Bravo", perSec: 8000 },
    { kind: "message-rate", node: "Bravo", perSec: 9500 },
  ];
  for (const s of stream) src.feed(s);
  t.eq("live runtime SURVIVED from telemetry", liveRt.verdict, "SURVIVED");
  t.eq("live counterfactual COLLAPSED", liveRt.simulate({ do: { "Quarantine:Bravo": false } }).verdict, "COLLAPSED");
  t.eq("live simulate basedOnMode=live", liveRt.simulate({ do: {} }).basedOnMode, "live");
};
