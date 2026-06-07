import { type Suite } from "./harness.js";
import {
  type Config,
  type Observation,
  type Topology,
  counterfactual,
  lifecycle,
  makeId,
  nodeState,
  reconstruct,
  run,
  verdict,
} from "../src/kernel.js";

export const name = "M2 hardening (topology · decay · state machine)";

export const suite: Suite["suite"] = (t) => {
  // ── trust heals over quiet logical time ──
  const heal: Observation[] = [
    { id: makeId("SignatureInvalid", "Bravo", 1), t: 1, kind: "SignatureInvalid", node: "Bravo" },
    { id: makeId("Heartbeat", "Bravo", 2), t: 2, kind: "Heartbeat", node: "Bravo" },
    { id: makeId("Heartbeat", "Bravo", 3), t: 3, kind: "Heartbeat", node: "Bravo" },
  ];
  const healed = run(heal);
  t.eq("attack drops trust to 0.7", reconstruct(healed.timeline, 1).trust["Bravo"], 0.7);
  t.eq("two quiet heartbeats heal to 0.9", reconstruct(healed.timeline, 3).trust["Bravo"], 0.9);
  t.eq("heartbeat on a healthy node does nothing", run([
    { id: makeId("Heartbeat", "Bravo", 1), t: 1, kind: "Heartbeat", node: "Bravo" },
  ]).timeline.length, 1); // just the observation, no TrustRegen

  // ── node lifecycle: reach each of the five states with a minimal scenario ──
  // HEALTHY (untouched), ALERT (trust dented, not infected),
  // EXPOSED (one flood: infected, trust 0.7 still >= compromised, not isolated),
  // ISOLATED (two bad sigs: quarantined, never infected -> never recovers),
  // SCARRED (two floods: isolated then recovered).
  const alert = run([{ id: makeId("SignatureInvalid", "Bravo", 1), t: 1, kind: "SignatureInvalid", node: "Bravo" }]);
  t.eq("ALERT (trust dented, not infected)", nodeState(alert.state, "Bravo"), "ALERT");
  t.eq("untouched node stays HEALTHY", nodeState(alert.state, "Delta"), "HEALTHY");

  const exposed = run([{ id: makeId("PacketFlood", "Bravo", 1), t: 1, kind: "PacketFlood", node: "Bravo", rate: 8000 }]);
  t.eq("EXPOSED (infected, not yet isolated)", nodeState(exposed.state, "Bravo"), "EXPOSED");

  const isolated = run([
    { id: makeId("SignatureInvalid", "Bravo", 1), t: 1, kind: "SignatureInvalid", node: "Bravo" },
    { id: makeId("SignatureInvalid", "Bravo", 2), t: 2, kind: "SignatureInvalid", node: "Bravo" },
  ]);
  t.eq("ISOLATED (quarantined, never infected -> no recovery)", nodeState(isolated.state, "Bravo"), "ISOLATED");

  const incident: Observation[] = [
    { id: makeId("PacketFlood", "Bravo", 1), t: 1, kind: "PacketFlood", node: "Bravo", rate: 8000 },
    { id: makeId("PacketFlood", "Bravo", 2), t: 2, kind: "PacketFlood", node: "Bravo", rate: 9500 },
  ];
  const inc = run(incident);
  t.eq("t1 -> EXPOSED", nodeState(reconstruct(inc.timeline, 1), "Bravo"), "EXPOSED");
  t.eq("t2 -> SCARRED (isolated then recovered)", nodeState(reconstruct(inc.timeline, 2), "Bravo"), "SCARRED");
  t.ok("lifecycle trace ends SCARRED", lifecycle(inc.timeline, "Bravo").map((x) => x.state).includes("SCARRED"));

  // ── topology is just data: the counterfactual diverges on any graph ──
  const LINE: Topology = {
    nodes: ["A", "B", "C", "D", "E"],
    edges: { A: ["B"], B: ["A", "C"], C: ["B", "D"], D: ["C", "E"], E: ["D"] },
  };
  const cfg: Config = { topology: LINE, params: { trustDrop: 0.3, compromised: 0.5, collapseAt: 3, regen: 0.1 } };
  const attack: Observation[] = [
    { id: makeId("PacketFlood", "A", 1), t: 1, kind: "PacketFlood", node: "A", rate: 8000 },
    { id: makeId("PacketFlood", "A", 2), t: 2, kind: "PacketFlood", node: "A", rate: 9500 },
  ];
  t.eq("LINE actual -> SURVIVED", verdict(run(attack, undefined, cfg).state), "SURVIVED");
  t.eq(
    "LINE do(quarantine=false) -> COLLAPSED",
    verdict(counterfactual(attack, { do: { "Quarantine:A": false } }, cfg).state),
    "COLLAPSED",
  );

  // ── determinism survives the new axes ──
  t.eq(
    "hardened run is deterministic",
    JSON.stringify(run(incident).timeline),
    JSON.stringify(run(incident).timeline),
  );
};
