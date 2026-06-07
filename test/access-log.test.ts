import { type Suite } from "./harness.js";
import { readFileSync } from "node:fs";
import { counterfactual, run, verdict } from "../src/kernel.js";
import { parseAccessLog } from "../src/sources/access-log.js";

export const name = "M9 real access-log analysis";

const cfg = (topology: { nodes: string[]; edges: Record<string, string[]> }) => ({
  topology,
  params: { trustDrop: 0.3, compromised: 0.5, collapseAt: 3, regen: 0.1 },
});

export const suite: Suite["suite"] = (t) => {
  const text = readFileSync("fixtures/access.log", "utf8");
  const r = parseAccessLog(text);

  // parsing the real combined log format
  t.eq("all 19 log lines parsed", r.summary.lines, 19);
  t.eq("four distinct clients found", r.summary.clients.length, 4);
  t.eq("busiest client is the attacker", r.summary.busiestClient, "203.0.113.7");
  t.eq("two flood-seconds detected", r.summary.floods, 2);
  t.ok("attacker floods are on the right node", r.observations.every((o) => o.kind !== "PacketFlood" || o.node === "203.0.113.7"));

  // topology derived from the log: a Server hub + each client as a leaf
  t.ok("topology has a Server hub", r.topology.nodes.includes("Server"));
  t.eq("topology node count = server + clients", r.topology.nodes.length, 5);
  t.ok("clients are leaves of Server", r.topology.edges["203.0.113.7"]?.includes("Server") === true);

  // the causal verdict on real data
  const actual = run(r.observations, undefined, cfg(r.topology));
  const cf = counterfactual(r.observations, { do: { "Quarantine:203.0.113.7": false } }, cfg(r.topology));
  t.eq("with auto-defense (block attacker) -> SURVIVED", verdict(actual.state), "SURVIVED");
  t.eq("without blocking the attacker -> COLLAPSED", verdict(cf.state), "COLLAPSED");

  // determinism on real input
  t.eq("parse is deterministic", JSON.stringify(parseAccessLog(text)), JSON.stringify(parseAccessLog(text)));

  // an empty/garbage log yields nothing, gracefully
  const empty = parseAccessLog("not a log\n\n# comment");
  t.eq("garbage log -> no observations", empty.observations.length, 0);
};
