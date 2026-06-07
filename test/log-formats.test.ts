import { type Suite } from "./harness.js";
import { readFileSync } from "node:fs";
import { counterfactual, run, verdict } from "../src/kernel.js";
import { analyzeLog, detectFormat, parseCsvLog, parseJsonLog } from "../src/sources/log-formats.js";

export const name = "M12 multi-format log analysis (JSON / CSV)";

const cfg = (topology: { nodes: string[]; edges: Record<string, string[]> }) => ({
  topology,
  params: { trustDrop: 0.3, compromised: 0.5, collapseAt: 3, regen: 0.1 },
});

// Same incident as fixtures/access.log, expressed in three formats -> same verdict.
function assertIncident(t: Parameters<Suite["suite"]>[0], label: string, r: ReturnType<typeof analyzeLog>) {
  t.eq(`${label}: four clients`, r.summary.clients.length, 4);
  t.eq(`${label}: busiest is the attacker`, r.summary.busiestClient, "203.0.113.7");
  t.eq(`${label}: two flood-seconds`, r.summary.floods, 2);
  const actual = run(r.observations, undefined, cfg(r.topology));
  const cf = counterfactual(r.observations, { do: { "Quarantine:203.0.113.7": false } }, cfg(r.topology));
  t.eq(`${label}: with defense -> SURVIVED`, verdict(actual.state), "SURVIVED");
  t.eq(`${label}: without blocking -> COLLAPSED`, verdict(cf.state), "COLLAPSED");
}

export const suite: Suite["suite"] = (t) => {
  const json = readFileSync("fixtures/access.json", "utf8");
  const csv = readFileSync("fixtures/access.csv", "utf8");

  // format sniffing
  t.eq("detects JSON", detectFormat(json, "access.json"), "json");
  t.eq("detects CSV", detectFormat(csv, "access.csv"), "csv");
  t.eq("detects combined by content", detectFormat('1.2.3.4 - - [x] "GET / HTTP/1.1" 200'), "combined");

  // same incident, three formats, identical causal verdict
  assertIncident(t, "json", analyzeLog(json, "access.json"));
  assertIncident(t, "csv", analyzeLog(csv, "access.csv"));

  // ISO timestamps and epoch numbers both resolve correctly
  t.ok("JSON ISO times parsed", parseJsonLog(json).observations.length > 0);
  t.ok("CSV epoch times parsed", parseCsvLog(csv).observations.length > 0);

  // robustness: garbage in, nothing out (no throw)
  t.eq("garbage JSON -> no observations", analyzeLog("{ not json", "x.json").observations.length, 0);
  t.eq("empty CSV -> no observations", analyzeLog("ip,status\n", "x.csv").observations.length, 0);
  t.eq("unknown format detected", detectFormat("just some prose without structure"), "unknown");
};
