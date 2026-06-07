import { type Suite } from "./harness.js";
import { WebSocket } from "ws";
import { type Observation, makeId } from "../src/kernel.js";
import { CausalRuntime } from "../src/runtime.js";
import { LiveSignalSource } from "../src/source.js";
import { startServer } from "../src/server.js";

export const name = "M10 live HTTP/WebSocket service";

const flood = (t: number): Observation => ({ id: makeId("PacketFlood", "Bravo", t), t, kind: "PacketFlood", node: "Bravo", rate: 9000 });
const wait = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export const suite: Suite["suite"] = async (t) => {
  const rt = new CausalRuntime(new LiveSignalSource());
  const srv = await startServer(rt, { port: 0 }); // ephemeral port
  const base = srv.url;

  try {
    // initial state over REST
    const s0 = await (await fetch(`${base}/api/state`)).json() as any;
    t.eq("initial verdict is SURVIVED", s0.verdict, "SURVIVED");
    t.eq("live mode reported", s0.mode, "live");
    t.eq("topology exposed (4 nodes)", s0.nodes.length, 4);

    // a WS client should receive the live decision stream
    const ws = new WebSocket(base.replace("http", "ws"));
    const messages: Array<{ type: string }> = [];
    ws.on("message", (d) => messages.push(JSON.parse(d.toString())));
    await new Promise<void>((r) => ws.on("open", () => r()));
    await wait(50);

    // POST two real observations -> auto-defense holds
    const r1 = await (await fetch(`${base}/api/observe`, { method: "POST", body: JSON.stringify(flood(1)) })).json() as any;
    t.eq("observe returns a verdict", r1.verdict, "SURVIVED");
    await fetch(`${base}/api/observe`, { method: "POST", body: JSON.stringify(flood(2)) });

    const s1 = await (await fetch(`${base}/api/state`)).json() as any;
    t.eq("after attack + defense: SURVIVED", s1.verdict, "SURVIVED");
    const bravo = s1.nodes.find((n: { node: string }) => n.node === "Bravo");
    t.ok("Bravo ended SCARRED (isolated then recovered)", bravo?.state === "SCARRED");

    const timeline = await (await fetch(`${base}/api/timeline`)).json() as any;
    t.ok("timeline has events", Array.isArray(timeline) && timeline.length > 0);

    // the do()-operator over HTTP is a branded SIMULATION
    const sim = await (await fetch(`${base}/api/simulate`, { method: "POST", body: JSON.stringify({ do: { "Quarantine:Bravo": false } }) })).json() as any;
    t.eq("simulate is branded SIMULATION", sim.brand, "SIMULATION");
    t.eq("simulate verdict diverges", sim.verdict, "COLLAPSED");

    // bad input is rejected, not crashed on
    const bad = await fetch(`${base}/api/observe`, { method: "POST", body: "{not json" });
    t.eq("malformed body -> 400", bad.status, 400);

    await wait(50);
    t.ok("WS streamed an initial state + decisions", messages.some((m) => m.type === "state") && messages.some((m) => m.type === "decisions"));
    ws.close();
  } finally {
    await srv.close();
  }
};
