/**
 * source.ts — where observations COME FROM.  The "Causal Security Runtime" pivot.
 *
 * The kernel doesn't care whether a PacketFlood came from a scripted demo, a mesh
 * peer, a k8s log, or a firewall. It only folds Observations. So we put a single
 * interface in front of it — ObservationSource — and the engine becomes a runtime
 * that any source can drive.
 *
 * THE MODE SPLIT (handoff §4.1, the load-bearing safety property):
 *   A real defensive system must act ONLY on observable signals. A scripted attack
 *   or a counterfactual is a SIMULATION and must be labelled as such, or the
 *   product gives false confidence ("we're protected" — against a fake attack).
 *   So every source declares its Mode, and that mode travels with the data.
 *
 *     Mode "live" : observations derived from real runtime signals. Acted upon.
 *     Mode "demo" : scripted/replayed observations. Clearly simulation.
 */

import { type Observation, type NodeId, type Tick, makeId } from "./kernel.js";

export type Mode = "live" | "demo";

export type ObservationHandler = (o: Observation) => void;

/** Anything that can feed observations into the runtime. */
export interface ObservationSource {
  readonly mode: Mode;
  readonly name: string;
  subscribe(handler: ObservationHandler): () => void; // returns an unsubscribe fn
  start(): void | Promise<void>;
  stop(): void | Promise<void>;
}

// ──────────────────────── ScriptedSource (demo) ────────────────────────
// Replays a fixed list of observations. This is DEMONSTRATION mode — the attack
// is authored, not observed. Use it for demos, tests, and counterfactual stories.

export class ScriptedSource implements ObservationSource {
  readonly mode: Mode = "demo";
  private handlers = new Set<ObservationHandler>();
  private started = false;

  constructor(
    private script: Observation[],
    readonly name = "scripted",
  ) {}

  subscribe(handler: ObservationHandler): () => void {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  start(): void {
    if (this.started) return;
    this.started = true;
    // emit in deterministic (tick, id) order — matches the batch engine's sort
    const ordered = [...this.script].sort((a, b) => a.t - b.t || a.id.localeCompare(b.id));
    for (const o of ordered) for (const h of [...this.handlers]) h(o);
  }

  stop(): void {
    this.started = false;
  }
}

// ──────────────────────── LiveSignalSource (live) ────────────────────────
// Maps real APP-LAYER telemetry into observations. The handoff is explicit: a
// browser/Node process can't see raw packets, so the LIVE path uses app-layer
// signals — message rate, signature failures, malformed payloads, route flapping.
// The mapping is deterministic and is the only place "is this an attack?" lives.

/** App-layer telemetry — what a real node can actually measure about its peers. */
export type Signal =
  | { kind: "message-rate"; node: NodeId; perSec: number } // bursty traffic
  | { kind: "bad-signature"; node: NodeId } // a peer sent an unverifiable message (see ingest.ts)
  | { kind: "malformed-payload"; node: NodeId } // protocol violation
  | { kind: "route-flap"; from: NodeId; to: NodeId } // a link kept dropping
  | { kind: "quiet"; node: NodeId }; // a clean interval — evidence of good behaviour

export type LiveThresholds = {
  floodPerSec: number; // message-rate above this reads as a PacketFlood
};

export const DEFAULT_THRESHOLDS: LiveThresholds = { floodPerSec: 5000 };

export class LiveSignalSource implements ObservationSource {
  readonly mode: Mode = "live";
  private handlers = new Set<ObservationHandler>();
  private tick = 0; // logical clock: monotonically advances per ingested signal

  constructor(
    readonly name = "live-app-layer",
    private thresholds: LiveThresholds = DEFAULT_THRESHOLDS,
  ) {}

  subscribe(handler: ObservationHandler): () => void {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  start(): void {}
  stop(): void {}

  /**
   * Translate one real telemetry signal into an observation (or none) and emit it.
   * Returns the observation produced, for testing. Pure mapping; tick is a counter.
   */
  feed(signal: Signal): Observation | null {
    const t: Tick = ++this.tick;
    const o = this.map(signal, t);
    if (o) for (const h of [...this.handlers]) h(o);
    return o;
  }

  private map(s: Signal, t: Tick): Observation | null {
    switch (s.kind) {
      case "message-rate":
        return s.perSec >= this.thresholds.floodPerSec
          ? { id: makeId("PacketFlood", s.node, t), t, kind: "PacketFlood", node: s.node, rate: s.perSec }
          : null; // normal traffic is not an observation worth recording
      case "bad-signature":
        return { id: makeId("SignatureInvalid", s.node, t), t, kind: "SignatureInvalid", node: s.node };
      case "malformed-payload":
        return { id: makeId("SignatureInvalid", s.node, t), t, kind: "SignatureInvalid", node: s.node };
      case "route-flap":
        return { id: makeId("RouteFailure", `${s.from}-${s.to}`, t), t, kind: "RouteFailure", from: s.from, to: s.to };
      case "quiet":
        return { id: makeId("Heartbeat", s.node, t), t, kind: "Heartbeat", node: s.node };
    }
  }
}
