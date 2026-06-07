/**
 * runtime.ts — the LIVE engine: fold observations as they arrive, not in a batch.
 *
 * run() in kernel.ts is batch (great for proofs/replay). A real deployment gets
 * observations one at a time, forever. CausalRuntime drives the SAME pure fold()
 * incrementally, keeping the authoritative timeline + state, and records the exact
 * observation log so the run is perfectly replayable and counterfactual-able.
 *
 * The mode split, enforced here:
 *   - It is attached to a source with a Mode (live | demo).
 *   - simulate(iv) — the do()-operator — NEVER touches live state. It re-folds the
 *     recorded observation log on a throwaway copy and returns a result explicitly
 *     branded SIMULATION. You cannot accidentally present a counterfactual as the
 *     real timeline. That is the difference between insight and false confidence.
 */

import {
  type Config,
  type Decision,
  type Intervention,
  type Observation,
  type State,
  type Timeline,
  type Verdict,
  DEFAULT_CONFIG,
  fold,
  genesis,
  verdict,
} from "./kernel.js";
import { type Mode, type ObservationSource } from "./source.js";

export type Branded = "ACTUAL" | "SIMULATION";

export type RuntimeSnapshot = {
  brand: Branded;
  mode: Mode;
  verdict: Verdict;
  timeline: Timeline;
  observations: Observation[];
};

export type SimulationResult = {
  brand: "SIMULATION"; // always — a counterfactual is never the real timeline
  basedOnMode: Mode;
  intervention: Intervention;
  verdict: Verdict;
  timeline: Timeline;
  state: State;
};

export class CausalRuntime {
  readonly mode: Mode;
  private state: State;
  private log: Observation[] = []; // the authoritative observation history
  private events: Timeline = []; // observations + produced decisions, in order
  private unsubscribe: (() => void) | null = null;
  private listeners = new Set<(produced: Decision[], o: Observation) => void>();

  constructor(
    private source: ObservationSource,
    private config: Config = DEFAULT_CONFIG,
  ) {
    this.mode = source.mode;
    this.state = genesis(config.topology);
  }

  /** Begin consuming the source. Each observation is folded immediately. */
  start(): void {
    if (this.unsubscribe) return;
    this.unsubscribe = this.source.subscribe((o) => this.ingest(o));
    void this.source.start();
  }

  stop(): void {
    this.unsubscribe?.();
    this.unsubscribe = null;
    void this.source.stop();
  }

  /** Fold a single observation into live state. Returns the decisions it produced. */
  ingest(o: Observation): Decision[] {
    this.log.push(o);
    this.events.push(o);
    const r = fold(this.state, o, undefined, this.config);
    this.state = r.state;
    this.events.push(...r.produced);
    for (const l of [...this.listeners]) l(r.produced, o);
    return r.produced;
  }

  /** Subscribe to live decisions as they are derived (for UI / alerting). */
  onDecisions(listener: (produced: Decision[], o: Observation) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  // ── authoritative (ACTUAL) views ──
  get verdict(): Verdict {
    return verdict(this.state);
  }
  /** The live world-state (a snapshot copy is not made — treat as read-only). */
  liveState(): State {
    return this.state;
  }
  /** The nodes of this runtime's topology. */
  nodes(): string[] {
    return this.config.topology.nodes;
  }
  snapshot(): RuntimeSnapshot {
    return {
      brand: "ACTUAL",
      mode: this.mode,
      verdict: this.verdict,
      timeline: [...this.events],
      observations: [...this.log],
    };
  }
  get observationLog(): Observation[] {
    return [...this.log];
  }

  /**
   * The do()-operator on recorded history. ALWAYS a simulation: it re-folds the
   * observation log on a fresh state and returns a SIMULATION-branded result.
   * Live state is untouched — guaranteed, because we never mutate this.state here.
   */
  simulate(iv: Intervention): SimulationResult {
    // re-run the recorded observations under the intervention, from genesis
    let s = genesis(this.config.topology);
    const timeline: Timeline = [];
    const removed = new Set(iv.remove ?? []);
    const inbox = this.log
      .filter((o) => !removed.has(o.id))
      .slice()
      .sort((a, b) => a.t - b.t || a.id.localeCompare(b.id));
    for (const o of inbox) {
      timeline.push(o);
      const r = fold(s, o, iv, this.config);
      s = r.state;
      timeline.push(...r.produced);
    }
    return {
      brand: "SIMULATION",
      basedOnMode: this.mode,
      intervention: iv,
      verdict: verdict(s),
      timeline,
      state: s,
    };
  }
}
