/**
 * CHIMERA KERNEL — a causal security runtime (the proven core, now importable).
 *
 * The whole point: prove that, from IDENTICAL observations, the system's actual
 * policy SURVIVES while do(quarantine = false) COLLAPSES. Deterministic and
 * reproducible -> Chimera is a kernel, not a concept.
 *
 * The law that makes it work:  state = fold(decide over observations),
 * where decide() is PURE (no clock, no randomness, logical ticks, derived ids).
 *
 * Phase 0 note: identity/signature verification happens OUTSIDE this file, at the
 * ingest boundary (see ../src/ingest.ts). By the time observations reach run(),
 * they are already authenticated. This keeps the fold pure and replayable.
 */

// ───────────────────────────── Types ─────────────────────────────

export type NodeId = string;
export type EventId = string;
export type Tick = number; // logical clock — a counter, NEVER wall-clock

// EXOGENOUS — ground-truth facts from the world. Immutable. The ONLY primary input.
export type Observation =
  | { id: EventId; t: Tick; kind: "PacketFlood"; node: NodeId; rate: number }
  | { id: EventId; t: Tick; kind: "HeartbeatLost"; node: NodeId }
  | { id: EventId; t: Tick; kind: "SignatureInvalid"; node: NodeId }
  | { id: EventId; t: Tick; kind: "RouteFailure"; from: NodeId; to: NodeId };

// ENDOGENOUS — consequences. NEVER authored by hand. Always produced by decide().
export type Decision =
  | { id: EventId; t: Tick; kind: "TrustDrop"; node: NodeId; causedBy: EventId[] }
  | { id: EventId; t: Tick; kind: "Quarantine"; node: NodeId; causedBy: EventId[] }
  | { id: EventId; t: Tick; kind: "Reroute"; from: NodeId; to: NodeId; causedBy: EventId[] }
  | { id: EventId; t: Tick; kind: "Spread"; from: NodeId; to: NodeId; causedBy: EventId[] }
  | { id: EventId; t: Tick; kind: "Recovery"; node: NodeId; causedBy: EventId[] }
  | { id: EventId; t: Tick; kind: "Collapse"; causedBy: EventId[] };

export type Event = Observation | Decision;
export type Timeline = Event[];

// Derived world-state. A cache of the fold — NEVER stored as truth.
export type State = {
  trust: Record<NodeId, number>;
  infected: Set<NodeId>;
  quarantined: Set<NodeId>;
  recovered: Set<NodeId>;
  trustLog: Record<NodeId, EventId[]>; // causal ledger: what dropped each node's trust
  quarantineId: Record<NodeId, EventId>; // which decision quarantined each node
  spreads: EventId[]; // every Spread so far (collapse provenance)
  alive: boolean;
};

// The do() operator. Two distinct questions, two distinct keys.
export type Intervention = {
  remove?: EventId[]; //              "what if this OBSERVATION never happened?"
  do?: Record<string, boolean>; //    "what if this DECISION were forced/suppressed?"
};

export type Verdict = "SURVIVED" | "COLLAPSED";

// ──────────────────────────── Topology ───────────────────────────
// Star mesh centred on Bravo (the hub). Attack Bravo and the whole net is at risk.

export const NODES: NodeId[] = ["Alpha", "Bravo", "Charlie", "Delta"];
export const EDGES: Record<NodeId, NodeId[]> = {
  Alpha: ["Bravo"],
  Bravo: ["Alpha", "Charlie", "Delta"],
  Charlie: ["Bravo"],
  Delta: ["Bravo"],
};

export const TRUST_DROP = 0.3; // each attack signal costs this much trust
export const COMPROMISED = 0.5; // trust below this = compromised
export const COLLAPSE_AT = 3; // this many live-infected nodes = network collapse

const neighbors = (n: NodeId): NodeId[] => [...(EDGES[n] ?? [])].sort();

// ──────────────────────────── Helpers ────────────────────────────

// Deterministic id — derived purely from (kind, label, tick). NEVER random.
export function makeId(kind: string, label: string, t: Tick): EventId {
  return label ? `${kind}:${label}@t${t}` : `${kind}@t${t}`;
}

export function genesis(): State {
  const trust: Record<NodeId, number> = {};
  const trustLog: Record<NodeId, EventId[]> = {};
  for (const n of NODES) {
    trust[n] = 1.0;
    trustLog[n] = [];
  }
  return {
    trust,
    infected: new Set(),
    quarantined: new Set(),
    recovered: new Set(),
    trustLog,
    quarantineId: {},
    spreads: [],
    alive: true,
  };
}

export function clone(s: State): State {
  return {
    trust: { ...s.trust },
    infected: new Set(s.infected),
    quarantined: new Set(s.quarantined),
    recovered: new Set(s.recovered),
    trustLog: Object.fromEntries(Object.entries(s.trustLog).map(([k, v]) => [k, [...v]])),
    quarantineId: { ...s.quarantineId },
    spreads: [...s.spreads],
    alive: s.alive,
  };
}

// ──────────────────── apply: the single fold step ────────────────────
// Pure: (state, event) -> next state. Used by BOTH run() and reconstruct().

export function apply(state: State, e: Event): State {
  const s = clone(state);
  switch (e.kind) {
    case "PacketFlood":
      s.infected.add(e.node); // being flooded = exposed/infected
      break;
    case "HeartbeatLost":
    case "SignatureInvalid":
    case "RouteFailure":
      break; // raw signals; trust only ever moves through decisions
    case "TrustDrop":
      s.trust[e.node] = Math.max(0, (s.trust[e.node] ?? 1) - TRUST_DROP);
      s.trustLog[e.node] = [...(s.trustLog[e.node] ?? []), e.id];
      break;
    case "Quarantine":
      s.quarantined.add(e.node);
      s.quarantineId[e.node] = e.id;
      break;
    case "Spread":
      s.infected.add(e.to);
      s.trust[e.to] = 0; // a spread-to node is fully compromised
      s.trustLog[e.to] = [...(s.trustLog[e.to] ?? []), e.id];
      s.spreads.push(e.id);
      break;
    case "Recovery":
      s.trust[e.node] = 1.0;
      s.infected.delete(e.node);
      s.recovered.add(e.node);
      break;
    case "Reroute":
      break; // routing flavour; no state impact in the kernel
    case "Collapse":
      s.alive = false;
      break;
  }
  return s;
}

// ──────────────────── decide: THE policy (pure) ────────────────────
// Same (state, obs) -> same decisions. No Date.now, no Math.random.
//   obs !== null  -> observation-driven reactions (the system reacting to detected facts)
//   obs === null  -> state-driven cascade, returns AT MOST ONE decision (run() loops to fixpoint)

export function decide(
  state: State,
  obs: Observation | null,
  iv: Intervention | undefined,
  tick: Tick,
): Decision[] {
  if (obs) {
    switch (obs.kind) {
      case "PacketFlood":
      case "HeartbeatLost":
      case "SignatureInvalid": {
        const node = obs.node;
        const out: Decision[] = [];
        const tdId = makeId("TrustDrop", node, tick);
        out.push({ id: tdId, t: tick, kind: "TrustDrop", node, causedBy: [obs.id] });

        // Quarantine is OBSERVATION-driven: you isolate a node because you DETECTED
        // an attack on it. Silent spread (no fresh observation) is never reacted to.
        const newTrust = Math.max(0, (state.trust[node] ?? 1) - TRUST_DROP);
        const forced = iv?.do?.[`Quarantine:${node}`];
        const wouldQuarantine = newTrust < COMPROMISED || forced === true;
        if (forced !== false && wouldQuarantine && !state.quarantined.has(node)) {
          out.push({
            id: makeId("Quarantine", node, tick),
            t: tick,
            kind: "Quarantine",
            node,
            causedBy: [...(state.trustLog[node] ?? []), tdId],
          });
        }
        return out;
      }
      case "RouteFailure":
        return [
          {
            id: makeId("Reroute", `${obs.from}-${obs.to}`, tick),
            t: tick,
            kind: "Reroute",
            from: obs.from,
            to: obs.to,
            causedBy: [obs.id],
          },
        ];
    }
  }

  // ── state-driven cascade (one decision per call) ──

  // 1. Spread: a compromised, un-quarantined node infects an uninfected neighbour.
  for (const from of NODES) {
    if (state.infected.has(from) && (state.trust[from] ?? 1) < COMPROMISED && !state.quarantined.has(from)) {
      for (const to of neighbors(from)) {
        if (!state.infected.has(to)) {
          return [
            {
              id: makeId("Spread", `${from}->${to}`, tick),
              t: tick,
              kind: "Spread",
              from,
              to,
              causedBy: [...(state.trustLog[from] ?? [])],
            },
          ];
        }
      }
    }
  }

  // 2. Collapse: too many live-infected nodes and the organism dies.
  const live = NODES.filter((n) => state.infected.has(n) && !state.quarantined.has(n));
  if (state.alive && live.length >= COLLAPSE_AT) {
    return [{ id: makeId("Collapse", "", tick), t: tick, kind: "Collapse", causedBy: [...state.spreads] }];
  }

  // 3. Recovery: once nothing live is still compromised, quarantined nodes heal.
  const stillCompromised = NODES.some(
    (n) => !state.quarantined.has(n) && state.infected.has(n) && (state.trust[n] ?? 1) < COMPROMISED,
  );
  if (!stillCompromised) {
    for (const n of NODES) {
      if (state.quarantined.has(n) && state.infected.has(n) && !state.recovered.has(n)) {
        return [
          {
            id: makeId("Recovery", n, tick),
            t: tick,
            kind: "Recovery",
            node: n,
            causedBy: [state.quarantineId[n]].filter(Boolean) as EventId[],
          },
        ];
      }
    }
  }

  return [];
}

// ──────────────────── run: THE engine ────────────────────
// Folds observations in (tick, id) order, interleaving derived decisions and
// running the cascade to a fixpoint after each. Honours the intervention.

export function run(observations: Observation[], iv?: Intervention): { timeline: Timeline; state: State } {
  const removed = new Set(iv?.remove ?? []);
  const inbox = observations
    .filter((o) => !removed.has(o.id))
    .slice()
    .sort((a, b) => a.t - b.t || a.id.localeCompare(b.id));

  let state = genesis();
  const timeline: Timeline = [];

  for (const o of inbox) {
    timeline.push(o);
    state = apply(state, o);
    for (const d of decide(state, o, iv, o.t)) {
      timeline.push(d);
      state = apply(state, d);
    }
    // drive the cascade to a fixpoint (terminates: state changes are monotonic)
    for (let guard = 0; guard < 1000; guard++) {
      const [d] = decide(state, null, iv, o.t);
      if (!d) break;
      timeline.push(d);
      state = apply(state, d);
    }
  }

  return { timeline, state };
}

// ──────────────────── derived queries ────────────────────

// State as-of a tick: replay the recorded timeline up to t. Powers Memory River.
export function reconstruct(timeline: Timeline, t: Tick): State {
  let state = genesis();
  for (const e of timeline) if (e.t <= t) state = apply(state, e);
  return state;
}

// The explicit do()-operator entry point.
export function counterfactual(
  observations: Observation[],
  iv: Intervention,
): { timeline: Timeline; state: State } {
  return run(observations, iv);
}

// Walk causedBy parents transitively -> the observations that justify a decision.
const OBS_KINDS = new Set(["PacketFlood", "HeartbeatLost", "SignatureInvalid", "RouteFailure"]);
export function explain(timeline: Timeline, decisionId: EventId): Observation[] {
  const byId = new Map(timeline.map((e) => [e.id, e]));
  const seen = new Set<EventId>();
  const roots: Observation[] = [];
  const stack = [decisionId];
  while (stack.length) {
    const id = stack.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    const e = byId.get(id);
    if (!e) continue;
    if (OBS_KINDS.has(e.kind)) roots.push(e as Observation);
    else for (const p of (e as Decision).causedBy ?? []) stack.push(p);
  }
  return roots.sort((a, b) => a.t - b.t || a.id.localeCompare(b.id));
}

// Where/how two timelines diverge.
export function diff(a: Timeline, b: Timeline): { divergedAt: Tick; onlyInA: Event[]; onlyInB: Event[] } {
  let i = 0;
  while (i < a.length && i < b.length && a[i]!.id === b[i]!.id) i++;
  const divergedAt = a[i]?.t ?? b[i]?.t ?? -1;
  return { divergedAt, onlyInA: a.slice(i), onlyInB: b.slice(i) };
}

export function verdict(state: State): Verdict {
  return state.alive ? "SURVIVED" : "COLLAPSED";
}
