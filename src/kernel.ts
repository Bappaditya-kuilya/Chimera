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
 *
 * M2 (hardening): topology + tuning are now a Config threaded through the fold
 * (default = STAR + DEFAULT_PARAMS, so the original proof is byte-identical).
 * Added: Heartbeat/TrustRegen (trust heals over quiet logical time) and the
 * HEALTHY/ALERT/EXPOSED/ISOLATED/SCARRED node lifecycle (a pure projection).
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
  | { id: EventId; t: Tick; kind: "RouteFailure"; from: NodeId; to: NodeId }
  | { id: EventId; t: Tick; kind: "Heartbeat"; node: NodeId }; // a quiet tick: "node behaved"

// ENDOGENOUS — consequences. NEVER authored by hand. Always produced by decide().
export type Decision =
  | { id: EventId; t: Tick; kind: "TrustDrop"; node: NodeId; causedBy: EventId[] }
  | { id: EventId; t: Tick; kind: "TrustRegen"; node: NodeId; causedBy: EventId[] }
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

// ──────────────────────────── Config ─────────────────────────────
// Topology and tuning are data, not hardcoded — so the SAME engine runs a star
// mesh, a line, a k8s cluster, whatever. Defaults reproduce the original proof.

export type Topology = { nodes: NodeId[]; edges: Record<NodeId, NodeId[]> };
export type Params = {
  trustDrop: number; // each attack signal costs this much trust
  compromised: number; // trust below this = compromised
  collapseAt: number; // this many live-infected nodes = network collapse
  regen: number; // trust healed per quiet Heartbeat (decay-over-time, reversed)
};
export type Config = { topology: Topology; params: Params };

// Star mesh centred on Bravo (the hub). Attack Bravo and the whole net is at risk.
export const STAR: Topology = {
  nodes: ["Alpha", "Bravo", "Charlie", "Delta"],
  edges: {
    Alpha: ["Bravo"],
    Bravo: ["Alpha", "Charlie", "Delta"],
    Charlie: ["Bravo"],
    Delta: ["Bravo"],
  },
};

export const DEFAULT_PARAMS: Params = { trustDrop: 0.3, compromised: 0.5, collapseAt: 3, regen: 0.1 };
export const DEFAULT_CONFIG: Config = { topology: STAR, params: DEFAULT_PARAMS };

// Back-compat aliases (older imports). Same values the proof was built on.
export const NODES = STAR.nodes;
export const EDGES = STAR.edges;
export const TRUST_DROP = DEFAULT_PARAMS.trustDrop;
export const COMPROMISED = DEFAULT_PARAMS.compromised;
export const COLLAPSE_AT = DEFAULT_PARAMS.collapseAt;

const neighbors = (topo: Topology, n: NodeId): NodeId[] => [...(topo.edges[n] ?? [])].sort();

// ──────────────────────────── Helpers ────────────────────────────

// Deterministic id — derived purely from (kind, label, tick). NEVER random.
export function makeId(kind: string, label: string, t: Tick): EventId {
  return label ? `${kind}:${label}@t${t}` : `${kind}@t${t}`;
}

export function genesis(topo: Topology = STAR): State {
  const trust: Record<NodeId, number> = {};
  const trustLog: Record<NodeId, EventId[]> = {};
  for (const n of topo.nodes) {
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

// trust never escapes [0, 1]; rounded to kill float drift so replay is exact.
const clampTrust = (x: number): number => Math.round(Math.max(0, Math.min(1, x)) * 1e6) / 1e6;

// ──────────────────── apply: the single fold step ────────────────────
// Pure: (state, event, params) -> next state. Used by BOTH run() and reconstruct().

export function apply(state: State, e: Event, params: Params = DEFAULT_PARAMS): State {
  const s = clone(state);
  switch (e.kind) {
    case "PacketFlood":
      s.infected.add(e.node); // being flooded = exposed/infected
      break;
    case "HeartbeatLost":
    case "SignatureInvalid":
    case "RouteFailure":
    case "Heartbeat":
      break; // raw signals; trust only ever moves through decisions
    case "TrustDrop":
      s.trust[e.node] = clampTrust((s.trust[e.node] ?? 1) - params.trustDrop);
      s.trustLog[e.node] = [...(s.trustLog[e.node] ?? []), e.id];
      break;
    case "TrustRegen":
      s.trust[e.node] = clampTrust((s.trust[e.node] ?? 1) + params.regen);
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
  config: Config = DEFAULT_CONFIG,
): Decision[] {
  const { topology: topo, params } = config;
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
        const newTrust = clampTrust((state.trust[node] ?? 1) - params.trustDrop);
        const forced = iv?.do?.[`Quarantine:${node}`];
        const wouldQuarantine = newTrust < params.compromised || forced === true;
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
      case "Heartbeat": {
        // Trust heals over quiet logical time: a node that is behaving (not
        // currently infected) regenerates trust toward baseline. This is the
        // "trust decay over time" axis — reversed, because recovery is the goal.
        const node = obs.node;
        if (!state.infected.has(node) && (state.trust[node] ?? 1) < 1) {
          return [
            { id: makeId("TrustRegen", node, tick), t: tick, kind: "TrustRegen", node, causedBy: [obs.id] },
          ];
        }
        return [];
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
  for (const from of topo.nodes) {
    if (state.infected.has(from) && (state.trust[from] ?? 1) < params.compromised && !state.quarantined.has(from)) {
      for (const to of neighbors(topo, from)) {
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
  const live = topo.nodes.filter((n) => state.infected.has(n) && !state.quarantined.has(n));
  if (state.alive && live.length >= params.collapseAt) {
    return [{ id: makeId("Collapse", "", tick), t: tick, kind: "Collapse", causedBy: [...state.spreads] }];
  }

  // 3. Recovery: once nothing live is still compromised, quarantined nodes heal.
  const stillCompromised = topo.nodes.some(
    (n) => !state.quarantined.has(n) && state.infected.has(n) && (state.trust[n] ?? 1) < params.compromised,
  );
  if (!stillCompromised) {
    for (const n of topo.nodes) {
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

// ──────────────────── fold: one observation -> its consequences ────────────────────
// The atomic step shared by the batch engine (run) and the incremental runtime
// (CausalRuntime). Pure: applies the observation, the observation-driven
// decisions, then drives the state cascade to a fixpoint. Returns the new state
// and the decisions PRODUCED (the caller owns where the observation goes in the log).

export function fold(
  state: State,
  o: Observation,
  iv: Intervention | undefined,
  config: Config = DEFAULT_CONFIG,
): { state: State; produced: Decision[] } {
  const produced: Decision[] = [];
  let s = apply(state, o, config.params);
  for (const d of decide(s, o, iv, o.t, config)) {
    produced.push(d);
    s = apply(s, d, config.params);
  }
  // drive the cascade to a fixpoint (terminates: state changes are monotonic)
  for (let guard = 0; guard < 1000; guard++) {
    const [d] = decide(s, null, iv, o.t, config);
    if (!d) break;
    produced.push(d);
    s = apply(s, d, config.params);
  }
  return { state: s, produced };
}

// ──────────────────── run: THE engine ────────────────────
// Folds observations in (tick, id) order, interleaving derived decisions and
// running the cascade to a fixpoint after each. Honours the intervention.

export function run(
  observations: Observation[],
  iv?: Intervention,
  config: Config = DEFAULT_CONFIG,
): { timeline: Timeline; state: State } {
  const removed = new Set(iv?.remove ?? []);
  const inbox = observations
    .filter((o) => !removed.has(o.id))
    .slice()
    .sort((a, b) => a.t - b.t || a.id.localeCompare(b.id));

  let state = genesis(config.topology);
  const timeline: Timeline = [];

  for (const o of inbox) {
    timeline.push(o);
    const r = fold(state, o, iv, config);
    state = r.state;
    timeline.push(...r.produced);
  }

  return { timeline, state };
}

// ──────────────────── derived queries ────────────────────

// State as-of a tick: replay the recorded timeline up to t. Powers Memory River.
export function reconstruct(timeline: Timeline, t: Tick, params: Params = DEFAULT_PARAMS): State {
  let state = genesis();
  for (const e of timeline) if (e.t <= t) state = apply(state, e, params);
  return state;
}

// The explicit do()-operator entry point.
export function counterfactual(
  observations: Observation[],
  iv: Intervention,
  config: Config = DEFAULT_CONFIG,
): { timeline: Timeline; state: State } {
  return run(observations, iv, config);
}

// Walk causedBy parents transitively -> the observations that justify a decision.
const OBS_KINDS = new Set(["PacketFlood", "HeartbeatLost", "SignatureInvalid", "RouteFailure", "Heartbeat"]);
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

// ──────────────────── node lifecycle (M2) ────────────────────
// A PURE projection over State — not stored, derived. Five states:
//   HEALTHY  : trust intact, not under attack
//   ALERT    : trust dented (an attack signal landed) but not infected
//   EXPOSED  : actively infected / under live attack, not yet isolated
//   ISOLATED : quarantined, not yet healed
//   SCARRED  : was isolated, has recovered — healthy again, but it happened

export type NodeState = "HEALTHY" | "ALERT" | "EXPOSED" | "ISOLATED" | "SCARRED";

export function nodeState(state: State, node: NodeId, params: Params = DEFAULT_PARAMS): NodeState {
  if (state.quarantined.has(node)) return state.recovered.has(node) ? "SCARRED" : "ISOLATED";
  if (state.infected.has(node)) return "EXPOSED";
  const trust = state.trust[node] ?? 1;
  void params; // thresholds reserved for future graded ALERT levels
  return trust < 1 ? "ALERT" : "HEALTHY";
}

/** The lifecycle trace for a node: every tick at which its state changed. */
export function lifecycle(
  timeline: Timeline,
  node: NodeId,
  params: Params = DEFAULT_PARAMS,
): Array<{ t: Tick; state: NodeState }> {
  const ticks = [...new Set(timeline.map((e) => e.t))].sort((a, b) => a - b);
  const out: Array<{ t: Tick; state: NodeState }> = [];
  let prev: NodeState | null = null;
  for (const t of ticks) {
    const st = nodeState(reconstruct(timeline, t, params), node, params);
    if (st !== prev) out.push({ t, state: st });
    prev = st;
  }
  return out;
}
