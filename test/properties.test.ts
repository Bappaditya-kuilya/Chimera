import { type Suite } from "./harness.js";
import {
  type Observation,
  type State,
  STAR,
  makeId,
  reconstruct,
  run,
} from "../src/kernel.js";
import { ScriptedSource } from "../src/source.js";
import { CausalRuntime } from "../src/runtime.js";

export const name = "M8 properties (fuzzed invariants)";

// Deterministic PRNG (mulberry32) — the kernel forbids Math.random, but tests may
// use a SEEDED generator so every run explores the same cases reproducibly.
function rng(seedN: number): () => number {
  let a = seedN >>> 0;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let x = Math.imul(a ^ (a >>> 15), 1 | a);
    x = (x + Math.imul(x ^ (x >>> 7), 61 | x)) ^ x;
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
  };
}

const KINDS = ["PacketFlood", "SignatureInvalid", "Heartbeat", "HeartbeatLost"] as const;

function randomScenario(r: () => number): Observation[] {
  const n = 1 + Math.floor(r() * 8); // 1..8 observations
  const obs: Observation[] = [];
  for (let i = 0; i < n; i++) {
    const t = i + 1; // distinct ticks -> unique ids, clean ordering
    const node = STAR.nodes[Math.floor(r() * STAR.nodes.length)]!;
    const kind = KINDS[Math.floor(r() * KINDS.length)]!;
    if (kind === "PacketFlood") obs.push({ id: makeId(kind, node, t), t, kind, node, rate: 8000 });
    else obs.push({ id: makeId(kind, node, t), t, kind, node } as Observation);
  }
  return obs;
}

// Canonical signature of a State, for deep equality across runs.
function stateKey(s: State): string {
  return JSON.stringify({
    trust: Object.fromEntries(Object.keys(s.trust).sort().map((k) => [k, s.trust[k]])),
    infected: [...s.infected].sort(),
    quarantined: [...s.quarantined].sort(),
    recovered: [...s.recovered].sort(),
    alive: s.alive,
  });
}

export const suite: Suite["suite"] = (t) => {
  const r = rng(0xc0ffee);
  const N = 400;
  let detOk = 0, trustOk = 0, reconOk = 0, runtimeOk = 0, removeOk = 0;

  for (let i = 0; i < N; i++) {
    const obs = randomScenario(r);

    // 1. determinism: two runs are byte-identical
    if (JSON.stringify(run(obs).timeline) === JSON.stringify(run(obs).timeline)) detOk++;

    const { timeline, state } = run(obs);

    // 2. trust is always within [0, 1]
    if (Object.values(state.trust).every((v) => v >= 0 && v <= 1)) trustOk++;

    // 3. reconstruct at the last tick reproduces the run's final state
    const maxT = timeline.reduce((m, e) => Math.max(m, e.t), 0);
    if (stateKey(reconstruct(timeline, maxT)) === stateKey(state)) reconOk++;

    // 4. incremental runtime == batch run() for the same observations
    const rt = new CausalRuntime(new ScriptedSource(obs));
    rt.start();
    if (JSON.stringify(rt.snapshot().timeline) === JSON.stringify(timeline)) runtimeOk++;

    // 5. removing all observations -> empty timeline, network alive
    const removed = run(obs, { remove: obs.map((o) => o.id) });
    if (removed.timeline.length === 0 && removed.state.alive) removeOk++;
  }

  t.eq("determinism holds across all fuzzed scenarios", detOk, N);
  t.eq("trust stays within [0,1] across all scenarios", trustOk, N);
  t.eq("reconstruct(maxTick) == final state across all scenarios", reconOk, N);
  t.eq("runtime-incremental == batch across all scenarios", runtimeOk, N);
  t.eq("remove-all-observations -> nothing happens across all scenarios", removeOk, N);
};
