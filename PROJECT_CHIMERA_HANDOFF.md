# Project Chimera — Session Handoff

> A self-contained summary of work so far. Drop this into a new chat to continue
> instantly. Everything below is **done and verified** unless marked otherwise.

---

## 1. What Chimera actually is (the pivot)

It started as an "Autonomous Cyber Survival Network" (offline mesh + threat
detection + biological UI). After analysis, the **real invention** was isolated:

```
Event Sourcing  +  Explainable Decisions  +  Counterfactual Replay
```

Everything else (WebRTC mesh, Three.js shaders, genome vault) is **replaceable
presentation**. The core answers a question almost no security tool can:

> "Can you prove that your intervention mattered?"

Repositioning: **not** an offline cyber mesh → a **Causal Security Runtime**.
The mesh is just one *source of observations*; later you can plug in k8s logs,
firewalls, IoT, agents, etc. Same engine.

### Locked core (non-negotiable)
- Event Store · Decision Engine · Replay Engine · Counterfactual Engine

### Replaceable
- Transport: WebRTC / BLE / LoRa / WiFi-Direct

### Optional (great differentiators, not fundamental)
- Living Mesh UI · Genome Vault · biological visuals

---

## 2. The key architectural insight (why the old design was broken)

The original spec stored **decisions as primary events** in a flat log. That makes
counterfactual replay **fake**: delete `Quarantine`, replay, and the engine just
**re-derives** `Quarantine` → timelines never diverge.

**The fix — two event classes:**

| Class | Examples | Property |
|---|---|---|
| **Observation** (exogenous) | PacketFlood, HeartbeatLost, SignatureInvalid, RouteFailure | Ground-truth facts. Immutable. The *only* primary input. You may **remove** these. |
| **Decision** (endogenous) | TrustDrop, Quarantine, Spread, Recovery, Collapse | Derived consequences. Never authored by hand. You **intervene** on these (`do()`). |

**Two distinct counterfactual questions:**
- `remove(observationId)` → "what if this **input** never happened?"
- `do(decision = value)` → "what if we had **decided** differently?" (Pearl's do-operator)

Naive `delete + replay` re-derives the decision. `do()` overrides the **policy**
while holding inputs constant → the future genuinely changes.

**The load-bearing law:**
```
state = fold(decide over observations)      // and decide() is PURE
```
No `Date.now`, no `Math.random`, logical ticks, derived ids. This purity is the
*only* reason replay and counterfactuals are reproducible.

**`causedBy` — one field, four jobs:** explainability · replay · counterfactual ·
(future) cause→effect visualization — all from a single causal DAG.

---

## 3. What's been built — the kernel (DONE, all checks pass)

A single TypeScript file proving the whole idea, with **no mesh, no UI, no
persistence**. Runs with zero build step via `tsx`.

**Location:** `~/chimera-kernel/`
- `observations.ts` — the kernel (~290 lines)
- `package.json` — `"type": "module"`, `npm start`

**Run it:**
```bash
cd ~/chimera-kernel && npx tsx observations.ts
```

### Public surface
```ts
// types: Observation | Decision | Event | State | Intervention | Verdict
apply(state, event)                         // pure single fold step
decide(state, obs|null, iv, tick)           // THE policy — pure, deterministic
run(observations, iv?)                      // the engine -> { timeline, state }
reconstruct(timeline, t)                    // state as-of tick t (replay)
counterfactual(observations, iv)            // the do()-operator entry point
explain(timeline, decisionId)               // walk causedBy -> root observations
diff(a, b)                                  // where two timelines diverge
verdict(state)                              // "SURVIVED" | "COLLAPSED"
```

### Scenario it proves
Star topology centred on hub **Bravo**. Identical input: two `PacketFlood`s on Bravo.

| Run | Timeline | Verdict |
|---|---|---|
| **Actual** | flood → trust-- → flood → trust-- → **QUARANTINE** → recovery | **SURVIVED** |
| **`do(Quarantine:Bravo=false)`** | flood → trust-- → flood → trust-- → **SPREAD×3** → **COLLAPSE** | **COLLAPSED** |

Shared byte-identical prefix; diverges at **t2** exactly where policy is overridden.
The net collapses in the counterfactual because Quarantine is *observation-driven*
(you isolate what you **detect** being attacked) — the silent spread generates no
observation, so the un-quarantined hub infects every neighbour → collapse.

### Verification output (all PASS)
```
✓ actual verdict: SURVIVED
✓ counterfactual verdict: COLLAPSED
✓ negative control (force quarantine=true): SURVIVED   # forcing the real decision changes nothing
✓ determinism (two runs byte-identical): true
✓ remove all observations -> nothing happens: SURVIVED # "what if the attack never came?"
✓ explain(Quarantine:Bravo@t2) -> PacketFlood@t1, PacketFlood@t2
```

---

## 4. Open design decisions still to make (for a "real product")

These were flagged but **not yet built** — they matter because the goal is a real
hostile-environment product, not just a demo:

1. **Live vs Demonstration mode split** — real defense must only act on *observable*
   signals; scripted attacks/counterfactuals must be clearly labeled simulation, or
   the product gives false confidence. (Same event store, different event source.)
2. **Phase 0: Threat Model + Identity + Discovery** (missing from the original roadmap)
   - Offline **peer discovery**: WebRTC/PeerJS needs a signaling server (central, censorable). Need mDNS / BLE / QR-pairing / LoRa for true "internet-independent."
   - **Cryptographic identity + Sybil resistance** — the Trust Matrix is meaningless if identities are free. Out-of-band QR fingerprint exchange = web-of-trust.
3. **Genome inputs must be physically real** — browsers can't see raw packets over
   WebRTC. Use app-layer signals (message rate, signature failures, malformed payloads, route flapping) for the *live* path; wire-level entropy belongs to demo mode only.
4. **Browser-only may not hold** for a real product (no background BLE, no raw radio).
   Consider Tauri / React Native shell; keep PWA for the demo.

---

## 5. Suggested next steps (all are wrappers around the proven kernel)

1. **Harden the kernel** — richer topology, trust *decay over time*, multi-stage
   attacks, full state machine (HEALTHY/ALERT/EXPOSED/ISOLATED/SCARRED), unit tests.
2. **Make `Observation` an interface** — plug a real source (WebRTC mesh, later
   k8s/firewall logs). This realizes the "Causal Security Runtime" pivot.
3. **Visualize** — Memory River / Living Mesh reading straight off `timeline` +
   `causedBy`, with `reconstruct(t)` as the scrubber.

---

## 6. Quick-start prompt for the new session

> "I'm building Project Chimera, a Causal Security Runtime. The kernel is already
> built and proven in `~/chimera-kernel/observations.ts` (run `npx tsx
> observations.ts` — all checks pass). It proves SURVIVED vs COLLAPSED from
> identical observations via `do(quarantine=false)`. Read PROJECT_CHIMERA_HANDOFF.md
> for full context. I want to work on **[harden the kernel / add real observation
> source / build the visualization / Phase 0 identity+discovery]** next."
