# Chimera — Causal Security Runtime

A deterministic causal engine for security decisions. From **identical observations**,
it proves that the system's policy `SURVIVED` while a counterfactual
`do(quarantine = false)` `COLLAPSED` — answering the question almost no security tool
can: *"Can you prove that your intervention mattered?"*

See `PROJECT_CHIMERA_HANDOFF.md` for the full thesis and design rationale.

```bash
npm install        # local node_modules only — nothing global
npm start          # the kernel proof  (observations.ts)
npm test           # full test suite (42 checks)
npm run demo       # Phase 0 end-to-end story
npm run multistage # M2: lifecycle + trust-heal + topology-agnostic divergence
npm run live       # M3: live telemetry -> runtime, plus a branded SIMULATION
npm run lan        # M4: two peers discover each other over real UDP multicast
npm run typecheck  # strict tsc, no emit
```

## Layout

```
observations.ts        canonical kernel proof (unchanged behaviour, now imports src/kernel)
src/
  kernel.ts            the proven PURE causal engine: fold / run / counterfactual / explain / reconstruct
                       + M2: configurable Topology/Params, trust heal-over-time, node lifecycle
  crypto.ts            ed25519 + sha256/512 + canonical JSON — the ONLY crypto-lib touchpoint
  identity.ts          keypairs, fingerprint = sha256(pubkey), safety numbers, QR pairing manifests
  trust-store.ts       the web of trust — the Sybil boundary
  ingest.ts            sign + verify observations; the authentication edge before the pure fold
  discovery.ts         DiscoverySource interface + QR/out-of-band impl (+ BLE/LoRa stubs)
  lan.ts               LanDiscovery — REAL zero-config LAN transport over UDP multicast (Node)
  source.ts            ObservationSource interface + Mode (live|demo); Scripted & LiveSignal adapters
  runtime.ts           CausalRuntime: incremental live folding + SIMULATION-branded counterfactuals
  index.ts             public barrel
test/                  zero-dependency suites (kernel-style PASS/FAIL), run via npm test
demo/phase0.ts         narrative: identities -> offline pairing -> Sybil/forgery rejected -> SURVIVED vs COLLAPSED
demo/multistage.ts     M2: a node's HEALTHY->ALERT->EXPOSED->ISOLATED->SCARRED lifecycle + a 2nd topology
demo/live.ts           M3: app-layer telemetry -> live runtime; counterfactual as a branded SIMULATION
demo/lan.ts            M4: two peers discover each other over real UDP multicast; trust still gated
```

## Milestones

- **M1 — kernel + Phase 0** ✅ identity, Sybil resistance, signed-observation ingest, offline QR pairing.
- **M2 — hardened kernel** ✅ configurable topology/params, trust heal-over-time, node lifecycle.
- **M3 — live runtime + mode split** ✅ ObservationSource, CausalRuntime, SIMULATION branding.
- **M4 — real LAN transport** ✅ LanDiscovery over UDP multicast; discovery stays distinct from trust.
- M5 — visualization (Memory River + causal DAG, time-scrubber, actual-vs-counterfactual) *(next)*

## M3 — live observation source + Live/Demonstration split

The "Causal Security Runtime" pivot, realized: the kernel doesn't care where
observations come from, so a single `ObservationSource` interface puts any source
in front of it.

- **`ObservationSource` + `Mode`** — every source declares `live` or `demo`.
  - `ScriptedSource` (demo): replays a canned scenario — the attack is *authored*.
  - `LiveSignalSource` (live): maps real **app-layer telemetry** (message rate, bad
    signatures, malformed payloads, route flaps, quiet intervals) into observations.
    (Per the handoff: a browser/Node process can't see raw packets, so the live path
    uses app-layer signals.)
- **`CausalRuntime`** — folds observations incrementally via the same pure `fold()`
  the batch engine uses (proven equivalent in tests), keeping authoritative
  timeline + state and a replayable observation log.
- **The mode split (safety property):** `simulate(iv)` — the do()-operator — always
  returns a result **branded `SIMULATION`** and **never mutates live state**. A
  scripted attack or counterfactual can never be mistaken for real defense, which is
  what would otherwise give dangerous false confidence.



## M2 — hardening

All additive and **backward-compatible**: the original proof is byte-identical, because
the defaults reproduce the original constants.

- **Topology & tuning are data** (`Config { topology, params }`, default `STAR` +
  `DEFAULT_PARAMS`). The same engine runs a star, a line, a k8s cluster — the
  counterfactual divergence (SURVIVED vs COLLAPSED) holds on any graph.
- **Trust heals over quiet logical time**: a `Heartbeat` observation on a behaving
  node emits a `TrustRegen` decision, regenerating trust toward baseline —
  deterministic, with causal provenance. (Absent from old scenarios, so they're unchanged.)
- **Node lifecycle** (a pure projection, never stored):
  `HEALTHY → ALERT → EXPOSED → ISOLATED → SCARRED`, via `nodeState()` and the
  `lifecycle()` transition trace.



## Phase 0 — cryptographic identity, Sybil resistance, offline discovery

The kernel's Trust Matrix is meaningless if identities are free. Phase 0 makes them
expensive to *trust* (not to mint):

- **Identity** = an ed25519 keypair. `fingerprint = sha256(publicKey)`, shown as a
  human-comparable **safety number**.
- **Offline pairing** over a QR / out-of-band channel — *no signaling server*. A peer
  is admitted only after (1) its manifest's fingerprint matches its embedded key
  (`verifyPairing`) and (2) you vouch for it out of band (`TrustStore.add`).
- **Authentication boundary** (`ingest`): every observation arrives **signed**. The
  gate rejects:
  - `unknown-author` → **Sybil resistance** (a fresh key is worthless until vouched for),
  - `bad-signature` → **forgery + tamper resistance** (you can't put words in a peer's mouth, and flipping a byte breaks the signature).
- The **kernel stays pure**: all crypto happens once, at the edge. By the time an
  observation is folded, it is already authenticated — so replay/counterfactual
  determinism is preserved (proven by `npm test`).

```
signed observations ──► [ ingest: verify vs web of trust ] ──► Observation[] ──► run()
                               │
                        rejected (Sybil / forged / tampered)
```

### Discovery transports

`DiscoverySource` is one interface; the channel is assumed **hostile** — it only
delivers *candidate* manifests, never trust. Implemented now: **QR / out-of-band**.
Stubbed behind the same interface (throw on `start()`, never silent no-ops):
`MdnsDiscovery` (LAN), `BleDiscovery` (phone-to-phone, needs native), `LoRaDiscovery`
(long-range radio).
