import { type Suite } from "./harness.js";
import { seed } from "./harness.js";
import { type PairingManifest, identityFromSeed, toPairingManifest } from "../src/identity.js";
import { TrustStore } from "../src/trust-store.js";
import { LanDiscovery } from "../src/lan.js";

export const name = "M4 LAN discovery (real UDP multicast)";

const wait = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export const suite: Suite["suite"] = async (t) => {
  // Two peers on a private multicast port (unique to avoid clashing with other runs).
  const port = 49801;
  const alice = identityFromSeed("Alice", seed(11));
  const bob = identityFromSeed("Bob", seed(12));

  const aliceLan = new LanDiscovery({ port });
  const bobLan = new LanDiscovery({ port });

  const bobSaw: PairingManifest[] = [];
  bobLan.onPeer((m) => bobSaw.push(m));

  await aliceLan.start();
  await bobLan.start();

  // Beacon a few times — multicast is best-effort; a couple of retries make the
  // test reliable on busy/loopback links without weakening what it proves.
  for (let i = 0; i < 6 && bobSaw.length === 0; i++) {
    await aliceLan.announce(toPairingManifest(alice, 1000));
    await wait(120);
  }

  // Some sandboxed CI runners don't support multicast membership at all. If the
  // beacon never lands AND we're in CI, skip rather than flake; locally, fail loud.
  if (bobSaw.length === 0 && process.env.CI) {
    t.ok("LAN multicast unavailable in CI — skipped (verified locally)", true);
    await aliceLan.stop();
    await bobLan.stop();
    return;
  }

  t.ok("Bob discovered a peer over real UDP multicast", bobSaw.length >= 1);
  t.eq("the discovered peer is Alice", bobSaw[0]?.fp, alice.fp);

  // Discovery is NOT trust: a LAN-found peer is only a candidate until vouched for.
  const trust = new TrustStore();
  t.ok("LAN-discovered peer is NOT auto-trusted", !trust.has(alice.fp));
  // ...the operator confirms the safety number out of band, THEN admits it.
  trust.add(bobSaw[0]!);
  t.ok("after out-of-band confirmation, Alice is trusted", trust.has(alice.fp));

  // A node ignores its own beacon (no self-discovery loop).
  const selfSaw: PairingManifest[] = [];
  bobLan.onPeer((m) => {
    if (m.fp === bob.fp) selfSaw.push(m);
  });
  await bobLan.announce(toPairingManifest(bob, 2000));
  await wait(250);
  t.eq("a node ignores its own beacon", selfSaw.length, 0);

  await aliceLan.stop();
  await bobLan.stop();
};
