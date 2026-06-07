import { type Suite } from "./harness.js";
import { seed } from "./harness.js";
import { type PairingManifest, identityFromSeed, toPairingManifest } from "../src/identity.js";
import { TrustStore } from "../src/trust-store.js";
import { BleDiscovery, OutOfBandChannel, QRDiscovery } from "../src/discovery.js";

export const name = "discovery (QR transport + stubs)";

export const suite: Suite["suite"] = (t) => {
  const channel = new OutOfBandChannel();
  const alpha = identityFromSeed("Alpha", seed(1)); // the local node, "scanning"
  const bravo = identityFromSeed("Bravo", seed(2)); // the peer presenting a QR

  const trust = new TrustStore();
  const seen: PairingManifest[] = [];

  const disco = new QRDiscovery(channel);
  disco.start();
  disco.onPeer((m) => {
    seen.push(m);
    trust.add(m); // operator vouches after eyeballing the safety number
  });

  // Bravo's device presents its QR onto the shared out-of-band channel.
  new QRDiscovery(channel).announce(toPairingManifest(bravo, 200));

  t.eq("one peer discovered", seen.length, 1);
  t.eq("discovered the right fingerprint", seen[0]?.fp, bravo.fp);
  t.ok("discovered peer entered the web of trust", trust.has(bravo.fp));

  // a hostile channel: random noise and a tampered manifest must be ignored
  channel.present("random non-pairing junk");
  const tampered = "chimera:pair:1:" + "!!!!notbase64!!!!";
  channel.present(tampered);
  t.eq("noise + malformed ignored", seen.length, 1);

  // the QR transport delivers UNVERIFIED candidates only after integrity passes;
  // a key-swapped manifest (fp != hash(key)) is dropped by the transport guard
  const swapped = { ...toPairingManifest(alpha, 1), pubkey: toPairingManifest(bravo, 1).pubkey };
  channel.present("chimera:pair:1:" + base64urlOf(swapped));
  t.eq("integrity-failing manifest dropped", seen.length, 1);

  // automatic transports that need native hardware are honest stubs, not silent no-ops
  t.throws("ble stub throws on start", () => new BleDiscovery().start());
};

// local helper to craft a raw (possibly bad) pairing payload for the negative test
function base64urlOf(m: unknown): string {
  const json = JSON.stringify(m);
  let s = "";
  for (const b of new TextEncoder().encode(json)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
