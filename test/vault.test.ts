import { type Suite } from "./harness.js";
import { seed } from "./harness.js";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readFileSync, rmSync } from "node:fs";
import { type Observation, makeId } from "../src/kernel.js";
import { identityFromSeed, toPairingManifest } from "../src/identity.js";
import { TrustStore } from "../src/trust-store.js";
import { signObservation } from "../src/ingest.js";
import { bytesToHex } from "../src/crypto.js";
import { loadVault, saveVault } from "../src/vault.js";

export const name = "M7 Genome Vault (encrypted persistence)";

export const suite: Suite["suite"] = (t) => {
  const me = identityFromSeed("Bravo", seed(2));
  const peer = identityFromSeed("Alpha", seed(1));
  const trust = new TrustStore();
  trust.add(toPairingManifest(peer, 100));

  const obs: Observation = { id: makeId("PacketFlood", "Bravo", 1), t: 1, kind: "PacketFlood", node: "Bravo", rate: 8000 };
  const log = [signObservation(obs, me)];

  const path = join(tmpdir(), `chimera-vault-${bytesToHex(seed(7)).slice(0, 8)}.json`);
  const pass = "correct horse battery staple";

  try {
    saveVault(path, { identity: me, trust, log }, pass);

    // round-trip: identity, trust, and log all survive
    const back = loadVault(path, pass);
    t.eq("identity fingerprint round-trips", back.identity.fp, me.fp);
    t.eq("secret key round-trips", bytesToHex(back.identity.keypair.secretKey), bytesToHex(me.keypair.secretKey));
    t.eq("trusted peer round-trips", back.trust.has(peer.fp), true);
    t.eq("observation log round-trips", back.log.length, 1);

    // a reloaded identity can still sign verifiably (the key really survived)
    const reSigned = signObservation(obs, back.identity);
    t.eq("reloaded identity produces the same signature", reSigned.sig, log[0]!.sig);

    // wrong passphrase fails (AES-GCM auth tag) — never silently returns garbage
    t.throws("wrong passphrase is rejected", () => loadVault(path, "wrong passphrase"));

    // the secret is NOT stored in clear
    const raw = readFileSync(path, "utf8");
    t.eq("secret key is not present in plaintext", raw.includes(bytesToHex(me.keypair.secretKey)), false);
  } finally {
    rmSync(path, { force: true });
  }
};
