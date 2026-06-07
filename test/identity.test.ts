import { type Suite } from "./harness.js";
import { seed } from "./harness.js";
import {
  decodePairing,
  encodePairing,
  fingerprint,
  identityFromSeed,
  safetyNumber,
  toPairingManifest,
  verifyPairing,
} from "../src/identity.js";

export const name = "identity & QR pairing";

export const suite: Suite["suite"] = (t) => {
  const alpha = identityFromSeed("Alpha", seed(1));

  // fingerprint is deterministic and bound to the key
  t.eq("fingerprint is sha256(pubkey)", alpha.fp, fingerprint(alpha.keypair.publicKey));
  t.eq("fingerprint length 64 hex", alpha.fp.length, 64);
  t.eq("same seed -> same fingerprint", identityFromSeed("X", seed(1)).fp, alpha.fp);
  t.ok("different seed -> different fingerprint", identityFromSeed("Y", seed(2)).fp !== alpha.fp);

  // safety number is a readable prefix of the fingerprint
  t.ok("safety number is fp prefix", alpha.fp.startsWith(safetyNumber(alpha.fp).replace(/ /g, "")));

  // pairing manifest round-trips through the QR string unchanged
  const m = toPairingManifest(alpha, 1717000000);
  const qr = encodePairing(m);
  t.ok("qr string is chimera pairing", qr.startsWith("chimera:pair:1:"));
  t.eq("decode(encode(m)) == m", decodePairing(qr), m);

  // integrity: a valid manifest verifies; a key-swapped one does not
  t.ok("genuine manifest verifies", verifyPairing(m));
  const bravo = identityFromSeed("Bravo", seed(2));
  const swapped = { ...m, pubkey: toPairingManifest(bravo, 1).pubkey }; // keep Alpha's fp, Bravo's key
  t.ok("key-swapped manifest rejected", !verifyPairing(swapped));

  // malformed input is rejected loudly, not silently coerced
  t.throws("decode garbage throws", () => decodePairing("not-a-pairing-string"));
};
