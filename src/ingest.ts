/**
 * ingest.ts — the authentication boundary between the world and the pure kernel.
 *
 *      signed observations  ──►  [ ingest: verify against web of trust ]  ──►  Observation[]  ──►  run()
 *                                         │
 *                                  rejected (Sybil / forged / tampered)
 *
 * The kernel (kernel.ts) never sees an unauthenticated fact. decide()/apply()
 * stay pure; all crypto happens HERE, once, at the edge. By the time an
 * Observation is folded, we know exactly which trusted peer asserted it.
 *
 * What gets rejected, and why it matters:
 *   - unknown-author  -> Sybil resistance: a freshly minted key is worthless until
 *                        someone vouches for it out of band (TrustStore.add).
 *   - bad-signature   -> forgery resistance: you cannot put words in a peer's mouth.
 *   - tampered        -> integrity: flipping a byte of the observation breaks the sig.
 */

import { type Observation } from "./kernel.js";
import { type Fingerprint } from "./identity.js";
import { type Identity } from "./identity.js";
import { TrustStore } from "./trust-store.js";
import {
  type Signature,
  bytesToHex,
  canonicalJSON,
  hexToBytes,
  sign,
  utf8ToBytes,
  verify,
} from "./crypto.js";

/** An observation as it actually travels the mesh: the fact + who signed it. */
export type SignedObservation = {
  obs: Observation;
  author: Fingerprint; // claimed author (must be a known peer to be accepted)
  sig: string; // hex ed25519 signature over canonical(obs) by the author's key
};

/** Exactly what gets signed/verified — the canonical bytes of the observation. */
function signingBytes(obs: Observation): Uint8Array {
  return utf8ToBytes(canonicalJSON(obs));
}

/** A peer signs an observation it witnessed. */
export function signObservation(obs: Observation, identity: Identity): SignedObservation {
  const sig = sign(signingBytes(obs), identity.keypair.secretKey);
  return { obs, author: identity.fp, sig: bytesToHex(sig) };
}

export type RejectReason = "unknown-author" | "bad-signature" | "malformed";

export type IngestResult = {
  accepted: Observation[];
  rejected: Array<{ signed: SignedObservation; reason: RejectReason }>;
};

/**
 * Verify a batch of signed observations against the web of trust.
 * Only authenticated facts come out the `accepted` side — feed those to run().
 */
export function ingest(signed: SignedObservation[], trust: TrustStore): IngestResult {
  const accepted: Observation[] = [];
  const rejected: IngestResult["rejected"] = [];

  for (const s of signed) {
    const reason = checkOne(s, trust);
    if (reason) rejected.push({ signed: s, reason });
    else accepted.push(s.obs);
  }
  return { accepted, rejected };
}

function checkOne(s: SignedObservation, trust: TrustStore): RejectReason | null {
  const pubkey = trust.publicKeyOf(s.author);
  if (!pubkey) return "unknown-author"; // Sybil gate: author was never vouched for

  let sig: Signature;
  try {
    sig = hexToBytes(s.sig);
  } catch {
    return "malformed";
  }

  // Re-derive the exact bytes the author should have signed and check them. Any
  // tampering with obs (rate, node, tick, kind, id) changes these bytes -> fails.
  if (!verify(sig, signingBytes(s.obs), pubkey)) return "bad-signature";

  return null;
}
