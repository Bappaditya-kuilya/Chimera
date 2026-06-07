/**
 * identity.ts — cryptographic peer identity + offline QR pairing.
 *
 * Why this exists (the Sybil-resistance argument):
 *   The kernel's Trust Matrix is meaningless if identities are free. Anyone could
 *   mint a thousand nodes and vote trust up/down. So an identity is an ed25519
 *   keypair, and a peer is only ever trusted after its FINGERPRINT is verified
 *   OUT OF BAND (you read the safety-number off a screen / scan a QR in person).
 *   Generating keys is cheap; getting a human to vouch for your fingerprint is not.
 *   That asymmetry is the whole defence.
 *
 * fingerprint = sha256(publicKey). It binds a short, human-comparable string to a
 * 32-byte key. verifyPairing() re-derives it, so a tampered manifest (swapped key,
 * same claimed fp) is rejected before the peer ever enters the web of trust.
 */

import {
  type Hex,
  type Keypair,
  type PublicKey,
  base64url,
  bytesToHex,
  canonicalJSON,
  generateKeypair,
  hexToBytes,
  keypairFromSeed,
  sha256Hex,
  utf8ToBytes,
} from "./crypto.js";

export type Fingerprint = Hex; // full sha256(publicKey), 64 hex chars

/** Stable identifier for a public key: sha256(pubkey), hex. */
export function fingerprint(publicKey: PublicKey): Fingerprint {
  return sha256Hex(publicKey);
}

/**
 * Human-verifiable "safety number" — the first `groups`*4 hex chars in spaced
 * blocks, e.g. "b62e 867f a2f3 afe1". This is what two people read aloud or
 * eyeball side-by-side to confirm they paired the right key. Truncation is fine:
 * the full fingerprint is still checked in verifyPairing(); the short form is a
 * UX affordance, not the security boundary.
 */
export function safetyNumber(fp: Fingerprint, groups = 8): string {
  const re = new RegExp(`.{1,4}`, "g");
  return (fp.slice(0, groups * 4).match(re) ?? []).join(" ");
}

// ── local identity (holds secret material) ──

export type Identity = {
  nick: string;
  fp: Fingerprint;
  keypair: Keypair;
};

export function createIdentity(nick: string): Identity {
  const keypair = generateKeypair();
  return { nick, fp: fingerprint(keypair.publicKey), keypair };
}

/** Reproducible identity from a 32-byte seed — for tests/demos with stable fps. */
export function identityFromSeed(nick: string, seed: Uint8Array): Identity {
  const keypair = keypairFromSeed(seed);
  return { nick, fp: fingerprint(keypair.publicKey), keypair };
}

// ── pairing manifest (public-only; this is what crosses the QR) ──

export type PairingManifest = {
  v: 1;
  fp: Fingerprint; // claimed fingerprint (re-derived & checked on receipt)
  pubkey: Hex; // 32-byte ed25519 public key, hex
  nick: string; // human label, advisory only
  ts: number; // issuance time, caller-supplied (NOT generated here — keep lib pure)
};

const PAIR_PREFIX = "chimera:pair:1:";

/**
 * Public manifest for an identity. `ts` is passed IN (issuance time) rather than
 * read from the clock, so this module stays deterministic and testable.
 */
export function toPairingManifest(identity: Identity, ts: number): PairingManifest {
  return {
    v: 1,
    fp: identity.fp,
    pubkey: bytesToHex(identity.keypair.publicKey),
    nick: identity.nick,
    ts,
  };
}

/** Serialize to a compact, QR-encodable string (also paste-able over any channel). */
export function encodePairing(m: PairingManifest): string {
  return PAIR_PREFIX + base64url.encode(utf8ToBytes(canonicalJSON(m)));
}

/** Parse a pairing string back into a manifest. Throws on malformed input. */
export function decodePairing(s: string): PairingManifest {
  if (!s.startsWith(PAIR_PREFIX)) throw new Error("not a chimera pairing string");
  const json = new TextDecoder().decode(base64url.decode(s.slice(PAIR_PREFIX.length)));
  const m = JSON.parse(json) as PairingManifest;
  if (m.v !== 1 || typeof m.fp !== "string" || typeof m.pubkey !== "string") {
    throw new Error("malformed pairing manifest");
  }
  return m;
}

/**
 * The integrity gate: the claimed fingerprint MUST equal sha256(embedded pubkey).
 * A manifest that swaps in a different key while keeping the victim's fp fails
 * here — so a forged manifest can never impersonate a fingerprint a human trusts.
 */
export function verifyPairing(m: PairingManifest): boolean {
  try {
    return m.fp === fingerprint(hexToBytes(m.pubkey));
  } catch {
    return false;
  }
}
