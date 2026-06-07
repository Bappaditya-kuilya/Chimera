/**
 * crypto.ts — the only place that touches a crypto library.
 *
 * Everything else in Phase 0 speaks in terms of these primitives, so swapping
 * @noble for WebCrypto / a Tauri-native backend later is a one-file change.
 *
 * Purity note: key generation and randomBytes ARE non-deterministic — that is
 * correct and lives OUTSIDE the kernel's pure fold. ed25519 SIGNING, however, is
 * deterministic by spec (RFC 8032): same key + same message -> same signature.
 * That is what lets signed timelines stay reproducible. For reproducible tests,
 * use keypairFromSeed() instead of generateKeypair().
 */

import * as ed from "@noble/ed25519";
import { sha256 as nobleSha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";

// @noble/ed25519 v2 needs SHA-512 wired in for synchronous sign/verify.
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export type Bytes = Uint8Array;
export type Hex = string;

// ── encoding ──

export const bytesToHex = (b: Bytes): Hex => ed.etc.bytesToHex(b);
export const hexToBytes = (h: Hex): Bytes => ed.etc.hexToBytes(h);

const enc = new TextEncoder();
const dec = new TextDecoder();
export const utf8ToBytes = (s: string): Bytes => enc.encode(s);
export const bytesToUtf8 = (b: Bytes): string => dec.decode(b);

export const base64url = {
  encode(b: Bytes): string {
    let s = "";
    for (const byte of b) s += String.fromCharCode(byte);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  decode(s: string): Bytes {
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  },
};

// ── hashing ──

export const sha256 = (b: Bytes): Bytes => nobleSha256(b);
export const sha256Hex = (b: Bytes): Hex => bytesToHex(nobleSha256(b));

// ── keys & signatures ──

export type SecretKey = Bytes; // 32-byte ed25519 seed
export type PublicKey = Bytes; // 32-byte ed25519 public key
export type Signature = Bytes; // 64-byte ed25519 signature

export type Keypair = { secretKey: SecretKey; publicKey: PublicKey };

/** Fresh random identity. Non-deterministic — for real peers, not for tests. */
export function generateKeypair(): Keypair {
  const secretKey = ed.utils.randomPrivateKey();
  return { secretKey, publicKey: ed.getPublicKey(secretKey) };
}

/** Reproducible identity from a 32-byte seed. Use in tests/demos for stable fps. */
export function keypairFromSeed(seed: Bytes): Keypair {
  if (seed.length !== 32) throw new Error(`seed must be 32 bytes, got ${seed.length}`);
  return { secretKey: seed, publicKey: ed.getPublicKey(seed) };
}

export const sign = (message: Bytes, secretKey: SecretKey): Signature => ed.sign(message, secretKey);

export function verify(signature: Signature, message: Bytes, publicKey: PublicKey): boolean {
  try {
    return ed.verify(signature, message, publicKey);
  } catch {
    return false; // malformed signature/key bytes -> not valid, never throw
  }
}

// ── canonical serialization (deterministic signing target) ──
// Stable, key-sorted JSON so that signing/verifying a structured value is
// reproducible regardless of property insertion order or platform.

export function canonicalJSON(value: unknown): string {
  return JSON.stringify(sortDeep(value));
}

function sortDeep(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v as Record<string, unknown>).sort()) {
      out[k] = sortDeep((v as Record<string, unknown>)[k]);
    }
    return out;
  }
  return v;
}
