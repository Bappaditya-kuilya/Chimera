/**
 * vault.ts — the Genome Vault: encrypted, on-disk persistence so a node survives
 * restarts without leaking its identity.
 *
 * What's secret vs public:
 *   - The identity SECRET KEY is the only thing that must never leak. It is
 *     encrypted at rest with a passphrase: scrypt(passphrase) -> AES-256-GCM.
 *   - Everything else (the public keys / fingerprints of peers, the signed
 *     observation log) is already public by design, so it is stored in clear
 *     inside the same file — but the file's integrity still rides on the GCM tag
 *     of the secret section being valid before we trust any of it.
 *
 * Node-only (node:crypto + fs) — never imported by the browser bundle. Zero new
 * dependencies: AES-256-GCM and scrypt come from node:crypto.
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { type Identity, type PairingManifest, identityFromSeed } from "./identity.js";
import { type SignedObservation } from "./ingest.js";
import { TrustStore } from "./trust-store.js";
import { bytesToHex } from "./crypto.js";

const VERSION = 1 as const;
const KDF_N = 1 << 15; // scrypt cost (sane default; tune up for production)
const KDF_MAXMEM = 96 * 1024 * 1024; // headroom above scrypt's ~128*N*r bytes (default cap is too low)

type Sealed = { salt: string; iv: string; tag: string; ct: string };

function seal(plain: Uint8Array, passphrase: string): Sealed {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(passphrase, salt, 32, { N: KDF_N, maxmem: KDF_MAXMEM });
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
  return {
    salt: salt.toString("hex"),
    iv: iv.toString("hex"),
    tag: cipher.getAuthTag().toString("hex"),
    ct: ct.toString("hex"),
  };
}

function open(s: Sealed, passphrase: string): Uint8Array {
  const key = scryptSync(passphrase, Buffer.from(s.salt, "hex"), 32, { N: KDF_N, maxmem: KDF_MAXMEM });
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(s.iv, "hex"));
  decipher.setAuthTag(Buffer.from(s.tag, "hex"));
  // throws "Unsupported state or unable to authenticate data" on wrong passphrase/tamper
  return Buffer.concat([decipher.update(Buffer.from(s.ct, "hex")), decipher.final()]);
}

export type VaultFile = {
  v: typeof VERSION;
  nick: string;
  fp: string;
  secret: Sealed; // the encrypted 32-byte ed25519 seed
  peers: PairingManifest[]; // public web of trust
  log: SignedObservation[]; // public signed observation history
};

export type VaultContents = {
  identity: Identity;
  trust: TrustStore;
  log: SignedObservation[];
};

/** Serialize identity (secret encrypted) + trust + log to an on-disk vault file. */
export function saveVault(
  path: string,
  contents: VaultContents,
  passphrase: string,
): void {
  if (!passphrase) throw new Error("a passphrase is required to seal the vault");
  const file: VaultFile = {
    v: VERSION,
    nick: contents.identity.nick,
    fp: contents.identity.fp,
    secret: seal(contents.identity.keypair.secretKey, passphrase),
    peers: contents.trust.list().map((p) => ({
      v: 1,
      fp: p.fp,
      pubkey: bytesToHex(p.publicKey),
      nick: p.nick,
      ts: p.pairedAt,
    })),
    log: contents.log,
  };
  writeFileSync(path, JSON.stringify(file, null, 2));
}

/** Load and decrypt a vault. Throws on wrong passphrase or a tampered file. */
export function loadVault(path: string, passphrase: string): VaultContents {
  const file = JSON.parse(readFileSync(path, "utf8")) as VaultFile;
  if (file.v !== VERSION) throw new Error(`unsupported vault version ${file.v}`);

  const seed = open(file.secret, passphrase); // throws on bad passphrase
  const identity = identityFromSeed(file.nick, seed);
  if (identity.fp !== file.fp) throw new Error("vault integrity error: fingerprint mismatch");

  const trust = new TrustStore();
  for (const m of file.peers) trust.add(m); // re-verifies each manifest on the way in

  return { identity, trust, log: file.log };
}
