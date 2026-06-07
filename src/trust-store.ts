/**
 * trust-store.ts — the web of trust.
 *
 * A peer enters the store ONLY via add(manifest), and ONLY if:
 *   1. the manifest's fingerprint matches its embedded public key (verifyPairing),
 *   2. you, the operator, performed the out-of-band check (you scanned/compared the
 *      safety number in person). add() assumes step 2 already happened — calling it
 *      IS the act of vouching.
 *
 * This is the Sybil boundary. The ingest layer (ingest.ts) will accept an
 * observation only if its author fingerprint is already in here. Unknown keys —
 * however many an attacker mints — author nothing.
 */

import { type Fingerprint, type PairingManifest, verifyPairing } from "./identity.js";
import { type PublicKey, hexToBytes } from "./crypto.js";

export type Peer = {
  fp: Fingerprint;
  publicKey: PublicKey;
  nick: string;
  pairedAt: number; // the manifest ts at the moment of pairing
};

export class TrustStore {
  private peers = new Map<Fingerprint, Peer>();

  /**
   * Vouch for a peer from its pairing manifest. Returns the stored Peer.
   * Throws if the manifest fails its integrity check (fp != hash(pubkey)) — a
   * tampered manifest never silently enters the web of trust.
   */
  add(manifest: PairingManifest): Peer {
    if (!verifyPairing(manifest)) {
      throw new Error(`refusing to trust ${manifest.nick}: fingerprint does not match public key`);
    }
    const peer: Peer = {
      fp: manifest.fp,
      publicKey: hexToBytes(manifest.pubkey),
      nick: manifest.nick,
      pairedAt: manifest.ts,
    };
    this.peers.set(peer.fp, peer);
    return peer;
  }

  has(fp: Fingerprint): boolean {
    return this.peers.has(fp);
  }

  get(fp: Fingerprint): Peer | undefined {
    return this.peers.get(fp);
  }

  /** Public key for a known fingerprint, or undefined if the peer is untrusted. */
  publicKeyOf(fp: Fingerprint): PublicKey | undefined {
    return this.peers.get(fp)?.publicKey;
  }

  /** Revoke trust in a peer (e.g. key compromise). Returns true if it was present. */
  remove(fp: Fingerprint): boolean {
    return this.peers.delete(fp);
  }

  list(): Peer[] {
    return [...this.peers.values()].sort((a, b) => a.fp.localeCompare(b.fp));
  }

  get size(): number {
    return this.peers.size;
  }
}
