/**
 * lan.ts — a REAL discovery transport: zero-config LAN over UDP multicast.
 *
 * This is the working realization of the mDNS-style stub in discovery.ts. It needs
 * no signaling server and no internet — peers beacon their pairing manifest to a
 * local multicast group and hear each other directly on the link. (Node-only: it
 * uses node:dgram. The browser-safe transports stay in discovery.ts.)
 *
 * SECURITY — the link is hostile (this is the whole point of LAN being only
 * *discovery*, never *trust*):
 *   - Sybil over multicast is trivial: anyone can beacon any manifest.
 *   - So LanDiscovery surfaces CANDIDATES only. It integrity-checks each manifest
 *     (verifyPairing: fp == hash(pubkey)) and drops the rest, but it NEVER vouches.
 *   - Admission into the web of trust still requires the out-of-band safety-number
 *     confirmation from M1 (TrustStore.add). Discovery finds peers; humans trust them.
 */

import dgram from "node:dgram";
import { type PairingManifest, decodePairing, encodePairing, verifyPairing } from "./identity.js";
import { type DiscoverySource, type PeerHandler } from "./discovery.js";

export type LanOptions = {
  group?: string; // multicast group (local-scope by default)
  port?: number;
};

const DEFAULTS = { group: "239.255.41.42", port: 49737 };

export class LanDiscovery implements DiscoverySource {
  readonly name = "lan-udp-multicast";
  private socket: dgram.Socket | null = null;
  private handlers: PeerHandler[] = [];
  private selfFp: string | null = null;
  private readonly group: string;
  private readonly port: number;

  constructor(opts: LanOptions = {}) {
    this.group = opts.group ?? DEFAULTS.group;
    this.port = opts.port ?? DEFAULTS.port;
  }

  async start(): Promise<void> {
    if (this.socket) return;
    const sock = dgram.createSocket({ type: "udp4", reuseAddr: true });
    this.socket = sock;

    sock.on("message", (buf) => {
      let m: PairingManifest;
      try {
        m = decodePairing(buf.toString());
      } catch {
        return; // not a pairing beacon — ignore link noise
      }
      if (!verifyPairing(m)) return; // integrity gate: fp must match embedded key
      if (m.fp === this.selfFp) return; // ignore our own beacon echoed back
      for (const h of this.handlers) h(m, this.name);
    });

    await new Promise<void>((resolve, reject) => {
      sock.once("error", reject);
      sock.bind(this.port, () => {
        try {
          sock.addMembership(this.group);
          sock.setMulticastTTL(1); // stay on the local link; never routed off-LAN
        } catch {
          /* membership may fail on hosts without multicast; unicast send still works */
        }
        resolve();
      });
    });
  }

  /** Beacon our pairing manifest to the LAN. Remembers our fp to filter the echo. */
  async announce(self: PairingManifest): Promise<void> {
    if (!this.socket) throw new Error("LanDiscovery.start() must run before announce()");
    this.selfFp = self.fp;
    const payload = Buffer.from(encodePairing(self));
    await new Promise<void>((resolve, reject) => {
      this.socket!.send(payload, this.port, this.group, (err) => (err ? reject(err) : resolve()));
    });
  }

  onPeer(handler: PeerHandler): void {
    this.handlers.push(handler);
  }

  async stop(): Promise<void> {
    this.socket?.close();
    this.socket = null;
  }
}
