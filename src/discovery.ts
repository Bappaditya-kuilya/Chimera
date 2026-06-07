/**
 * discovery.ts — how peers FIND each other without a central server.
 *
 * The handoff's Phase-0 worry: WebRTC/PeerJS needs a signaling server, which is
 * central and censorable — not "internet-independent." So discovery is abstracted
 * behind one interface, and the only transport implemented now is the one that
 * needs zero infrastructure and zero trust in the channel: OUT-OF-BAND QR pairing.
 *
 * Security stance: the discovery channel is assumed HOSTILE. Anything it delivers
 * is just a candidate PairingManifest. verifyPairing() (integrity) + an operator's
 * out-of-band eyeball of the safety number (authenticity) are what actually admit a
 * peer — never the transport. That is why an in-person QR and an untrusted mDNS
 * broadcast can share the same interface safely.
 */

import { type PairingManifest, decodePairing, encodePairing, verifyPairing } from "./identity.js";

export type PeerHandler = (manifest: PairingManifest, source: string) => void;

/**
 * A way to announce yourself and learn about candidate peers. Implementations
 * range from QR (manual) to mDNS/BLE/LoRa (automatic). All deliver UNVERIFIED
 * manifests; admission is the caller's job (verifyPairing + TrustStore.add).
 */
export interface DiscoverySource {
  readonly name: string;
  start(): Promise<void> | void;
  stop(): Promise<void> | void;
  /** Publish our own manifest onto the channel. */
  announce(self: PairingManifest): Promise<void> | void;
  /** Register a callback fired for every candidate peer the channel surfaces. */
  onPeer(handler: PeerHandler): void;
}

// ──────────────────────── QR / out-of-band (implemented) ────────────────────────

/**
 * The medium for QR pairing: a human carries the string from one device to another
 * (camera scan, copy-paste, NFC tap). In a real app each side has its own device;
 * here a shared OutOfBandChannel lets two in-process peers rehearse the exchange.
 * It is deliberately dumb — no auth, no ordering guarantees — to model real life.
 */
export class OutOfBandChannel {
  private listeners = new Set<(payload: string) => void>();

  /** Someone shows a QR / pastes a string. Everyone "looking" receives it. */
  present(payload: string): void {
    for (const l of [...this.listeners]) l(payload);
  }

  observe(listener: (payload: string) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
}

export class QRDiscovery implements DiscoverySource {
  readonly name = "qr-out-of-band";
  private handlers: PeerHandler[] = [];
  private unsubscribe: (() => void) | null = null;

  constructor(private channel: OutOfBandChannel) {}

  start(): void {
    if (this.unsubscribe) return;
    this.unsubscribe = this.channel.observe((payload) => {
      let m: PairingManifest;
      try {
        m = decodePairing(payload); // ignore non-pairing noise on the channel
      } catch {
        return;
      }
      if (!verifyPairing(m)) return; // drop manifests that fail their own integrity check
      for (const h of this.handlers) h(m, this.name);
    });
  }

  stop(): void {
    this.unsubscribe?.();
    this.unsubscribe = null;
  }

  /** Render our manifest as a QR-encodable string and present it on the channel. */
  announce(self: PairingManifest): void {
    this.channel.present(encodePairing(self));
  }

  onPeer(handler: PeerHandler): void {
    this.handlers.push(handler);
  }
}

// ──────────────────────── automatic transports ────────────────────────
// These satisfy the same interface so the engine is transport-agnostic.
//   - LAN is IMPLEMENTED for real (UDP multicast) in ./lan.ts (Node-only).
//   - BLE/LoRa are honest stubs: they throw on start() rather than pretend to
//     work — a stub that silently no-ops would give false confidence, exactly
//     the failure mode the handoff warns about.

class NotImplementedDiscovery implements DiscoverySource {
  constructor(
    readonly name: string,
    private readonly plan: string,
  ) {}
  start(): never {
    throw new Error(`${this.name} not implemented yet. Plan: ${this.plan}`);
  }
  stop(): void {}
  announce(): void {
    throw new Error(`${this.name} not implemented yet. Plan: ${this.plan}`);
  }
  onPeer(): void {}
}

/** Phone-to-phone over Bluetooth LE GATT. True off-grid; needs native (Tauri/RN), not browser. */
export class BleDiscovery extends NotImplementedDiscovery {
  constructor() {
    super(
      "ble",
      "advertise a Chimera GATT service exposing the manifest; central scans & reads peers. Requires native BLE (Tauri/React Native shell).",
    );
  }
}

/** Long-range, very-low-bandwidth radio for sparse hostile environments. Manifest must be chunked. */
export class LoRaDiscovery extends NotImplementedDiscovery {
  constructor() {
    super(
      "lora",
      "beacon a compressed fp over LoRa; exchange full manifest on demand in chunks (sub-kbps). Requires radio hardware.",
    );
  }
}
