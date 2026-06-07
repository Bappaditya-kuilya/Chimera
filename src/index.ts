/**
 * Chimera — public surface.
 *
 *   kernel      : the proven pure causal engine (run / counterfactual / explain / ...)
 *   crypto      : ed25519 + hashing primitives (the only crypto-lib touchpoint)
 *   identity    : keypairs, fingerprints, QR pairing manifests
 *   trust-store : the web of trust (Sybil boundary)
 *   ingest      : sign + verify observations before they reach the kernel
 *   discovery   : DiscoverySource interface + QR impl (+ mDNS/BLE/LoRa stubs)
 */

export * from "./kernel.js";
export * from "./crypto.js";
export * from "./identity.js";
export * from "./trust-store.js";
export * from "./ingest.js";
export * from "./discovery.js";
