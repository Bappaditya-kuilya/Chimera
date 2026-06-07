/**
 * qr.ts — real, scannable QR codes for pairing (via the `qrcode` library).
 *
 * The pairing manifest (identity.ts) already serializes to a compact string; this
 * just renders that string as an actual QR a phone camera can scan, instead of
 * asking a human to copy 200 characters by hand. Node-only here (used by the CLI
 * demos); the same `qrcode` lib also works in the browser if needed.
 */

import QRCode from "qrcode";

/** A QR code as ANSI blocks for the terminal. */
export function qrTerminal(text: string): Promise<string> {
  return QRCode.toString(text, { type: "terminal", small: true });
}

/** A QR code as a data: URL (PNG) — embeddable in an <img> in a web UI. */
export function qrDataUrl(text: string): Promise<string> {
  return QRCode.toDataURL(text, { margin: 1, scale: 4 });
}
