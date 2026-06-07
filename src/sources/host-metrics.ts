/**
 * sources/host-metrics.ts — observations from REAL host telemetry (systeminformation).
 *
 * Reads this machine's actual network throughput and busiest processes and maps
 * spikes into observations. Proves Chimera runs on real signals, not just scripts.
 * Node-only; needs two samples to compute a per-second delta (the lib reports null
 * on the very first call).
 */

import si from "systeminformation";
import { type Observation, makeId } from "../kernel.js";
import { type Mode, type ObservationHandler, type ObservationSource } from "../source.js";

export type HostThresholds = {
  rxBytesPerSec: number; // inbound throughput above this on an interface reads as a flood
};

export const DEFAULT_HOST_THRESHOLDS: HostThresholds = { rxBytesPerSec: 5_000_000 }; // 5 MB/s

/**
 * Samples real network-interface stats and emits a PacketFlood observation for any
 * interface whose inbound rate exceeds the threshold. Each interface is a node.
 */
export class HostMetricsSource implements ObservationSource {
  readonly mode: Mode = "live";
  readonly name = "host-metrics";
  private handlers = new Set<ObservationHandler>();
  private tick = 0;
  private looping = false;

  constructor(
    private thresholds: HostThresholds = DEFAULT_HOST_THRESHOLDS,
    private intervalMs = 1000,
  ) {}

  subscribe(handler: ObservationHandler): () => void {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  start(): void {
    if (this.looping) return;
    this.looping = true;
    void this.loop();
  }
  stop(): void {
    this.looping = false;
  }

  /** Take one real sample and emit any observations it implies. Returns them too. */
  async sample(): Promise<Observation[]> {
    const stats = await si.networkStats();
    const t = ++this.tick;
    const out: Observation[] = [];
    for (const s of stats) {
      const rx = s.rx_sec ?? 0; // null on first sample
      if (rx >= this.thresholds.rxBytesPerSec) {
        const node = s.iface;
        const o: Observation = { id: makeId("PacketFlood", node, t), t, kind: "PacketFlood", node, rate: Math.round(rx) };
        out.push(o);
      }
    }
    for (const o of out) for (const h of [...this.handlers]) h(o);
    return out;
  }

  /** The real interfaces this host exposes — use them to build a topology. */
  async interfaces(): Promise<string[]> {
    const stats = await si.networkStats();
    return stats.map((s) => s.iface);
  }

  private async loop(): Promise<void> {
    while (this.looping) {
      await this.sample();
      await new Promise((r) => setTimeout(r, this.intervalMs));
    }
  }
}
