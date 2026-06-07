/**
 * sources/access-log.ts — turn a REAL web-server access log into observations.
 *
 * This is the "Causal Security Runtime" pivot on real data: point Chimera at an
 * nginx/Apache access log and it answers "a client hammered us — did blocking it
 * actually save the server, or would we have gone down anyway?"
 *
 * Parsing is real (the standard "combined" log format). The mapping rule:
 *   - bucket requests per client IP per second,
 *   - a second whose request count >= floodPerSecond is a PacketFlood on that IP,
 *   - bursts of auth failures (401/403) become SignatureInvalid signals,
 *   - the topology is derived from the IPs actually seen: a Server hub with each
 *     client as a leaf, so an un-blocked flood can cascade Server -> other clients.
 *
 * Node-side only (string parsing, no DOM); never imported by the browser bundle.
 */

import { type Observation, type Topology, makeId } from "../kernel.js";

export type AccessLogOptions = {
  floodPerSecond?: number; // requests/sec from one IP that reads as a flood
  authFailsForBadSig?: number; // 401/403s in a second that read as a bad-signature
  server?: string; // the node name for "our server" (the hub)
};

const DEFAULTS: Required<AccessLogOptions> = {
  floodPerSecond: 5,
  authFailsForBadSig: 3,
  server: "Server",
};

// Standard "combined"/"common" access log line:
//   1.2.3.4 - - [10/Oct/2024:13:55:36 -0700] "GET /path HTTP/1.1" 200 1234 "..." "..."
const LINE = /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+)\s+(\S+)[^"]*" (\d{3}) /;
const TIME = /^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{2})(\d{2})$/;
const MONTHS: Record<string, number> = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

export type Entry = { ip: string; epoch: number; status: number };

function parseTime(s: string): number | null {
  const m = TIME.exec(s.trim());
  if (!m) return null;
  const [, dd, mon, yyyy, hh, mm, ss, tzh, tzm] = m;
  const month = MONTHS[mon!];
  if (month === undefined) return null;
  const utc = Date.UTC(+yyyy!, month, +dd!, +hh!, +mm!, +ss!) / 1000;
  const tzOffset = (tzh!.startsWith("-") ? -1 : 1) * (Math.abs(+tzh!) * 3600 + +tzm! * 60);
  return utc - tzOffset; // normalize to real UTC seconds
}

export type AccessLogResult = {
  observations: Observation[];
  topology: Topology;
  summary: {
    lines: number;
    clients: string[];
    floods: number;
    badSigs: number;
    busiestClient: string | null;
  };
};

/**
 * Shared mapping: turn parsed {ip, epoch, status} entries into observations + a
 * derived Server-hub topology. Used by ALL log formats (combined/JSON/CSV) so the
 * "is this an attack?" rule lives in exactly one place.
 */
export function buildFromEntries(entries: Entry[], opts: AccessLogOptions = {}): AccessLogResult {
  const o = { ...DEFAULTS, ...opts };
  if (!entries.length) {
    return {
      observations: [],
      topology: { nodes: [o.server], edges: { [o.server]: [] } },
      summary: { lines: 0, clients: [], floods: 0, badSigs: 0, busiestClient: null },
    };
  }

  const minEpoch = Math.min(...entries.map((e) => e.epoch));
  // counts[ip][secondBucket] = { reqs, authFails }
  const counts = new Map<string, Map<number, { reqs: number; authFails: number }>>();
  const perClient = new Map<string, number>();
  for (const e of entries) {
    const bucket = Math.max(0, Math.floor(e.epoch - minEpoch));
    const byBucket = counts.get(e.ip) ?? new Map();
    const cell = byBucket.get(bucket) ?? { reqs: 0, authFails: 0 };
    cell.reqs++;
    if (e.status === 401 || e.status === 403) cell.authFails++;
    byBucket.set(bucket, cell);
    counts.set(e.ip, byBucket);
    perClient.set(e.ip, (perClient.get(e.ip) ?? 0) + 1);
  }

  const clients = [...counts.keys()].sort();
  const observations: Observation[] = [];
  let floods = 0;
  let badSigs = 0;

  for (const ip of clients) {
    for (const [bucket, cell] of [...counts.get(ip)!.entries()].sort((a, b) => a[0] - b[0])) {
      const t = bucket + 1; // logical tick = seconds since first request (1-based)
      if (cell.reqs >= o.floodPerSecond) {
        observations.push({ id: makeId("PacketFlood", ip, t), t, kind: "PacketFlood", node: ip, rate: cell.reqs });
        floods++;
      } else if (cell.authFails >= o.authFailsForBadSig) {
        observations.push({ id: makeId("SignatureInvalid", ip, t), t, kind: "SignatureInvalid", node: ip });
        badSigs++;
      }
    }
  }

  // topology: a Server hub with each observed client as a leaf.
  const nodes = [o.server, ...clients];
  const edges: Record<string, string[]> = { [o.server]: [...clients] };
  for (const ip of clients) edges[ip] = [o.server];

  const busiestClient = [...perClient.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0]![0];

  return {
    observations: observations.sort((a, b) => a.t - b.t || a.id.localeCompare(b.id)),
    topology: { nodes, edges },
    summary: { lines: entries.length, clients, floods, badSigs, busiestClient },
  };
}

/** Parse a real access log (combined/common format) into observations + topology. */
export function parseAccessLog(text: string, opts: AccessLogOptions = {}): AccessLogResult {
  const entries: Entry[] = [];
  for (const raw of text.split("\n")) {
    if (!raw.trim()) continue;
    const m = LINE.exec(raw);
    if (!m) continue;
    const epoch = parseTime(m[2]!);
    if (epoch === null) continue;
    entries.push({ ip: m[1]!, epoch, status: Number(m[5]) });
  }
  return buildFromEntries(entries, opts);
}
