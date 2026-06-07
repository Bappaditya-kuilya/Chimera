/**
 * sources/log-formats.ts — parse JSON / CSV / combined logs into Chimera analysis.
 *
 * Browser-safe (imports only the kernel + the shared mapping in access-log.ts; no
 * Node APIs), so the web app can analyze a file the user drops in, entirely client
 * side. All formats funnel through buildFromEntries() so the "is this an attack?"
 * rule is identical everywhere.
 */

import { type AccessLogOptions, type AccessLogResult, type Entry, buildFromEntries, parseAccessLog } from "./access-log.js";

export type LogFormat = "combined" | "json" | "csv" | "unknown";

const IP_KEYS = ["ip", "client", "client_ip", "clientip", "remote_addr", "remoteaddr", "src", "source", "host"];
const TIME_KEYS = ["time", "timestamp", "@timestamp", "ts", "date", "datetime", "time_local"];
const STATUS_KEYS = ["status", "code", "statuscode", "status_code", "response", "resp"];

function pick(obj: Record<string, unknown>, keys: string[]): unknown {
  const lower: Record<string, unknown> = {};
  for (const k of Object.keys(obj)) lower[k.toLowerCase()] = obj[k];
  for (const k of keys) if (lower[k] !== undefined) return lower[k];
  return undefined;
}

/** Parse a timestamp value (epoch seconds/ms, or an ISO/date string) to UTC seconds. */
function toEpoch(v: unknown): number | null {
  if (typeof v === "number") return v > 1e12 ? v / 1000 : v; // ms vs s heuristic
  if (typeof v === "string" && v.trim()) {
    const n = Number(v);
    if (Number.isFinite(n) && /^\d+$/.test(v.trim())) return n > 1e12 ? n / 1000 : n;
    const ms = Date.parse(v);
    if (!Number.isNaN(ms)) return ms / 1000;
  }
  return null;
}

function entryFrom(record: Record<string, unknown>): Entry | null {
  const ip = pick(record, IP_KEYS);
  const epoch = toEpoch(pick(record, TIME_KEYS));
  if (typeof ip !== "string" || epoch === null) return null;
  const statusRaw = pick(record, STATUS_KEYS);
  const status = typeof statusRaw === "number" ? statusRaw : Number(statusRaw) || 200;
  return { ip, epoch, status };
}

/** JSON array of records, or newline-delimited JSON (one object per line). */
export function parseJsonLog(text: string, opts: AccessLogOptions = {}): AccessLogResult {
  const records: Record<string, unknown>[] = [];
  const trimmed = text.trim();
  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed)) records.push(...parsed);
    else if (parsed && typeof parsed === "object") records.push(parsed);
  } catch {
    // NDJSON fallback
    for (const line of trimmed.split("\n")) {
      const l = line.trim();
      if (!l) continue;
      try {
        records.push(JSON.parse(l));
      } catch {
        /* skip bad line */
      }
    }
  }
  const entries = records.map(entryFrom).filter((e): e is Entry => e !== null);
  return buildFromEntries(entries, opts);
}

/** A minimal RFC-4180-ish CSV row splitter (handles quoted fields and commas). */
function splitCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inQ = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQ) {
      if (c === '"') {
        if (line[i + 1] === '"') { cur += '"'; i++; } else inQ = false;
      } else cur += c;
    } else if (c === '"') inQ = true;
    else if (c === ",") { out.push(cur); cur = ""; }
    else cur += c;
  }
  out.push(cur);
  return out.map((s) => s.trim());
}

/** CSV with a header row; ip/timestamp/status columns are auto-detected by name. */
export function parseCsvLog(text: string, opts: AccessLogOptions = {}): AccessLogResult {
  const lines = text.split("\n").filter((l) => l.trim());
  if (lines.length < 2) return buildFromEntries([], opts);
  const header = splitCsvLine(lines[0]!).map((h) => h.toLowerCase());
  const entries: Entry[] = [];
  for (let i = 1; i < lines.length; i++) {
    const cells = splitCsvLine(lines[i]!);
    const record: Record<string, unknown> = {};
    header.forEach((h, j) => (record[h] = cells[j]));
    const e = entryFrom(record);
    if (e) entries.push(e);
  }
  return buildFromEntries(entries, opts);
}

/** Sniff the format from content (and optional filename) and parse accordingly. */
export function detectFormat(text: string, filename?: string): LogFormat {
  const t = text.trim();
  const ext = filename?.toLowerCase().split(".").pop();
  if (ext === "json") return "json";
  if (ext === "csv") return "csv";
  if (t.startsWith("[") || t.startsWith("{")) return "json";
  // combined log lines look like:  1.2.3.4 - - [.. ] "GET .." 200
  if (/^\S+ \S+ \S+ \[[^\]]+\] "/.test(t)) return "combined";
  // a header row with commas and a recognizable column name -> CSV
  const first = t.split("\n")[0]?.toLowerCase() ?? "";
  if (first.includes(",") && (first.includes("ip") || first.includes("status") || first.includes("time"))) return "csv";
  return "unknown";
}

export type AnalyzeResult = AccessLogResult & { format: LogFormat };

/** One entry point for the web UI: detect format, parse, return observations+topology. */
export function analyzeLog(text: string, filename?: string, opts: AccessLogOptions = {}): AnalyzeResult {
  const format = detectFormat(text, filename);
  const result =
    format === "json" ? parseJsonLog(text, opts)
    : format === "csv" ? parseCsvLog(text, opts)
    : format === "combined" ? parseAccessLog(text, opts)
    : buildFromEntries([], opts);
  return { ...result, format };
}
