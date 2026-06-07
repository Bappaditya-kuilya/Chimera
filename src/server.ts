/**
 * server.ts — run Chimera as a real service (HTTP + WebSocket), not just a library.
 *
 * Wraps a live CausalRuntime so other systems can POST real observations and get
 * back a live, explainable verdict — and stream decisions as they happen. Also
 * serves the interactive web UI, so `npm run serve` is a complete running app.
 *
 *   GET  /api/state      -> { verdict, mode, nodes:[{node,state,trust,...}] }
 *   GET  /api/timeline   -> the event timeline
 *   POST /api/observe    -> ingest one Observation; returns { verdict, produced }
 *   POST /api/simulate   -> { intervention } -> a branded SIMULATION result
 *   WS   /               -> pushes { verdict, produced, obs } on every ingest
 *
 * Node-only (node:http + ws). Never part of the browser bundle.
 */

import http from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, resolve } from "node:path";
import { WebSocketServer, type WebSocket } from "ws";
import { type Observation, type Intervention, nodeState } from "./kernel.js";
import { CausalRuntime } from "./runtime.js";

export type ServerOptions = { port?: number; host?: string; webDir?: string };

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".webmanifest": "application/manifest+json; charset=utf-8",
};

function stateView(rt: CausalRuntime) {
  const s = rt.liveState();
  return {
    verdict: rt.verdict,
    mode: rt.mode,
    nodes: rt.nodes().map((n) => ({
      node: n,
      state: nodeState(s, n),
      trust: s.trust[n] ?? 1,
      infected: s.infected.has(n),
      quarantined: s.quarantined.has(n),
    })),
  };
}

function readJson(req: http.IncomingMessage): Promise<unknown> {
  return new Promise((res, rej) => {
    let body = "";
    req.on("data", (c) => {
      body += c;
      if (body.length > 1_000_000) rej(new Error("body too large"));
    });
    req.on("end", () => {
      try {
        res(body ? JSON.parse(body) : {});
      } catch {
        rej(new Error("invalid JSON"));
      }
    });
    req.on("error", rej);
  });
}

const send = (res: http.ServerResponse, code: number, body: unknown) => {
  const json = JSON.stringify(body);
  res.writeHead(code, { "content-type": "application/json; charset=utf-8" });
  res.end(json);
};

export type ChimeraServer = {
  server: http.Server;
  url: string;
  close: () => Promise<void>;
};

/** Start an HTTP+WS server in front of a live runtime. Resolves once listening. */
export function startServer(rt: CausalRuntime, opts: ServerOptions = {}): Promise<ChimeraServer> {
  const host = opts.host ?? "127.0.0.1";
  const webDir = resolve(opts.webDir ?? "web");
  const clients = new Set<WebSocket>();

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", `http://${host}`);
      const path = url.pathname;
      if (req.method === "GET" && path === "/api/state") return send(res, 200, stateView(rt));
      if (req.method === "GET" && path === "/api/timeline") return send(res, 200, rt.snapshot().timeline);

      if (req.method === "POST" && path === "/api/observe") {
        const obs = (await readJson(req)) as Observation;
        if (!obs || !obs.kind || typeof obs.t !== "number") return send(res, 400, { error: "expected an Observation" });
        const produced = rt.ingest(obs);
        return send(res, 200, { verdict: rt.verdict, produced });
      }

      if (req.method === "POST" && path === "/api/simulate") {
        const iv = (await readJson(req)) as Intervention;
        return send(res, 200, rt.simulate(iv ?? {}));
      }

      // static UI
      if (req.method === "GET") return await serveStatic(res, webDir, path);

      return send(res, 404, { error: "not found" });
    } catch (e) {
      return send(res, 400, { error: (e as Error).message });
    }
  });

  // WebSocket: push live decisions to every connected client.
  const wss = new WebSocketServer({ server });
  wss.on("connection", (ws) => {
    clients.add(ws);
    ws.send(JSON.stringify({ type: "state", ...stateView(rt) }));
    ws.on("close", () => clients.delete(ws));
  });
  rt.onDecisions((produced, obs) => {
    const msg = JSON.stringify({ type: "decisions", obs, produced, verdict: rt.verdict });
    for (const ws of clients) if (ws.readyState === ws.OPEN) ws.send(msg);
  });

  return new Promise((resolveListening) => {
    server.listen(opts.port ?? 8787, host, () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : opts.port;
      resolveListening({
        server,
        url: `http://${host}:${port}`,
        close: () =>
          new Promise<void>((r) => {
            for (const ws of clients) ws.terminate();
            wss.close();
            server.close(() => r());
          }),
      });
    });
  });
}

async function serveStatic(res: http.ServerResponse, webDir: string, path: string): Promise<void> {
  const rel = normalize(path === "/" ? "/index.html" : path).replace(/^(\.\.[/\\])+/, "");
  const file = join(webDir, rel);
  if (!file.startsWith(webDir)) {
    res.writeHead(403);
    return void res.end("forbidden");
  }
  try {
    const data = await readFile(file);
    res.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream" });
    res.end(data);
  } catch {
    res.writeHead(404);
    res.end("not found");
  }
}
