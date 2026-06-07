/**
 * scripts/viz.mjs — bundle the browser-safe kernel for the M5 visualization.
 *
 *   node scripts/viz.mjs          -> one-shot build to web/app.js
 *   node scripts/viz.mjs --serve  -> build + serve web/ on http://127.0.0.1:5173
 *
 * Why a script (not the esbuild CLI): the source uses NodeNext ".js" import
 * specifiers that resolve to ".ts" on disk. A tiny resolve plugin maps them so the
 * same files that run under tsx also bundle for the browser. No app code changes,
 * no new runtime deps — esbuild is already present (it ships inside tsx).
 */

import esbuild from "esbuild";
import fs from "node:fs";
import path from "node:path";

// Map relative ".js" imports to their ".ts" source on disk (NodeNext <-> bundler).
const jsToTs = {
  name: "js-to-ts",
  setup(build) {
    build.onResolve({ filter: /\.js$/ }, (args) => {
      if (!args.path.startsWith(".")) return undefined;
      const ts = path.resolve(args.resolveDir, args.path.replace(/\.js$/, ".ts"));
      return fs.existsSync(ts) ? { path: ts } : undefined;
    });
  },
};

const options = {
  entryPoints: ["web/app.ts"],
  bundle: true,
  format: "esm",
  target: "es2022",
  outfile: "web/app.js",
  sourcemap: true,
  logLevel: "info",
  plugins: [jsToTs],
};

if (process.argv.includes("--serve")) {
  const ctx = await esbuild.context(options);
  await ctx.rebuild();
  const { port } = await ctx.serve({ servedir: "web", host: "127.0.0.1", port: 5173 });
  console.log(`\n  Chimera visualization → http://127.0.0.1:${port}\n  (Ctrl-C to stop)\n`);
} else {
  await esbuild.build(options);
  console.log("built web/app.js");
}
