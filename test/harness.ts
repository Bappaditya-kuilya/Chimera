/**
 * test/harness.ts — a tiny zero-dependency test harness, in the kernel's own style
 * (PASS/FAIL lines, process exit code). No framework: matches observations.ts.
 */

import { canonicalJSON } from "../src/crypto.js";

export type T = {
  eq(label: string, got: unknown, want: unknown): void;
  ok(label: string, cond: boolean): void;
  throws(label: string, fn: () => unknown): void;
};

export type Suite = { name: string; suite: (t: T) => void };

export function runSuites(suites: Suite[]): void {
  let total = 0;
  let failed = 0;

  for (const { name, suite } of suites) {
    console.log(`\n── ${name} ──`);
    const t: T = {
      eq(label, got, want) {
        total++;
        const ok = canonicalJSON(got) === canonicalJSON(want);
        if (!ok) failed++;
        console.log(
          `  [${ok ? "PASS" : "FAIL"}] ${label}` +
            (ok ? "" : `\n        got  ${canonicalJSON(got)}\n        want ${canonicalJSON(want)}`),
        );
      },
      ok(label, cond) {
        total++;
        if (!cond) failed++;
        console.log(`  [${cond ? "PASS" : "FAIL"}] ${label}`);
      },
      throws(label, fn) {
        total++;
        let threw = false;
        try {
          fn();
        } catch {
          threw = true;
        }
        if (!threw) failed++;
        console.log(`  [${threw ? "PASS" : "FAIL"}] ${label} (expected throw)`);
      },
    };
    suite(t);
  }

  console.log("\n══════════════════════════════════════════════════════════");
  console.log(
    failed === 0
      ? ` ALL ${total} CHECKS PASSED`
      : ` ${failed}/${total} CHECKS FAILED`,
  );
  console.log("══════════════════════════════════════════════════════════");
  process.exit(failed === 0 ? 0 : 1);
}

/** Deterministic 32-byte seed from a small integer — for stable test identities. */
export function seed(n: number): Uint8Array {
  return new Uint8Array(32).fill(n & 0xff);
}
