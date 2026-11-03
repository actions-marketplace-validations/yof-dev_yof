/**
 * Stopping yof attack: the first SIGINT / SIGTERM ends the probes, deletes every test record the run created (within a
 * hard deadline) and exits 130 / 143; a second signal exits at once.
 */
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseAttackConfig } from "../src/attack/config";
import type { FetchFn } from "../src/attack/http";
import { proveTarget } from "../src/attack/proof";
import { cleanupLines } from "../src/attack/report";
import { runAttack, STOP_CLEANUP_MS } from "../src/attack/runner";
import { STOP_EXIT_CODE, stopOnSignals, type SignalHost, type StopSignal } from "../src/attack/signals";
import { main } from "../src/cli";
import { fakeConfig, fakeEnv, startFakeApp, type FakeApp } from "./fake-app";

const noSleep = async () => {};
const realFetch: FetchFn = (u, i) => fetch(u, i);
let apps: FakeApp[] = [];
afterEach(async () => { for (const a of apps) await a.close(); apps = []; });
const app = async () => { const a = await startFakeApp(true); apps.push(a); return a; };

async function setup(a: FakeApp) {
  const cfg = parseAttackConfig(fakeConfig());
  const proof = await proveTarget(a.url, cfg, "full", { env: {} });
  if (!proof.ok) throw new Error(proof.message);
  return { cfg, proof };
}

/** A fetch that runs `onRequest` before each request is sent (to stop the run at a chosen point). */
const watching = (onRequest: (method: string, n: number, url: string) => void): FetchFn => {
  let n = 0;
  return (u, i) => { onRequest(i.method, ++n, u); return realFetch(u, i); };
};

class FakeHost implements SignalHost {
  handlers = new Map<StopSignal, Set<() => void>>();
  exits: number[] = [];
  errs: string[] = [];
  on(s: StopSignal, fn: () => void) { if (!this.handlers.has(s)) this.handlers.set(s, new Set()); this.handlers.get(s)!.add(fn); }
  off(s: StopSignal, fn: () => void) { this.handlers.get(s)?.delete(fn); }
  exit(code: number) { this.exits.push(code); }
  err(line: string) { this.errs.push(line); }
  emit(s: StopSignal) { for (const fn of [...(this.handlers.get(s) ?? [])]) fn(); }
  count() { return [...this.handlers.values()].reduce((n, s) => n + s.size, 0); }
}

describe("a run stopped part way", () => {
  it("leaves zero test records: no probe after the stop, then every record it created is deleted", async () => {
    const a = await app();
    const { cfg, proof } = await setup(a);
    const ctl = new AbortController();
    let posts = 0, stoppedAt = -1;
    // Stop while the second create request is being sent: it is allowed to finish, so its record is known and deleted.
    const f = watching((method, n, u) => { if (method === "POST" && u.endsWith("/api/notes") && ++posts === 2 && !ctl.signal.aborted) { stoppedAt = n; ctl.abort(); } });
    const r = await runAttack({ cfg, proof, mode: "full", env: fakeEnv(), sleep: noSleep, fetch: f, signal: ctl.signal });
    expect(stoppedAt).toBeGreaterThan(0);
    expect(r.stopped).toBe("cancelled");
    expect(r.cleanup.left).toEqual([]);
    expect(r.cleanup.deleted).toBeGreaterThanOrEqual(2);
    expect(a.notes.size).toBe(0);
    // After the stop only DELETEs reached the app.
    const after = a.requests.slice(stoppedAt);
    expect(after.length).toBeGreaterThan(0);
    expect(after.every((x) => x.method === "DELETE")).toBe(true);
  });

  it("a stop before anything was created deletes nothing and sends nothing more", async () => {
    const a = await app();
    const { cfg, proof } = await setup(a);
    const ctl = new AbortController();
    const f = watching((_m, n) => { if (n === 2) ctl.abort(); });
    const r = await runAttack({ cfg, proof, mode: "full", env: fakeEnv(), sleep: noSleep, fetch: f, signal: ctl.signal });
    expect(r).toMatchObject({ stopped: "cancelled", cleanup: { deleted: 0, left: [] } });
    expect(a.requests.length).toBeLessThanOrEqual(2);
    expect(a.notes.size).toBe(0);
  });

  it("clean-up has a hard deadline: past it, the records left are listed by route, never by id", async () => {
    const a = await app();
    const { cfg, proof } = await setup(a);
    const ctl = new AbortController();
    let t = 0, posts = 0;
    const f = watching((method, _n, u) => { if (method === "POST" && u.endsWith("/api/notes") && ++posts === 3) ctl.abort(); });
    // A clock that jumps once the run is stopped: the first delete goes, the deadline passes before the next one.
    const now = () => (t += ctl.signal.aborted ? STOP_CLEANUP_MS / 2 + 1 : 1);
    const r = await runAttack({ cfg, proof, mode: "full", env: fakeEnv(), sleep: noSleep, fetch: f, signal: ctl.signal, now });
    expect(r.stopped).toBe("cancelled");
    expect(r.cleanup.deleted).toBeGreaterThanOrEqual(1);
    expect(r.cleanup.left.length).toBeGreaterThanOrEqual(1);
    expect(r.cleanup.left.every((p) => p === "/api/notes/{id}")).toBe(true);
    expect(a.notes.size).toBe(r.cleanup.left.length);
    expect(cleanupLines(r.cleanup).join("\n")).toMatch(/left\.\n {2}Not deleted \(delete them in your app; they hold this run's yof marker text\): \/api\/notes\/\{id\}/);
  });
});

describe("signals", () => {
  it("the first signal stops the run without exiting; a second one exits at once with 130 or 143", () => {
    for (const [sig, code] of [["SIGINT", 130], ["SIGTERM", 143]] as const) {
      const host = new FakeHost();
      const h = stopOnSignals(host);
      expect(host.count()).toBe(2);
      host.emit(sig);
      expect(h.signal.aborted).toBe(true);
      expect(h.received()).toBe(sig);
      expect(host.exits).toEqual([]);
      expect(host.errs[0]).toMatch(/stopping\. Deleting the test records/);
      const t0 = performance.now();
      host.emit(sig);
      expect(host.exits).toEqual([code]);
      expect(performance.now() - t0).toBeLessThan(50);
      h.dispose();
      expect(host.count()).toBe(0);
      expect(STOP_EXIT_CODE[sig]).toBe(code);
    }
  });

  it("the CLI: SIGTERM mid-run cleans up, says so and exits 143; the handlers are removed afterwards", async () => {
    const a = await app();
    const dir = mkdtempSync(join(tmpdir(), "yof-stop-"));
    mkdirSync(join(dir, ".yof"));
    writeFileSync(join(dir, ".yof/attack.json"), fakeConfig());
    const host = new FakeHost();
    let posts = 0;
    const http = watching((method) => { if (method === "POST" && ++posts === 2) host.emit("SIGTERM"); });
    const out: string[] = [], err: string[] = [];
    const code = await main(["attack", a.url], { cwd: dir, out: (s) => out.push(s), err: (s) => err.push(s), env: fakeEnv(), http, sleep: noSleep, signals: host });
    expect(code).toBe(143);
    expect(a.notes.size).toBe(0);
    expect(out.join("\n")).toMatch(/Stopped early: you stopped the run\./);
    expect(err.join("\n")).toMatch(/Deleted (the test record|all \d+ test records) it created\./);
    expect(host.count()).toBe(0);
  });
});
