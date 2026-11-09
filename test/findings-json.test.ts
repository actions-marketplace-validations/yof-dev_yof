/**
 * findings.json in the CLI (Y18 C): `yof check --format findings-json` writes Cloudflare's security-audit format with
 * yof's verdicts, and `yof import <file> [path]` reads one strictly and checks each record's file and line against the
 * folder, read only. Schema: https://github.com/cloudflare/security-audit-skill (MIT License, Cloudflare, Inc.).
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { main } from "../src/cli";
import { fromFindingsJson, toFindingsJson } from "../src/findings-json";
import { captureIo, fakeStripeLive, mockFetcher, tempDir } from "./helpers";

const registry = {
  "https://registry.npmjs.org/reqeusts-helper": { status: 404 },
  "https://registry.npmjs.org/react": { status: 200, json: { time: { created: "2013-05-29T00:00:00Z" }, versions: Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`18.0.${i}`, {}])) } },
};

describe("yof check --format findings-json", () => {
  it("writes valid findings.json: a leaked key and a made-up package are confirmed, high at most, and the key stays masked", async () => {
    const key = fakeStripeLive();
    const dir = tempDir({ "src/config.ts": `export const stripe = "${key}";\n`, "package.json": JSON.stringify({ dependencies: { react: "^18", "reqeusts-helper": "^1.0.0" } }) });
    const { cap, io } = captureIo(dir, { fetcher: mockFetcher(registry) });
    expect(await main(["check", "--format", "findings-json"], io)).toBe(1);
    const out = cap.out.join("\n");
    expect(out.includes(key)).toBe(false);
    const r = fromFindingsJson(out);
    expect(r.errors).toEqual([]);
    expect(r.findings.map((f) => f.verdict)).toEqual(["confirmed", "confirmed"]);
    for (const f of r.findings) expect(f.severity!.overall).not.toBe("critical");
    expect(r.findings.map((f) => f.fingerprint.split("/")[1]).sort()).toEqual(["package.made_up", "secret.stripe_live"]);
    // the round trip is exact
    expect(toFindingsJson(r.findings)).toEqual(JSON.parse(out));
  });
  it("an unknown format is a usage error", async () => {
    const { io } = captureIo(tempDir({ "a.ts": "x" }));
    expect(await main(["check", "--format", "xml"], io)).toBe(2);
  });
});

const record = (o: Record<string, unknown> = {}) => ({
  verdict: "needs_validation", fingerprint: "src/a.ts:h:ssrf", title: "Fetch of a user URL", description: "The handler fetches a URL from the body.",
  claimed_root_cause: "No host allow-list.", trace: [{ kind: "sink", file: "src/a.ts", line: 2, scope: "h", description: "fetch(url)" }],
  evidence: [{ file: "src/a.ts", line: 2, description: "fetch(req.body.url)" }], blockers: ["Whether egress is blocked."], validation_plan: { local: "Call h with a loopback URL." }, ...o,
});

describe("yof import <findings.json>", () => {
  it("checks each record's file and line against the folder, reads nothing outside it, and exits 1 when a record needs a look", async () => {
    const dir = tempDir({
      "src/a.ts": "export async function h(req) {\n  return fetch(req.body.url);\n}\n",
      "findings.json": JSON.stringify([
        record(),
        record({ fingerprint: "src/b.ts:x", trace: [{ kind: "sink", file: "src/b.ts", line: 1, scope: "x", description: "d" }], evidence: [{ file: "src/b.ts", line: 1, description: "d" }] }),
        record({ fingerprint: "src/a.ts:far", trace: [{ kind: "sink", file: "src/a.ts", line: 90, scope: "x", description: "d" }], evidence: [{ file: "src/a.ts", line: 90, description: "d" }] }),
        record({ fingerprint: "escape", trace: [{ kind: "sink", file: "../../etc/passwd", line: 1, scope: "x", description: "d" }], evidence: [{ file: "../../etc/passwd", line: 1, description: "d" }] }),
        { verdict: "rejected", fingerprint: "src/a.ts:old", title: "Old claim", description: "d", claimed_root_cause: "c", trace: [{ kind: "sink", file: "src/a.ts", line: 1, scope: "s", description: "d" }], evidence: [{ file: "src/a.ts", line: 1, description: "d" }], reason: "Refuted." },
      ]),
    });
    const { cap, io } = captureIo(dir);
    expect(await main(["import", "findings.json", "--json"], io)).toBe(1);
    const r = JSON.parse(cap.out.join("\n")) as { records: { fingerprint: string; local: string; verdict: string }[]; errors: string[] };
    expect(r.errors).toEqual([]);
    const by = Object.fromEntries(r.records.map((x) => [x.fingerprint, x.local]));
    expect(by).toEqual({ "src/a.ts:h:ssrf": "found", "src/b.ts:x": "missing_file", "src/a.ts:far": "missing_line", escape: "outside_folder", "src/a.ts:old": "found" });
    const text = captureIo(dir);
    expect(await main(["import", "findings.json"], text.io)).toBe(1);
    expect(text.cap.out.join("\n")).toMatch(/Rejected \(1\): kept for the record, not counted/);
  });
  it("exit 2 on a file that is not valid findings.json; every problem is named; nothing is guessed", async () => {
    const dir = tempDir({ "findings.json": JSON.stringify([record({ extra: true }), record({ fingerprint: "b", blockers: [] })]) });
    const { cap, io } = captureIo(dir);
    expect(await main(["import", "findings.json"], io)).toBe(2);
    const text = cap.out.join("\n");
    expect(text).toMatch(/\[0\]\.extra: is not allowed/);
    expect(text).toMatch(/\[1\]\.blockers: needs at least 1 item/);
    const missing = captureIo(dir);
    expect(await main(["import", "nope.json"], missing.io)).toBe(2);
    expect(await main(["import"], missing.io)).toBe(2);
  });
  it("0 when only rejected records are left; the mapper is the same file as the yof app's, with the MIT credit", async () => {
    const dir = tempDir({ "a.ts": "x\n", "f.json": JSON.stringify([{ verdict: "rejected", fingerprint: "a", title: "t", description: "d", claimed_root_cause: "c", trace: [{ kind: "sink", file: "a.ts", line: 1, scope: "s", description: "d" }], evidence: [{ file: "a.ts", line: 1, description: "d" }], reason: "r" }]) });
    const { io } = captureIo(dir);
    expect(await main(["import", "f.json"], io)).toBe(0);
    const src = readFileSync(join(__dirname, "../src/findings-json.ts"), "utf8");
    expect(src).toMatch(/MIT License, Copyright \(c\) 2025-2026 Cloudflare, Inc\./);
    expect(readFileSync(join(__dirname, "../NOTICE"), "utf8")).toMatch(/Copyright \(c\) 2025-2026 Cloudflare, Inc\./);
  });
});
