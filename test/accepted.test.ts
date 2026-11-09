import { describe, expect, it } from "vitest";
import { main } from "../src/cli";
import { ACCEPTED_FILE, acceptFingerprint, acceptanceFor, parseAccepted, withEntry, withoutEntry } from "../src/accepted";
import { runCheck } from "../src/check";
import { captureIo, fakeStripeLive, tempDir } from "./helpers";

/** .yof/accepted.json: the format, the matching, and that a changed line no longer matches. */
const AT = "2026-11-07T10:00:00.000Z";

describe("accepted.json format", () => {
  it("round-trips an entry, replaces the same finding, and removes it on reopen", () => {
    const fp = acceptFingerprint("secret.stripe_live", "src/a.ts", 'const k = "x";');
    const e = { rule: "secret.stripe_live", file: "src/a.ts", fingerprint: fp, reason: "Test only", acceptedBy: "Ada", acceptedAt: AT };
    const one = withEntry(null, e);
    expect(JSON.parse(one)).toEqual({ version: 1, accepted: [e] });
    expect(one.endsWith("\n")).toBe(true);
    expect(parseAccepted(withEntry(one, { ...e, reason: "Changed my mind" }))).toEqual([{ ...e, reason: "Changed my mind" }]);
    expect(parseAccepted(withoutEntry(one, fp))).toEqual([]);
  });
  it("leaves out bad entries and bad JSON (the findings stay open)", () => {
    expect(parseAccepted("{")).toEqual([]);
    expect(parseAccepted(JSON.stringify({ accepted: [{ rule: "x", file: "a", fingerprint: "nothex", reason: "r", acceptedAt: AT }, { rule: "x", file: "../a", fingerprint: "a".repeat(32), reason: "r", acceptedAt: AT }] }))).toEqual([]);
  });
  it("the fingerprint ignores surrounding spaces but changes with the line, the file or the rule", () => {
    const a = acceptFingerprint("r", "f.ts", "  const a = 1;  ");
    expect(a).toBe(acceptFingerprint("r", "f.ts", "const a = 1;"));
    expect(a).not.toBe(acceptFingerprint("r", "f.ts", "const a = 2;"));
    expect(a).not.toBe(acceptFingerprint("r", "g.ts", "const a = 1;"));
    expect(a).not.toBe(acceptFingerprint("q", "f.ts", "const a = 1;"));
    expect(acceptanceFor([{ rule: "r", file: "f.ts", fingerprint: a, reason: "ok", acceptedBy: "", acceptedAt: AT }], "r", "f.ts", "const a = 1;")).toEqual({ reason: "ok", acceptedBy: "", acceptedAt: AT });
  });
});

describe("yof check honours .yof/accepted.json", () => {
  const key = fakeStripeLive();
  const line = `export const stripe = "${key}";`;
  const accepted = (content: string) => JSON.stringify({ version: 1, accepted: [{ rule: "secret.stripe_live", file: "src/pay.ts", fingerprint: acceptFingerprint("secret.stripe_live", "src/pay.ts", content), reason: "A revoked key kept for a test", acceptedBy: "Ada", acceptedAt: AT }] });

  it("an accepted key leaves the open count and the exit code, and is still printed with its reason", async () => {
    const dir = tempDir({ "src/pay.ts": `${line}\n`, [ACCEPTED_FILE]: accepted(line) });
    const r = await runCheck({ cwd: dir, offline: true });
    expect(r.counts.fix_now).toBe(0);
    expect(r.acceptedCount).toBe(1);
    expect(r.failed).toBe(false);
    expect(r.keys[0]!.accepted?.reason).toBe("A revoked key kept for a test");
    const { cap, io } = captureIo(dir);
    expect(await main(["check", "--offline"], io)).toBe(0);
    const text = cap.out.join("\n");
    expect(text).toMatch(/Accepted risks \(\.yof\/accepted\.json\)/);
    expect(text).toMatch(/accepted by Ada on 2026-11-07: A revoked key kept for a test/);
    expect(text.includes(key)).toBe(false);
  });
  it("the JSON carries the fingerprint, the acceptance and acceptedCount for the editors", async () => {
    const dir = tempDir({ "src/pay.ts": `${line}\n`, [ACCEPTED_FILE]: accepted(line) });
    const { cap, io } = captureIo(dir);
    await main(["check", "--offline", "--json"], io);
    const j = JSON.parse(cap.out.join("\n"));
    expect(j.acceptedCount).toBe(1);
    expect(j.keys[0].fingerprint).toMatch(/^[0-9a-f]{32}$/);
    expect(j.keys[0].accepted.acceptedBy).toBe("Ada");
  });
  it("a changed line no longer matches: the finding is open again", async () => {
    const dir = tempDir({ "src/pay.ts": `export const stripeKey = "${key}";\n`, [ACCEPTED_FILE]: accepted(line) });
    const r = await runCheck({ cwd: dir, offline: true });
    expect(r.acceptedCount).toBe(0);
    expect(r.counts.fix_now).toBe(1);
    expect(r.failed).toBe(true);
  });
});
