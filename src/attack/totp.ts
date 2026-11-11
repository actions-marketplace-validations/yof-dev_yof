/**
 * A time-based one-time code (RFC 6238, the Google Authenticator default: SHA-1, 30-second step, 6 digits) from a
 * base32 secret. yof attack uses it only to sign in as the owner's OWN test account, with a secret the owner keeps in
 * a CI environment variable. The secret is never written to a report, a log or the recorded exchanges.
 *
 * The replay engine (replay.ts) and its Python twin (regression.ts) carry their own small copies, so a generated
 * regression test signs in the same way with no dependency on yof.
 */
import { createHmac } from "node:crypto";

/** Decode an RFC 4648 base32 string (spaces and padding ignored, case-insensitive) to bytes; null when invalid. */
export function base32Decode(input: string): Buffer | null {
  const s = input.replace(/[\s=]/g, "").toUpperCase();
  if (!s || /[^A-Z2-7]/.test(s)) return null;
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0;
  const out: number[] = [];
  for (const ch of s) {
    value = (value << 5) | alphabet.indexOf(ch);
    bits += 5;
    if (bits >= 8) { bits -= 8; out.push((value >>> bits) & 0xff); }
  }
  return Buffer.from(out);
}

/** The 6-digit TOTP for a base32 secret at `now` (ms); "" when the secret is not valid base32. */
export function totpCode(secret: string, now: number = Date.now(), step = 30, digits = 6): string {
  const key = base32Decode(secret);
  if (!key || !key.length) return "";
  const counter = Math.floor(now / 1000 / step);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac("sha1", key).update(buf).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const bin = ((hmac[offset]! & 0x7f) << 24) | ((hmac[offset + 1]! & 0xff) << 16) | ((hmac[offset + 2]! & 0xff) << 8) | (hmac[offset + 3]! & 0xff);
  return String(bin % 10 ** digits).padStart(digits, "0");
}
