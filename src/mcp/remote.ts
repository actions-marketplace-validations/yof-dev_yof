/**
 * The optional link to the person's yof.io account (yof_findings, yof_patch_status, yof_lessons, and yof_explain for a
 * rule the CLI does not know). Off unless YOF_API_KEY is set: the key is the one the yof dashboard put in this tool's
 * config ("Connect your AI builder"). What is sent: the tool name and its arguments (ids, a rule id), never code or
 * file contents. The server is the hosted yof MCP endpoint (YOF_MCP_URL, default https://mcp.yof.io/mcp).
 */
export const DEFAULT_MCP_URL = "https://mcp.yof.io/mcp";
export const REMOTE_TIMEOUT_MS = 15_000;
export const KEY_SHAPE = /^yof_mcp_[A-Za-z0-9_-]{43}$/;

export type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body: string; signal?: AbortSignal }) => Promise<{ status: number; json: () => Promise<unknown> }>;

export interface RemoteConfig { key: string | null; url: string; fetch: FetchLike; version: string }

export function remoteConfig(env: Record<string, string | undefined>, version: string, f?: FetchLike): RemoteConfig {
  const key = (env.YOF_API_KEY ?? "").trim();
  let url = (env.YOF_MCP_URL ?? DEFAULT_MCP_URL).trim().replace(/\/$/, "");
  // Only https (or a local test server), so the key never travels in the clear.
  if (!/^https:\/\//.test(url) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/.test(url)) url = DEFAULT_MCP_URL;
  return { key: KEY_SHAPE.test(key) ? key : null, url, fetch: f ?? (globalThis.fetch as unknown as FetchLike), version };
}

export class RemoteError extends Error {}

async function rpc(cfg: RemoteConfig, method: string, params: Record<string, unknown>): Promise<unknown> {
  if (!cfg.key) throw new RemoteError("This needs your yof account. In the yof dashboard, open Connect your AI builder and connect this tool: the config it gives you carries the key.");
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), REMOTE_TIMEOUT_MS);
  try {
    const r = await cfg.fetch(cfg.url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", Authorization: `Bearer ${cfg.key}`, "User-Agent": `yof-cli/${cfg.version} (+https://yof.io)` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: ctl.signal,
    });
    const body = (await r.json().catch(() => null)) as { result?: unknown; error?: { message?: string } } | null;
    if (r.status === 401) throw new RemoteError("yof.io did not accept the key. It may have been revoked: connect this tool again from the yof dashboard.");
    if (r.status === 429) throw new RemoteError(body?.error?.message ?? "Too many calls to yof.io for now. Try again later.");
    if (body?.error) throw new RemoteError(String(body.error.message ?? "yof.io answered with an error.").slice(0, 300));
    if (r.status >= 400 || !body) throw new RemoteError(`yof.io answered ${r.status}.`);
    return body.result;
  } catch (e) {
    if (e instanceof RemoteError) throw e;
    throw new RemoteError(ctl.signal.aborted ? "yof.io did not answer in time." : "Could not reach yof.io.");
  } finally { clearTimeout(timer); }
}

/** Call one hosted tool; answers its structured data (the hosted server returns it as structuredContent). */
export async function remoteTool(cfg: RemoteConfig, name: string, args: Record<string, unknown>): Promise<unknown> {
  const result = (await rpc(cfg, "tools/call", { name, arguments: args })) as { structuredContent?: unknown; isError?: boolean } | null;
  if (result?.isError) throw new RemoteError(String((result.structuredContent as { error?: string } | undefined)?.error ?? "yof.io could not run that.").slice(0, 300));
  return result?.structuredContent ?? null;
}

/** One ping when the local server starts with a key, so the dashboard's "Test connection" turns green. No code is sent. */
export async function remotePing(cfg: RemoteConfig): Promise<boolean> {
  if (!cfg.key) return false;
  try { await rpc(cfg, "ping", {}); return true; } catch { return false; }
}
