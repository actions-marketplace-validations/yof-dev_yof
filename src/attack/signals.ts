/**
 * Stopping `yof attack` (Ctrl+C, or an editor or CI cancelling the run):
 *   - the first SIGINT or SIGTERM aborts the run's signal: no new probe goes out, the run deletes the test records it
 *     created (at most STOP_CLEANUP_MS), prints what was deleted or left, and exits 130 (SIGINT) or 143 (SIGTERM);
 *   - a second signal exits at once, without waiting for the clean-up.
 */
export type StopSignal = "SIGINT" | "SIGTERM";
export const STOP_EXIT_CODE: Record<StopSignal, number> = { SIGINT: 130, SIGTERM: 143 };

/** What the handler needs from the process (tests pass a fake). */
export interface SignalHost {
  on(signal: StopSignal, fn: () => void): void;
  off(signal: StopSignal, fn: () => void): void;
  exit(code: number): void;
  err(line: string): void;
}

export interface StopHandle {
  signal: AbortSignal;
  /** The first signal received, or null. */
  received(): StopSignal | null;
  dispose(): void;
}

export function stopOnSignals(host: SignalHost): StopHandle {
  const ctl = new AbortController();
  let first: StopSignal | null = null;
  const handlers = (["SIGINT", "SIGTERM"] as const).map((sig) => {
    const fn = () => {
      if (first) {
        host.err("yof attack: stopped at once. Test records not deleted yet stay in your app (they hold the run's yof marker text).");
        host.exit(STOP_EXIT_CODE[sig]);
        return;
      }
      first = sig;
      host.err("yof attack: stopping. Deleting the test records this run created (send the signal again to quit at once).");
      ctl.abort();
    };
    host.on(sig, fn);
    return [sig, fn] as const;
  });
  return {
    signal: ctl.signal,
    received: () => first,
    dispose: () => { for (const [sig, fn] of handlers) host.off(sig, fn); },
  };
}

export const processSignalHost = (): SignalHost => ({
  on: (s, fn) => { process.on(s, fn); },
  off: (s, fn) => { process.off(s, fn); },
  exit: (code) => process.exit(code),
  err: (line) => process.stderr.write(`${line}\n`),
});
