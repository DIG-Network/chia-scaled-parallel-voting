/**
 * Repeatedly evaluates `predicate()` until true or timeout. Used after
 * mempool submit (for example coinset `/push_tx`) to wait for on-chain observers.
 */

export interface PollUntilOptions {
  predicate: () => Promise<boolean>;
  /** Delay between retries after a failed predicate. Default 6000 ms. */
  pollMs?: number;
  /** Default 5 minutes */
  timeoutMs?: number;
  /** Invoked before each delay; `attempt` is 1-based. */
  onAttempt?: (info: {
    attempt: number;
    elapsedMs: number;
    nextDelayMs: number;
  }) => void;
}

export async function pollUntilConfirmed(opts: PollUntilOptions): Promise<boolean> {
  const pollMs = opts.pollMs ?? 6000;
  const timeoutMs = opts.timeoutMs ?? 5 * 60 * 1000;
  const started = Date.now();
  let attempt = 0;
  while (Date.now() - started < timeoutMs) {
    if (await opts.predicate()) return true;
    attempt += 1;
    opts.onAttempt?.({
      attempt,
      elapsedMs: Date.now() - started,
      nextDelayMs: pollMs,
    });
    await new Promise<void>((resolve) =>
      window.setTimeout(resolve, pollMs)
    );
  }
  return await opts.predicate();
}
