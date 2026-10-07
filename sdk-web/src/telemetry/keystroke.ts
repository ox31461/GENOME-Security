/**
 * Keystroke timing capture: records the inter-keydown interval (ms)
 * between consecutive keydown events on the given target, matching the
 * "flight time" signal the server-side detector (server/src/detector.rs)
 * and its training data (`genuine_keystroke_intervals`) were built on.
 *
 * Deliberately does NOT record which keys were pressed or their values --
 * only timing -- so this capture cannot leak typed content, only the
 * behavioral timing signal the trust engine needs.
 */

export interface KeystrokeCaptureOptions {
  /** Flush a batch once this many intervals have accumulated. Default 24. */
  batchSize?: number;
  /** Flush a batch at least this often regardless of size, in ms. Default 4000. */
  maxIntervalMs?: number;
  onBatch: (intervalsMs: number[]) => void;
}

export class KeystrokeCapture {
  private lastKeydownAt: number | null = null;
  private buffer: number[] = [];
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private readonly batchSize: number;
  private readonly maxIntervalMs: number;
  private readonly onBatch: (intervalsMs: number[]) => void;
  private readonly target: EventTarget;
  private readonly listener = (ev: Event) => this.handleKeydown(ev as KeyboardEvent);

  constructor(target: EventTarget, options: KeystrokeCaptureOptions) {
    this.target = target;
    this.batchSize = options.batchSize ?? 24;
    this.maxIntervalMs = options.maxIntervalMs ?? 4000;
    this.onBatch = options.onBatch;
  }

  start(): void {
    this.target.addEventListener("keydown", this.listener, { passive: true });
    this.flushTimer = setInterval(() => this.flush(), this.maxIntervalMs);
  }

  stop(): void {
    this.target.removeEventListener("keydown", this.listener);
    if (this.flushTimer) clearInterval(this.flushTimer);
    this.flushTimer = null;
    this.lastKeydownAt = null;
  }

  private handleKeydown(ev: KeyboardEvent): void {
    if (ev.repeat) return; // ignore OS auto-repeat, it is not a fresh motor event
    const now = performance.now();
    if (this.lastKeydownAt !== null) {
      this.buffer.push(now - this.lastKeydownAt);
      if (this.buffer.length >= this.batchSize) this.flush();
    }
    this.lastKeydownAt = now;
  }

  private flush(): void {
    if (this.buffer.length < 4) return; // too few samples for meaningful features
    const batch = this.buffer;
    this.buffer = [];
    this.onBatch(batch);
  }
}
