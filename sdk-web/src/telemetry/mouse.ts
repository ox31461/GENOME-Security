/**
 * Mouse timing capture: records the inter-sample interval (ms) between
 * consecutive `mousemove` events on the given target, matching the
 * timing signal the server-side detector was trained on
 * (`genuine_mouse_timing` in server/src/detector.rs). Position data is
 * intentionally not recorded here -- only movement timing.
 */

export interface MouseCaptureOptions {
  /** Flush a batch once this many intervals have accumulated. Default 32. */
  batchSize?: number;
  /** Flush a batch at least this often regardless of size, in ms. Default 4000. */
  maxIntervalMs?: number;
  onBatch: (intervalsMs: number[]) => void;
}

export class MouseCapture {
  private lastSampleAt: number | null = null;
  private buffer: number[] = [];
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private readonly batchSize: number;
  private readonly maxIntervalMs: number;
  private readonly onBatch: (intervalsMs: number[]) => void;
  private readonly target: EventTarget;
  private readonly listener = () => this.handleMove();

  constructor(target: EventTarget, options: MouseCaptureOptions) {
    this.target = target;
    this.batchSize = options.batchSize ?? 32;
    this.maxIntervalMs = options.maxIntervalMs ?? 4000;
    this.onBatch = options.onBatch;
  }

  start(): void {
    this.target.addEventListener("mousemove", this.listener, { passive: true });
    this.flushTimer = setInterval(() => this.flush(), this.maxIntervalMs);
  }

  stop(): void {
    this.target.removeEventListener("mousemove", this.listener);
    if (this.flushTimer) clearInterval(this.flushTimer);
    this.flushTimer = null;
    this.lastSampleAt = null;
  }

  private handleMove(): void {
    const now = performance.now();
    if (this.lastSampleAt !== null) {
      const delta = now - this.lastSampleAt;
      // Coalesce near-duplicate events the browser sometimes fires back
      // to back (sub-millisecond); they add noise without signal.
      if (delta > 0.5) {
        this.buffer.push(delta);
        if (this.buffer.length >= this.batchSize) this.flush();
      }
    }
    this.lastSampleAt = now;
  }

  private flush(): void {
    if (this.buffer.length < 4) return;
    const batch = this.buffer;
    this.buffer = [];
    this.onBatch(batch);
  }
}
