/**
 * Client-side synthetic-input injection simulator, for the demo app's
 * "inject synthetic-looking input" button only. This intentionally
 * mirrors the simplest synthetic-keystroke generator from
 * server/src/synthetic_input.rs (i.i.d. Gaussian jitter profiled to a
 * target mean/std, with no long-range correlation or heavy tail) -- the
 * same signal the server-side detector was trained to catch. This is a
 * demo aid, NOT a real injection technique, and ships only to make the
 * defense visibly react in the demo UI.
 */

function gaussianSample(mean: number, std: number): number {
  // Box-Muller transform.
  const u1 = Math.random() || Number.EPSILON;
  const u2 = Math.random();
  const z0 = Math.sqrt(-2.0 * Math.log(u1)) * Math.cos(2.0 * Math.PI * u2);
  return mean + std * z0;
}

/** Generate `n` i.i.d.-Gaussian inter-keystroke intervals (ms), profiled
 * to look like plausible human typing timing but lacking the
 * long-range-correlated / heavy-tailed structure real human motor
 * control produces -- this is exactly the signal the server-side
 * detector (server/src/detector.rs) is trained to flag. */
export function generateSyntheticKeystrokeBatch(n = 24, meanMs = 180, stdMs = 18): number[] {
  return Array.from({ length: n }, () => Math.max(20, gaussianSample(meanMs, stdMs)));
}
