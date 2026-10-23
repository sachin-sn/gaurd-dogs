/**
 * Alert throttling. Two limits, both over a rolling window:
 *
 * - The same alert (same key) is sent once per window. Repeats are counted, and
 *   the next alert says how many were suppressed.
 * - A global cap on how many different alerts go out per window. Alert keys come
 *   from events, which a compromised application can fabricate, so without a
 *   cap an attacker could bury a real alert under thousands of fake ones.
 *   Beyond the cap, one flood notice is sent per window and the rest are counted.
 *
 * Suppressed alerts are never lost silently: the pipeline records the counts in
 * the audit log.
 */

export interface ThrottleOptions {
  /** Window length in seconds. Default 300. */
  windowSeconds?: number;
  /** Most distinct alerts sent per window. Default 20. */
  maxPerWindow?: number;
  /** Most alert keys remembered. Default 1000. */
  maxKeys?: number;
}

export type Admission =
  | { admit: true; suppressedBefore: number }
  | { admit: false; reason: 'duplicate' }
  | { admit: false; reason: 'flood'; floodNotice: boolean };

export class AlertThrottle {
  private readonly windowMs: number;
  private readonly maxPerWindow: number;
  private readonly maxKeys: number;
  private readonly keys = new Map<string, { start: number; suppressed: number }>();
  private windowStart = Number.NEGATIVE_INFINITY;
  private admittedInWindow = 0;
  private floodNoticeSent = false;

  constructor(options: ThrottleOptions = {}) {
    const windowSeconds = options.windowSeconds ?? 300;
    this.maxPerWindow = options.maxPerWindow ?? 20;
    this.maxKeys = options.maxKeys ?? 1000;
    if (!Number.isFinite(windowSeconds) || windowSeconds <= 0) throw new RangeError('windowSeconds must be positive');
    if (!Number.isInteger(this.maxPerWindow) || this.maxPerWindow < 1) throw new RangeError('maxPerWindow must be a whole number of at least 1');
    if (!Number.isInteger(this.maxKeys) || this.maxKeys < 1) throw new RangeError('maxKeys must be a whole number of at least 1');
    this.windowMs = windowSeconds * 1000;
  }

  admit(key: string, nowMs: number): Admission {
    if (nowMs - this.windowStart >= this.windowMs) {
      this.windowStart = nowMs;
      this.admittedInWindow = 0;
      this.floodNoticeSent = false;
    }

    const entry = this.keys.get(key);
    if (entry !== undefined && nowMs - entry.start < this.windowMs) {
      entry.suppressed++;
      return { admit: false, reason: 'duplicate' };
    }

    if (this.admittedInWindow >= this.maxPerWindow) {
      const floodNotice = !this.floodNoticeSent;
      this.floodNoticeSent = true;
      return { admit: false, reason: 'flood', floodNotice };
    }

    this.admittedInWindow++;
    this.keys.delete(key);
    this.keys.set(key, { start: nowMs, suppressed: 0 });
    while (this.keys.size > this.maxKeys) {
      const oldest = this.keys.keys().next();
      if (oldest.done === true) break;
      this.keys.delete(oldest.value);
    }
    return { admit: true, suppressedBefore: entry?.suppressed ?? 0 };
  }
}
