import { createHmac } from 'node:crypto';
import { isIP } from 'node:net';
import type { GuardDogEvent } from '../core/types.js';
import { validateEvent } from '../core/validate.js';

/**
 * Log masking. Secrets and personal data are removed before an event leaves
 * the host, and before any model sees it.
 *
 * Design choices:
 * - Failing safe means over-masking. A few harmless strings may be masked; a
 *   secret should not slip through. Patterns are heuristics, not a guarantee.
 * - Client IP addresses are replaced by a keyed pseudonym, so the same address
 *   still correlates across events without being revealed. Destination hosts
 *   (such as the `host` attribute) are kept as they are, because the drift
 *   rules need them.
 * - Reports count what was masked and never include the masked values.
 * - Only `maskEvent` produces `masked: true`, and only for an event that is
 *   valid against the schema.
 */

export type MaskKind =
  | 'key-redacted'
  | 'private-key'
  | 'jwt'
  | 'cloud-key'
  | 'service-token'
  | 'bearer'
  | 'credential-url'
  | 'secret-pair'
  | 'email'
  | 'card'
  | 'ip'
  | 'truncated';

export type MaskReport = Partial<Record<MaskKind, number>>;

export interface MaskerOptions {
  /** Secret key for IP pseudonyms. At least 16 bytes. Keep it out of logs and out of model prompts. */
  pseudonymKey: string | Uint8Array;
  /** Attribute names (compared case-insensitively, ignoring - _ .) whose whole value is replaced. */
  redactKeyTerms?: readonly string[];
  /** Attributes whose IP addresses are kept as they are, such as destination hosts. Default: ['host']. */
  keepIpKeys?: readonly string[];
  /** Longest value kept after masking. Default 2048, the schema limit. */
  maxValueLength?: number;
}

export type UnmaskedEvent = Omit<GuardDogEvent, 'masked'>;

export interface Masker {
  maskText(text: string, options?: { keepIps?: boolean }): { text: string; report: MaskReport };
  maskEvent(event: UnmaskedEvent): { event: GuardDogEvent; report: MaskReport };
}

export const defaultRedactKeyTerms: readonly string[] = [
  'password',
  'passwd',
  'pwd',
  'secret',
  'token',
  'apikey',
  'accesskey',
  'authorization',
  'cookie',
  'sessionid',
  'credential',
  'privatekey',
];

const REDACTED = '[redacted]';

/** Longest input examined by the patterns. Bounds the cost of a hostile, huge value. */
const HARD_CAP = 65_536;

const PRIVATE_KEY =
  /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----[\s\S]{0,8192}?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|$)/g;
const JWT = /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g;
const CLOUD_KEY = /\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}/g;
const SERVICE_TOKEN =
  /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35})/g;
const BEARER = /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi;
const CREDENTIAL_URL = /\b([a-z][a-z0-9+.-]{1,20}:\/\/)[^\s/@:]+:[^\s/@]+@/gi;
const SECRET_PAIR =
  /\b(password|passwd|pwd|secret|client[_-]?secret|token|access[_-]?token|refresh[_-]?token|api[_-]?key|access[_-]?key|session[_-]?id)(["']?\s*[=:]\s*)(?!\[redacted\])("[^"]*"|'[^']*'|[^\s&;,"']+)/gi;
const EMAIL = /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8}/g;
const CARD = /\b(?:\d[ -]?){12,18}\d\b/g;
const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const IPV6 = /(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])/g;

function luhnValid(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[-_.\s]/g, '');
}

function bump(report: MaskReport, kind: MaskKind, by = 1): void {
  report[kind] = (report[kind] ?? 0) + by;
}

export function createMasker(options: MaskerOptions): Masker {
  const keyBytes =
    typeof options.pseudonymKey === 'string' ? Buffer.from(options.pseudonymKey, 'utf8') : Buffer.from(options.pseudonymKey);
  if (keyBytes.length < 16) {
    throw new RangeError('pseudonymKey must be at least 16 bytes');
  }
  const redactTerms = (options.redactKeyTerms ?? defaultRedactKeyTerms).map(normalizeKey);
  const keepIpKeys = new Set(options.keepIpKeys ?? ['host']);
  const maxValueLength = options.maxValueLength ?? 2048;

  const pseudonym = (ip: string): string =>
    `ip_${createHmac('sha256', keyBytes).update(ip.toLowerCase()).digest('hex').slice(0, 12)}`;

  function maskText(input: string, opts: { keepIps?: boolean } = {}): { text: string; report: MaskReport } {
    const report: MaskReport = {};
    let text = input;

    if (text.length > HARD_CAP) {
      text = text.slice(0, HARD_CAP);
      bump(report, 'truncated');
    }

    const swap = (kind: MaskKind, pattern: RegExp, replacement: string | ((...m: string[]) => string)) => {
      text = text.replace(pattern, (...args: unknown[]) => {
        bump(report, kind);
        const groups = args.slice(0, -2) as string[];
        return typeof replacement === 'function' ? replacement(...groups) : replacement;
      });
    };

    swap('private-key', PRIVATE_KEY, '[private-key]');
    swap('jwt', JWT, '[jwt]');
    swap('cloud-key', CLOUD_KEY, '[cloud-key]');
    swap('service-token', SERVICE_TOKEN, '[service-token]');
    swap('bearer', BEARER, (_all, scheme) => `${scheme} ${REDACTED}`);
    swap('credential-url', CREDENTIAL_URL, (_all, scheme) => `${scheme}${REDACTED}@`);
    swap('secret-pair', SECRET_PAIR, (_all, key, sep) => `${key}${sep}${REDACTED}`);
    swap('email', EMAIL, '[email]');

    text = text.replace(CARD, (match) => {
      const digits = match.replace(/\D/g, '');
      if (digits.length < 13 || digits.length > 19 || !luhnValid(digits)) return match;
      bump(report, 'card');
      return '[card]';
    });

    if (opts.keepIps !== true) {
      text = text.replace(IPV4, (match) => {
        if (isIP(match) !== 4) return match;
        bump(report, 'ip');
        return pseudonym(match);
      });
      text = text.replace(IPV6, (match) => {
        if (isIP(match) !== 6) return match;
        bump(report, 'ip');
        return pseudonym(match);
      });
    }

    if (text.length > maxValueLength) {
      text = text.slice(0, maxValueLength);
      bump(report, 'truncated');
    }
    return { text, report };
  }

  function maskEvent(event: UnmaskedEvent): { event: GuardDogEvent; report: MaskReport } {
    const report: MaskReport = {};
    const attrs: GuardDogEvent['attrs'] = {};

    for (const [key, value] of Object.entries(event.attrs)) {
      const normalized = normalizeKey(key);
      if (redactTerms.some((term) => normalized.includes(term))) {
        attrs[key] = REDACTED;
        bump(report, 'key-redacted');
        continue;
      }
      if (typeof value !== 'string') {
        attrs[key] = value;
        continue;
      }
      const masked = maskText(value, { keepIps: keepIpKeys.has(key) });
      attrs[key] = masked.text;
      for (const [kind, count] of Object.entries(masked.report) as [MaskKind, number][]) {
        bump(report, kind, count);
      }
    }

    const candidate: GuardDogEvent = {
      id: event.id,
      ts: event.ts,
      layer: event.layer,
      service: event.service,
      kind: event.kind,
      ...(event.traceId === undefined ? {} : { traceId: event.traceId }),
      attrs,
      masked: true,
    };

    const checked = validateEvent(candidate);
    if (!checked.ok) {
      // The message names schema paths only, never values.
      throw new TypeError(`event is not valid after masking: ${checked.errors.join('; ')}`);
    }
    return { event: checked.value, report };
  }

  return { maskText, maskEvent };
}
