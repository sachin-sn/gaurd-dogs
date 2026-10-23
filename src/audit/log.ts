import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { validateAuditEntry } from '../core/validate.js';
import type { JsonValue } from '../core/types.js';

export const GENESIS_HASH = '0'.repeat(64);

export interface AuditEntry {
  seq: number;
  ts: string;
  actor: string;
  type: string;
  data: JsonValue;
  prev: string;
  hash: string;
}

export interface AuditHead {
  seq: number;
  hash: string;
}

export type VerifyResult =
  | { ok: true; entries: number; head: AuditHead | null }
  | { ok: false; seq: number; reason: string };

export class AuditTamperError extends Error {
  constructor(
    readonly seq: number,
    reason: string,
  ) {
    super(`audit log failed verification at entry ${seq}: ${reason}`);
    this.name = 'AuditTamperError';
  }
}

/**
 * Canonical JSON: object keys sorted, no whitespace. Matches RFC 8785 for the
 * value space used here, so other languages can reproduce the same bytes.
 * Throws on anything that is not plain JSON (undefined, NaN, Infinity, functions).
 */
export function canonicalize(value: unknown): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'string':
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) throw new TypeError('audit data must not contain NaN or Infinity');
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) return `[${value.map((v) => canonicalize(v)).join(',')}]`;
      const proto: unknown = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) {
        throw new TypeError('audit data must be plain JSON objects');
      }
      const record = value as Record<string, unknown>;
      const keys = Object.keys(record).sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(record[k])}`).join(',')}}`;
    }
    default:
      throw new TypeError(`audit data must be plain JSON, got ${typeof value}`);
  }
}

export function hashEntry(entry: Omit<AuditEntry, 'hash'>): string {
  return createHash('sha256').update(canonicalize(entry), 'utf8').digest('hex');
}

export interface AuditLogOptions {
  /** Injectable clock for deterministic tests. */
  clock?: () => Date;
}

/**
 * Append-only, hash-chained audit log stored as JSON Lines.
 *
 * What this gives you: editing, deleting, inserting or reordering entries in
 * the middle of the file is detected by `verify()`.
 *
 * What it does not give you: protection against truncating the end of the
 * file, or against someone rewriting the whole chain. For that, copy `head()`
 * somewhere the log writer cannot reach (a human, another host, a write-once
 * store) and pass it back as `anchor` when verifying. In deployment, also make
 * the file append-only at the OS level and keep it out of the monitored
 * service's reach.
 *
 * Single writer per file is assumed.
 */
export class AuditLog {
  private readonly clock: () => Date;
  private last: AuditHead | null = null;

  private constructor(
    readonly path: string,
    options: AuditLogOptions,
  ) {
    this.clock = options.clock ?? (() => new Date());
  }

  /** Open a log, creating it if missing. Throws AuditTamperError if an existing file fails verification. */
  static open(path: string, options: AuditLogOptions = {}): AuditLog {
    const log = new AuditLog(path, options);
    if (fs.existsSync(path)) {
      const result = log.verify();
      if (!result.ok) throw new AuditTamperError(result.seq, result.reason);
      log.last = result.head;
    }
    return log;
  }

  head(): AuditHead | null {
    return this.last === null ? null : { ...this.last };
  }

  append(input: { actor: string; type: string; data: JsonValue }): AuditEntry {
    const base: Omit<AuditEntry, 'hash'> = {
      seq: this.last === null ? 0 : this.last.seq + 1,
      ts: this.clock().toISOString(),
      actor: input.actor,
      type: input.type,
      data: input.data,
      prev: this.last === null ? GENESIS_HASH : this.last.hash,
    };
    const entry: AuditEntry = { ...base, hash: hashEntry(base) };
    const checked = validateAuditEntry(entry);
    if (!checked.ok) throw new TypeError(`invalid audit entry: ${checked.errors.join('; ')}`);

    const fd = fs.openSync(this.path, 'a', 0o600);
    try {
      fs.writeSync(fd, `${canonicalize(entry)}\n`);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    this.last = { seq: entry.seq, hash: entry.hash };
    return entry;
  }

  entries(): AuditEntry[] {
    return this.readLines().map((line) => JSON.parse(line) as AuditEntry);
  }

  /**
   * Re-read the file from disk and check every link. Pass `anchor` (a `head()`
   * taken earlier and stored elsewhere) to also catch truncation and rewrites.
   */
  verify(options: { anchor?: AuditHead } = {}): VerifyResult {
    let lines: string[];
    try {
      lines = this.readLines();
    } catch (error) {
      return { ok: false, seq: 0, reason: error instanceof Error ? error.message : String(error) };
    }

    let prev = GENESIS_HASH;
    let head: AuditHead | null = null;
    const hashes: string[] = [];

    for (const [index, line] of lines.entries()) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch {
        return { ok: false, seq: index, reason: 'line is not valid JSON (possibly a partial write)' };
      }
      const checked = validateAuditEntry(parsed);
      if (!checked.ok) return { ok: false, seq: index, reason: `schema: ${checked.errors.join('; ')}` };
      const entry = checked.value as AuditEntry;

      if (entry.seq !== index) {
        return { ok: false, seq: index, reason: `expected seq ${index} but found ${entry.seq} (entry removed, inserted or reordered)` };
      }
      if (entry.prev !== prev) {
        return { ok: false, seq: index, reason: 'prev does not match the previous entry hash' };
      }
      const { hash, ...rest } = entry;
      let recomputed: string;
      try {
        recomputed = hashEntry(rest);
      } catch (error) {
        return { ok: false, seq: index, reason: error instanceof Error ? error.message : String(error) };
      }
      if (recomputed !== hash) {
        return { ok: false, seq: index, reason: 'hash does not match entry contents (entry was modified)' };
      }
      prev = hash;
      hashes.push(hash);
      head = { seq: entry.seq, hash };
    }

    const anchor = options.anchor;
    if (anchor !== undefined) {
      if (head === null || head.seq < anchor.seq) {
        return { ok: false, seq: head === null ? 0 : head.seq + 1, reason: `log is shorter than the anchor at seq ${anchor.seq} (tail removed)` };
      }
      if (hashes[anchor.seq] !== anchor.hash) {
        return { ok: false, seq: anchor.seq, reason: 'entry at the anchor seq does not match the anchored hash (log was rewritten)' };
      }
    }

    return { ok: true, entries: lines.length, head };
  }

  private readLines(): string[] {
    if (!fs.existsSync(this.path)) return [];
    const text = fs.readFileSync(this.path, 'utf8');
    if (text.length === 0) return [];
    // A well-formed file ends with a newline. A missing one means a partial write.
    const lines = text.split('\n');
    const last = lines.pop();
    if (last !== '') lines.push(last ?? '');
    return lines;
  }
}
