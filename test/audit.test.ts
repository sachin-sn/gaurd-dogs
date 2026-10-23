import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AuditLog, AuditTamperError, GENESIS_HASH, canonicalize, hashEntry } from '../src/index.js';

let dir: string;
let file: string;
let tick: number;
const clock = () => new Date(Date.UTC(2026, 9, 23, 10, 0, tick++));

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-dogs-audit-'));
  file = path.join(dir, 'run.audit.jsonl');
  tick = 0;
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function seed(count = 4): AuditLog {
  const log = AuditLog.open(file, { clock });
  for (let i = 0; i < count; i++) {
    log.append({ actor: 'dog-a', type: 'finding', data: { n: i, note: `entry ${i}` } });
  }
  return log;
}

const readLines = () => fs.readFileSync(file, 'utf8').trimEnd().split('\n');
const writeLines = (lines: string[]) => fs.writeFileSync(file, `${lines.join('\n')}\n`);

describe('AuditLog', () => {
  it('chains entries from a genesis hash', () => {
    const log = seed(3);
    const entries = log.entries();
    expect(entries.map((e) => e.seq)).toEqual([0, 1, 2]);
    expect(entries[0]?.prev).toBe(GENESIS_HASH);
    expect(entries[1]?.prev).toBe(entries[0]?.hash);
    expect(entries[2]?.prev).toBe(entries[1]?.hash);
    expect(log.verify()).toMatchObject({ ok: true, entries: 3 });
  });

  it('resumes the chain when reopened', () => {
    seed(2);
    const reopened = AuditLog.open(file, { clock });
    const next = reopened.append({ actor: 'dog-b', type: 'alert', data: null });
    expect(next.seq).toBe(2);
    expect(reopened.verify().ok).toBe(true);
  });

  it('produces hashes that can be recomputed from the canonical form', () => {
    const log = seed(1);
    const [entry] = log.entries();
    const { hash, ...rest } = entry!;
    expect(hashEntry(rest)).toBe(hash);
  });

  it('writes the file with owner-only permissions', () => {
    seed(1);
    expect(fs.statSync(file).mode & 0o077).toBe(0);
  });

  describe('tamper detection', () => {
    it('detects an edited entry', () => {
      seed();
      const lines = readLines();
      lines[1] = lines[1]!.replace('entry 1', 'entry X');
      writeLines(lines);
      expect(() => AuditLog.open(file)).toThrow(AuditTamperError);
      expect(() => AuditLog.open(file)).toThrow(/entry 1.*modified/);
    });

    it('detects a deleted entry', () => {
      seed();
      const lines = readLines();
      lines.splice(1, 1);
      writeLines(lines);
      expect(() => AuditLog.open(file)).toThrow(/entry 1/);
    });

    it('detects reordered entries', () => {
      seed();
      const lines = readLines();
      [lines[1], lines[2]] = [lines[2]!, lines[1]!];
      writeLines(lines);
      expect(() => AuditLog.open(file)).toThrow(AuditTamperError);
    });

    it('detects an entry re-hashed after editing because the next link breaks', () => {
      seed();
      const lines = readLines();
      const forged = JSON.parse(lines[1]!) as Record<string, unknown>;
      forged['data'] = { n: 1, note: 'forged' };
      const { hash: _old, ...rest } = forged;
      forged['hash'] = hashEntry(rest as Parameters<typeof hashEntry>[0]);
      lines[1] = canonicalize(forged);
      writeLines(lines);
      // Entry 1 now verifies on its own, but entry 2 still points at the old hash.
      expect(() => AuditLog.open(file)).toThrow(/entry 2.*prev/);
    });

    it('detects a partial last line from a crashed write', () => {
      seed();
      fs.appendFileSync(file, '{"seq":4,"ts":"2026-10-23T10:00:09.000Z"');
      expect(() => AuditLog.open(file)).toThrow(/partial write/);
    });

    it('detects lines that are not audit entries at all', () => {
      seed();
      fs.appendFileSync(file, '{"hello":"world"}\n');
      expect(() => AuditLog.open(file)).toThrow(AuditTamperError);
    });
  });

  describe('anchoring', () => {
    it('only detects truncation of the tail when an external anchor is supplied', () => {
      const log = seed(4);
      const anchor = log.head()!;
      writeLines(readLines().slice(0, 2));

      const reopened = AuditLog.open(file, { clock });
      expect(reopened.verify().ok).toBe(true); // a shorter chain is still internally consistent
      expect(reopened.verify({ anchor })).toMatchObject({ ok: false });
    });

    it('detects a fully rewritten chain against the anchor', () => {
      const log = seed(3);
      const anchor = log.head()!;
      fs.rmSync(file);
      tick = 0;
      const rewritten = AuditLog.open(file, { clock });
      for (let i = 0; i < 3; i++) rewritten.append({ actor: 'attacker', type: 'finding', data: { n: i } });
      expect(rewritten.verify().ok).toBe(true);
      expect(rewritten.verify({ anchor })).toMatchObject({ ok: false });
    });

    it('accepts the genuine log against its own anchor, including after more appends', () => {
      const log = seed(2);
      const anchor = log.head()!;
      log.append({ actor: 'dog-a', type: 'alert', data: [] });
      expect(log.verify({ anchor })).toMatchObject({ ok: true, entries: 3 });
    });
  });

  describe('payloads', () => {
    it('rejects data that is not plain JSON', () => {
      const log = AuditLog.open(file, { clock });
      expect(() => log.append({ actor: 'a', type: 't', data: { v: Number.NaN } })).toThrow(TypeError);
      expect(() => log.append({ actor: 'a', type: 't', data: { v: undefined } as never })).toThrow(TypeError);
      expect(() => log.append({ actor: 'a', type: 't', data: new Date() as never })).toThrow(TypeError);
      expect(fs.existsSync(file)).toBe(false);
    });

    it('canonicalizes independently of key order', () => {
      expect(canonicalize({ b: 1, a: { d: [1, 2], c: 'x' } })).toBe('{"a":{"c":"x","d":[1,2]},"b":1}');
    });

    it('keeps hostile strings inert: one entry stays one line', () => {
      const log = AuditLog.open(file, { clock });
      log.append({ actor: 'dog-a', type: 'finding', data: { path: 'x\n{"seq":99}\r\n' } });
      expect(readLines()).toHaveLength(1);
      expect(log.verify().ok).toBe(true);
    });
  });
});
