import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  AlertThrottle,
  AuditLog,
  Executor,
  Pipeline,
  actionDigest,
  createGatePolicy,
  createMasker,
  defaultRulesConfig,
  parseJsonLines,
  webrootNewExecutable,
  type AuditEntry,
  type ControlAdapter,
  type Notification,
  type PipelineOptions,
  type ProposedAction,
  type Rule,
  type RulesConfig,
} from '../src/index.js';
import { item, record, verified } from './helpers.js';

const NOW = new Date('2026-10-23T10:20:00Z');
const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

class Clock {
  private t = NOW.getTime();
  readonly now = (): Date => new Date(this.t);
  advance(seconds: number): void {
    this.t += seconds * 1000;
  }
}

class FakeAdapter implements ControlAdapter {
  applied: string[] = [];
  async apply(action: ProposedAction): Promise<{ handle: { rule: string } }> {
    this.applied.push(action.id);
    return { handle: { rule: `rule-${action.id}` } };
  }
  async revert(): Promise<void> {}
}

const config: RulesConfig = {
  ...defaultRulesConfig,
  webRoots: ['/var/www/html'],
  allowedWriters: ['deploy'],
  egressAllowList: { '*': ['api.example.invalid'] },
};

const panel = [
  { id: 'dog-a', model: 'model-x', evidenceView: 'raw-logs' },
  { id: 'dog-b', model: 'model-y', evidenceView: 'summaries' },
];
const approve2 = [
  { voter: 'dog-a', decision: 'approve' as const },
  { voter: 'dog-b', decision: 'approve' as const },
];
const split = [
  { voter: 'dog-a', decision: 'approve' as const },
  { voter: 'dog-b', decision: 'reject' as const },
];

let counter = 0;
/** An event as a sidecar would send it: no `masked` flag. */
function raw(attrs: Record<string, string | number | boolean>, overrides: Record<string, unknown> = {}) {
  counter++;
  return {
    id: `evt-${counter}`,
    ts: '2026-10-23T10:15:00Z',
    layer: 'application',
    service: 'shop-web',
    kind: 'file.created',
    attrs,
    ...overrides,
  };
}
const shell = (overrides: Record<string, unknown> = {}) =>
  raw({ path: '/var/www/html/uploads/x.php', actor: 'www-data' }, overrides);

function containment(overrides: Partial<ProposedAction> = {}): ProposedAction {
  return {
    id: 'act-1',
    proposedBy: 'dog-a',
    level: 3,
    kind: 'contain.rate-limit',
    target: 'shop-web:/upload',
    reason: 'Repeated executable uploads.',
    evidence: ['GD-EXAMPLE-0001'],
    createdAt: '2026-10-23T10:16:00Z',
    reversible: true,
    ttlSeconds: 900,
    votes: approve2,
    ...overrides,
  };
}

function setup(options: Partial<PipelineOptions> = {}, failAudit = false) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gd-pipe-'));
  dirs.push(dir);
  const clock = new Clock();
  const log = AuditLog.open(path.join(dir, 'audit.jsonl'), { clock: clock.now });
  const adapter = new FakeAdapter();
  const observer = new FakeAdapter();
  const sent: Notification[] = [];
  const executor = new Executor({
    policy: createGatePolicy({
      panel,
      preApproved: { 'contain.rate-limit': { maxTtlSeconds: 3600, targets: ['shop-web:*'] } },
      protectedTargets: ['guard-dog:*'],
      approvers: ['alice'],
    }),
    log,
    adapters: {
      'observe.raise-sampling': observer,
      'contain.rate-limit': adapter,
      'contain.block-source': adapter,
    },
    notifier: { notify: (n) => void sent.push(n) },
    clock: clock.now,
  });
  const audits: { actor: string; type: string; data: unknown }[] = [];
  const pipeline = new Pipeline({
    masker: createMasker({ pseudonymKey: 'k'.repeat(32) }),
    executor,
    log: {
      append: (input) => {
        if (failAudit) throw new Error('disk full');
        audits.push(input);
        return input as unknown as AuditEntry;
      },
    },
    inventory: [item()],
    allowedSources: ['example-advisory-feed'],
    rulesConfig: config,
    clock: clock.now,
    ...options,
  });
  return { pipeline, executor, adapter, observer, sent, audits, clock, log };
}

describe('parseJsonLines', () => {
  it('reads lines, ignores blanks and CRLF, and counts what it skips', () => {
    const text = '{"a":1}\r\n\n  \nnot json\n{"b":2}';
    const result = parseJsonLines(text);
    expect(result.items).toEqual([{ a: 1 }, { b: 2 }]);
    expect(result.skipped).toEqual({ tooLong: 0, invalid: 1, overLimit: 0 });
  });

  it('is bounded in lines and line length', () => {
    const result = parseJsonLines(`{"a":1}\n${'x'.repeat(50)}\n{"b":2}\n{"c":3}`, { maxLines: 3, maxLineLength: 20 });
    expect(result.items).toEqual([{ a: 1 }, { b: 2 }]);
    expect(result.skipped).toEqual({ tooLong: 1, invalid: 0, overLimit: 1 });
  });

  it('never throws on garbage, and does not let a __proto__ key pollute anything', () => {
    expect(() => parseJsonLines('\u0000\u0001{{{\n[[[\n"\ud800"')).not.toThrow();
    parseJsonLines('{"__proto__":{"polluted":true}}');
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
    expect(parseJsonLines('').items).toEqual([]);
  });
});

describe('AlertThrottle', () => {
  const T0 = 1_000_000;

  it('sends an alert once per window and reports the repeats at the next one', () => {
    const throttle = new AlertThrottle({ windowSeconds: 60 });
    expect(throttle.admit('a', T0)).toEqual({ admit: true, suppressedBefore: 0 });
    expect(throttle.admit('a', T0 + 1000)).toEqual({ admit: false, reason: 'duplicate' });
    expect(throttle.admit('a', T0 + 2000)).toEqual({ admit: false, reason: 'duplicate' });
    expect(throttle.admit('b', T0 + 3000)).toEqual({ admit: true, suppressedBefore: 0 });
    expect(throttle.admit('a', T0 + 61_000)).toEqual({ admit: true, suppressedBefore: 2 });
  });

  it('caps different alerts per window, with one flood notice, and resets next window', () => {
    const throttle = new AlertThrottle({ windowSeconds: 60, maxPerWindow: 2 });
    expect(throttle.admit('a', T0).admit).toBe(true);
    expect(throttle.admit('b', T0).admit).toBe(true);
    expect(throttle.admit('c', T0)).toEqual({ admit: false, reason: 'flood', floodNotice: true });
    expect(throttle.admit('d', T0)).toEqual({ admit: false, reason: 'flood', floodNotice: false });
    expect(throttle.admit('e', T0 + 61_000).admit).toBe(true);
    expect(throttle.admit('f', T0 + 61_000).admit).toBe(true);
    expect(throttle.admit('g', T0 + 61_000)).toMatchObject({ reason: 'flood', floodNotice: true });
  });

  it('forgets the oldest keys beyond its limit', () => {
    const throttle = new AlertThrottle({ windowSeconds: 60, maxPerWindow: 100, maxKeys: 2 });
    throttle.admit('a', T0);
    throttle.admit('b', T0);
    throttle.admit('c', T0);
    expect(throttle.admit('a', T0 + 1000).admit).toBe(true);
    expect(throttle.admit('c', T0 + 1000)).toEqual({ admit: false, reason: 'duplicate' });
  });

  it('rejects nonsense settings', () => {
    for (const bad of [{ windowSeconds: 0 }, { windowSeconds: Number.NaN }, { maxPerWindow: 0 }, { maxKeys: 1.5 }]) {
      expect(() => new AlertThrottle(bad)).toThrow(RangeError);
    }
  });
});

describe('pipeline: events', () => {
  it('turns a webshell upload into one alert and records the event as citable evidence', async () => {
    const { pipeline, sent, executor } = setup();
    const event = shell();
    const report = await pipeline.ingestEvents([event]);

    expect(report).toMatchObject({ received: 1, accepted: 1, rejected: 0, hits: 1, proposals: { applied: 1 } });
    expect(sent.map((n) => n.kind)).toEqual(['alert']);
    expect(sent[0]?.summary).toContain('[high] Executable file created in a web root on shop-web');
    expect(sent[0]?.summary).toContain('path=/var/www/html/uploads/x.php');
    expect(pipeline.knowsEvidence(event.id)).toBe(true);
    expect(executor.listPending()).toEqual([]);
  });

  it('says nothing and writes nothing for ordinary traffic', async () => {
    const { pipeline, sent, audits } = setup();
    const report = await pipeline.ingestEvents([raw({ path: '/var/www/html/uploads/photo.jpg' })]);

    expect(report).toMatchObject({ accepted: 1, hits: 0, proposals: {} });
    expect(sent).toEqual([]);
    expect(audits).toEqual([]);
  });

  it('masks every event itself and never believes a masked flag from the wire', async () => {
    const { pipeline, sent, audits } = setup();
    const event = shell({
      masked: true,
      attrs: {
        path: '/var/www/html/uploads/x.php?password=hunter2hunter2',
        actor: 'www-data',
        authorization: 'Bearer abcdefghijklmnop',
      },
    });
    const report = await pipeline.ingestEvents([event]);

    expect(report.masked).toMatchObject({ 'key-redacted': 1, 'secret-pair': 1 });
    const everythingSent = JSON.stringify([sent, audits]);
    expect(everythingSent).not.toContain('hunter2');
    expect(everythingSent).not.toContain('abcdefghijklmnop');
  });

  it('rejects malformed events without throwing, and keeps secrets out of the reasons', async () => {
    const { pipeline } = setup();
    const secret = 'sk-' + 'a'.repeat(30);
    const junk: unknown[] = [
      null,
      'text',
      42,
      [],
      {},
      { id: 'e-no-attrs', ts: '2026-10-23T10:15:00Z', layer: 'edge', service: 's', kind: 'http.request' },
      { id: 'e-attrs-array', attrs: [secret] },
      shell({ ts: 'yesterday', attrs: { token: secret, path: secret } }),
      shell({ attrs: { nested: { deep: secret } } }),
      shell({ layer: 'moon' }),
      shell(),
    ];
    const report = await pipeline.ingestEvents(junk);

    expect(report).toMatchObject({ received: 11, accepted: 1, rejected: 10, hits: 1 });
    expect(report.rejectedSamples).toHaveLength(5);
    expect(JSON.stringify(report)).not.toContain(secret);
  });

  it('sends one alert for repeats of the same thing, and says how many were held back', async () => {
    const { pipeline, sent, clock } = setup();
    const first = await pipeline.ingestEvents(Array.from({ length: 10 }, () => shell()));

    expect(first).toMatchObject({ hits: 10, suppressed: { duplicate: 9, flood: 0 }, proposals: { applied: 1 } });
    expect(sent).toHaveLength(1);

    clock.advance(301);
    await pipeline.ingestEvents([shell()]);
    expect(sent).toHaveLength(2);
    expect(sent[1]?.summary).toContain('9 similar alerts suppressed since the last one');
  });

  it('keeps different services and different rules apart', async () => {
    const { pipeline, sent } = setup();
    await pipeline.ingestEvents([
      shell(),
      shell({ service: 'billing' }),
      raw({ host: '203.0.113.9', actor: 'www-data' }, { kind: 'net.outbound' }),
    ]);
    expect(sent).toHaveLength(3);
  });

  it('cannot be buried under fabricated alerts: a cap, one flood notice, and the counts logged', async () => {
    const { pipeline, sent, audits } = setup({ throttle: { maxPerWindow: 3 } });
    const events = Array.from({ length: 8 }, (_, i) => shell({ service: `fake-${i}` }));
    const report = await pipeline.ingestEvents(events);

    expect(report.hits).toBe(8);
    expect(report.suppressed).toEqual({ duplicate: 0, flood: 5 });
    expect(report.proposals).toEqual({ applied: 4 });
    expect(sent).toHaveLength(4);
    expect(sent.at(-1)?.summary).toContain('More than 3 different alerts');
    expect(audits[0]?.data).toMatchObject({ hits: 8, suppressedFlood: 5 });
  });

  it('does not alert twice for an event it has already seen, even after the window', async () => {
    const { pipeline, sent, clock } = setup();
    const event = shell();
    await pipeline.ingestEvents([event]);
    clock.advance(1000);
    const again = await pipeline.ingestEvents([event]);

    expect(again.proposals).toEqual({ duplicate: 1 });
    expect(sent).toHaveLength(1);
  });

  it('survives a broken rule and still runs the others', async () => {
    const broken: Rule = {
      id: 'test.broken',
      description: 'always throws',
      evaluate() {
        throw new Error('boom');
      },
    };
    const { pipeline, sent } = setup({ rules: [broken, webrootNewExecutable] });
    const report = await pipeline.ingestEvents([shell()]);

    expect(report).toMatchObject({ ruleErrors: 1, hits: 1 });
    expect(sent).toHaveLength(1);
  });

  it('drops events beyond the batch limit and says so', async () => {
    const { pipeline, audits } = setup({ maxBatch: 10 });
    const report = await pipeline.ingestEvents(Array.from({ length: 12 }, () => raw({ path: '/x' })));

    expect(report).toMatchObject({ received: 12, dropped: 2, accepted: 10 });
    expect(audits[0]?.data).toMatchObject({ dropped: 2 });
  });

  it('writes counts to the audit log, never event content', async () => {
    const { pipeline, audits } = setup();
    await pipeline.ingestEvents([shell(), shell({ attrs: { path: '/var/www/html/up/y.php', actor: 'secretive-actor' } })]);

    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({ actor: 'pipeline', type: 'pipeline.events' });
    expect(JSON.stringify(audits)).not.toContain('/var/www/html');
    expect(JSON.stringify(audits)).not.toContain('secretive-actor');
  });

  it('still alerts when its own summary cannot be written', async () => {
    const { pipeline, sent } = setup({}, true);
    const report = await pipeline.ingestEvents([shell()]);

    expect(report.audited).toBe(false);
    expect(sent).toHaveLength(1);
  });

  it('remembers only so much evidence', async () => {
    const { pipeline } = setup({ maxKnownEvidence: 3 });
    const events = Array.from({ length: 5 }, () => raw({ path: '/x' }));
    await pipeline.ingestEvents(events);

    expect(events.map((e) => pipeline.knowsEvidence(e.id))).toEqual([false, false, true, true, true]);
  });
});

describe('pipeline: advisories', () => {
  it('alerts on an exposed service, asks for more sampling, and notes that a human has not verified it', async () => {
    const { pipeline, sent } = setup();
    const report = await pipeline.ingestAdvisories([record()]);

    expect(report).toMatchObject({ received: 1, findings: 1, rejected: 0, proposals: { applied: 2 } });
    const alert = sent.find((n) => n.kind === 'alert');
    expect(alert?.summary).toContain('high advisory GD-EXAMPLE-0001 affects example-lib 1.2.0 on shop-web, fixed in 1.4.2');
    expect(alert?.summary).toContain('Intel: from allow-listed source "example-advisory-feed", not human-verified');
    expect(pipeline.knowsEvidence('GD-EXAMPLE-0001')).toBe(true);
  });

  it('tells a human when a critical record is waiting for their verification', async () => {
    const { pipeline, sent } = setup();
    await pipeline.ingestAdvisories([record({ severity: 'critical' })]);

    expect(sent.find((n) => n.kind === 'alert')?.summary).toContain('Critical and unverified: a human must verify it');
  });

  it('ignores records that do not affect anything installed, and cites nothing for them', async () => {
    const { pipeline, sent } = setup();
    const report = await pipeline.ingestAdvisories([record({ fixed: '1.2.0' }), record({ id: 'GD-OTHER', package: 'other-lib' })]);

    expect(report.findings).toBe(0);
    expect(sent).toEqual([]);
    expect(pipeline.knowsEvidence('GD-OTHER')).toBe(false);
  });

  it('rejects unknown sources and malformed records without throwing', async () => {
    const { pipeline, sent } = setup();
    const report = await pipeline.ingestAdvisories([
      record({ source: 'random-blog' }),
      { id: 'GD-BAD' },
      null,
      'text',
    ]);

    expect(report).toMatchObject({ received: 4, findings: 0, rejected: 4 });
    expect(report.rejectedSamples.some((s) => s.reason.includes('allow-listed'))).toBe(true);
    expect(sent).toEqual([]);
  });

  it('does not repeat itself when the same feed is polled again, but speaks again when a record is verified', async () => {
    const { pipeline, sent } = setup();
    await pipeline.ingestAdvisories([record()]);
    const polled = await pipeline.ingestAdvisories([record()]);
    expect(polled.proposals).toEqual({ duplicate: 2 });
    expect(sent.filter((n) => n.kind === 'alert')).toHaveLength(1);

    await pipeline.ingestAdvisories([record({ verification: verified() })]);
    const alerts = sent.filter((n) => n.kind === 'alert');
    expect(alerts).toHaveLength(2);
    expect(alerts[1]?.summary).toContain('verified by reviewer@example.invalid');
  });

  it('speaks again when a record gets more serious or a fix appears, not when nothing changed', async () => {
    const { pipeline, sent } = setup();
    const alerts = () => sent.filter((n) => n.kind === 'alert').length;

    await pipeline.ingestAdvisories([record({ severity: 'medium', fixed: undefined })]);
    expect(alerts()).toBe(1);
    await pipeline.ingestAdvisories([record({ severity: 'medium', fixed: undefined })]);
    expect(alerts()).toBe(1);

    await pipeline.ingestAdvisories([record({ severity: 'high', fixed: undefined })]);
    expect(alerts()).toBe(2);
    await pipeline.ingestAdvisories([record({ severity: 'high', fixed: '1.4.2' })]);
    expect(alerts()).toBe(3);
  });

  it('forgets the ceiling of a record when it forgets the record', async () => {
    const { pipeline } = setup({ maxKnownEvidence: 3 });
    await pipeline.ingestAdvisories([record({ id: 'GD-1' }), record({ id: 'GD-2' }), record({ id: 'GD-3' })]);
    expect(pipeline.stats()).toEqual({ knownEvidence: 3, ceilings: 3 });

    await pipeline.ingestEvents(Array.from({ length: 5 }, () => raw({ path: '/x' })));
    expect(pipeline.stats()).toEqual({ knownEvidence: 3, ceilings: 0 });
    expect(pipeline.knowsEvidence('GD-1')).toBe(false);
  });
});

describe('pipeline: proposals from investigators', () => {
  it('gives the gate the evidence it knows and the ceiling each record allows', async () => {
    const { pipeline, adapter, executor } = setup();
    await pipeline.ingestAdvisories([record()]);

    // Unverified intel allows only an alert, so containment waits for a human.
    const held = await pipeline.submit(containment());
    expect(held.status).toBe('pending-human');
    expect(held.decision?.codes).toContain('above-intel-ceiling');
    expect(adapter.applied).toEqual([]);

    // Once a human has verified the record, the ceiling rises and a new proposal can run.
    await pipeline.ingestAdvisories([record({ verification: verified() })]);
    const ran = await pipeline.submit(containment({ id: 'act-2' }));
    expect(ran.status).toBe('applied');
    expect(adapter.applied).toContain('act-2');
    expect(executor.listActive().map((a) => a.actionId)).toContain('act-2');
  });

  it('denies containment that cites evidence the pipeline never saw', async () => {
    const { pipeline, adapter } = setup();
    await pipeline.ingestAdvisories([record({ verification: verified() })]);

    const invented = await pipeline.submit(containment({ evidence: ['GD-EXAMPLE-0001', 'evt-never-seen'] }));
    expect(invented.status).toBe('denied');
    expect(invented.decision?.codes).toContain('unknown-evidence');
    expect(adapter.applied).toEqual([]);
  });

  it('does not let a record that does not affect the inventory justify containment', async () => {
    const { pipeline } = setup();
    await pipeline.ingestAdvisories([record({ id: 'GD-OTHER', package: 'other-lib', verification: verified() })]);
    const result = await pipeline.submit(containment({ evidence: ['GD-OTHER'] }));

    expect(result.decision?.codes).toContain('unknown-evidence');
  });

  it('judges a waiting proposal on what was known when it was made, even after evidence ages out', async () => {
    const { pipeline, executor, adapter, clock } = setup({ maxKnownEvidence: 3 });
    const [event] = [shell()];
    await pipeline.ingestEvents([event]);

    const action = containment({ id: 'act-split', evidence: [event.id], votes: split });
    expect((await pipeline.submit(action)).status).toBe('pending-human');

    await pipeline.ingestEvents(Array.from({ length: 5 }, () => raw({ path: '/x' })));
    expect(pipeline.knowsEvidence(event.id)).toBe(false);

    const approved = await executor.approve('act-split', {
      approver: 'alice',
      approvedAt: clock.now().toISOString(),
      actionDigest: actionDigest(action),
    });
    expect(approved.status).toBe('applied');
    expect(adapter.applied).toEqual(['act-split']);
  });

  it('passes malformed proposals on to be denied, without throwing', async () => {
    const { pipeline } = setup();
    for (const junk of [null, 'x', 42, {}, { evidence: 'not-a-list' }, { evidence: [1, null, {}] }, { evidence: Array(500).fill('e') }]) {
      expect((await pipeline.submit(junk)).status).toBe('denied');
    }
  });
});
