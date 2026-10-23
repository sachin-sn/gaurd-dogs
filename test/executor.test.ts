import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  AuditLog,
  AuditTamperError,
  Executor,
  actionDigest,
  createGatePolicy,
  evaluateAction,
  type ActionKind,
  type AuditSink,
  type ControlAdapter,
  type ExecutorOptions,
  type GatePolicyInput,
  type HumanApproval,
  type Notification,
  type ProposedAction,
} from '../src/index.js';

const NOW = new Date('2026-10-23T10:20:00Z');
const KINDS: ActionKind[] = [
  'observe.raise-sampling',
  'alert.notify',
  'contain.rate-limit',
  'contain.block-source',
  'contain.quarantine-file',
  'contain.isolate-service',
];

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
  applyCalls: string[] = [];
  revertCalls: string[] = [];
  failApply = false;
  failRevert = false;
  applyHold: Promise<void> | null = null;
  revertHold: Promise<void> | null = null;

  async apply(action: ProposedAction): Promise<{ handle: { rule: string } }> {
    this.applyCalls.push(action.id);
    if (this.applyHold !== null) await this.applyHold;
    if (this.failApply) throw new Error('firewall unreachable');
    return { handle: { rule: `rule-${action.id}` } };
  }

  async revert(_handle: unknown, info: { actionId: string }): Promise<void> {
    this.revertCalls.push(info.actionId);
    if (this.revertHold !== null) await this.revertHold;
    if (this.failRevert) throw new Error('firewall unreachable');
  }
}

function policy(overrides: Partial<GatePolicyInput> = {}) {
  return createGatePolicy({
    panel: [
      { id: 'dog-a', model: 'model-x', evidenceView: 'raw-logs' },
      { id: 'dog-b', model: 'model-y', evidenceView: 'summaries' },
    ],
    preApproved: {
      'contain.rate-limit': { maxTtlSeconds: 3600, targets: ['shop-web:*'] },
      'contain.block-source': { maxTtlSeconds: 1800, targets: ['shop-web:*'] },
    },
    protectedTargets: ['guard-dog:*', 'audit:*'],
    approvers: ['alice'],
    ...overrides,
  });
}

const approve2 = [
  { voter: 'dog-a', decision: 'approve' as const },
  { voter: 'dog-b', decision: 'approve' as const },
];

function level3(overrides: Partial<ProposedAction> = {}): ProposedAction {
  return {
    id: 'act-1',
    proposedBy: 'dog-a',
    level: 3,
    kind: 'contain.rate-limit',
    target: 'shop-web:/upload',
    reason: 'Repeated executable uploads from one source in two minutes.',
    evidence: ['evt-1'],
    createdAt: '2026-10-23T10:16:00Z',
    reversible: true,
    ttlSeconds: 900,
    votes: approve2,
    ...overrides,
  };
}

function level4(overrides: Partial<ProposedAction> = {}): ProposedAction {
  return {
    id: 'act-4',
    proposedBy: 'dog-a',
    level: 4,
    kind: 'contain.isolate-service',
    target: 'shop-web',
    reason: 'Active compromise suspected.',
    evidence: ['evt-1'],
    createdAt: '2026-10-23T10:16:00Z',
    requiresHumanApproval: true,
    votes: approve2,
    ...overrides,
  };
}

function alertAction(overrides: Partial<ProposedAction> = {}): ProposedAction {
  return {
    id: 'act-l2',
    proposedBy: 'dog-a',
    level: 2,
    kind: 'alert.notify',
    target: 'shop-web',
    reason: 'Unusual outbound call.',
    evidence: ['evt-1'],
    createdAt: '2026-10-23T10:16:00Z',
    ...overrides,
  };
}

function approval(action: ProposedAction, clock: Clock, overrides: Partial<HumanApproval> = {}): HumanApproval {
  return {
    approver: 'alice',
    approvedAt: clock.now().toISOString(),
    actionDigest: actionDigest(action),
    ...overrides,
  };
}

function flakySink(log: AuditLog, failOn: (type: string) => boolean): AuditSink {
  return {
    append: (input) => {
      if (failOn(input.type)) throw new Error('disk full');
      return log.append(input);
    },
    entries: () => log.entries(),
    verify: (options) => log.verify(options),
  };
}

function setup(options: Partial<ExecutorOptions> & { sink?: (log: AuditLog) => AuditSink } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gd-exec-'));
  dirs.push(dir);
  const file = path.join(dir, 'audit.jsonl');
  const clock = new Clock();
  const log = AuditLog.open(file, { clock: clock.now });
  const adapter = new FakeAdapter();
  const sent: Notification[] = [];
  const adapters = Object.fromEntries(KINDS.filter((k) => k !== 'alert.notify').map((kind) => [kind, adapter]));
  const { sink, ...rest } = options;
  const build = (over: Partial<ExecutorOptions> = {}) =>
    new Executor({
      policy: policy(),
      log: sink === undefined ? log : sink(log),
      adapters,
      notifier: { notify: (n) => void sent.push(n) },
      clock: clock.now,
      ...rest,
      ...over,
    });
  const exec = build();
  const types = () => log.entries().map((entry) => entry.type);
  return { exec, build, log, file, clock, adapter, sent, types, adapters };
}

describe('executor: running cleared actions', () => {
  it('applies a cleared level 3 action and records decision, intent and result in that order', async () => {
    const { exec, adapter, types, clock } = setup();
    const result = await exec.submit(level3());

    expect(result.status).toBe('applied');
    expect(adapter.applyCalls).toEqual(['act-1']);
    expect(types()).toEqual(['gate.decision', 'containment.applying', 'containment.applied']);

    const [active] = exec.listActive();
    expect(active?.actionId).toBe('act-1');
    expect(active?.expiresAt).toBe(new Date(clock.now().getTime() + 900_000).toISOString());
  });

  it('sends alerts without a control and tells the human once, as an alert', async () => {
    const { exec, sent, adapter } = setup({ adapters: {} });
    const result = await exec.submit(alertAction());

    expect(result.status).toBe('applied');
    expect(adapter.applyCalls).toEqual([]);
    expect(sent.map((n) => n.kind)).toEqual(['alert']);
  });

  it('uses a control for level 1 observe actions, and they do not use up the containment budget', async () => {
    const { exec, adapter } = setup({ budget: { maxActive: 1 } });
    const observe: ProposedAction = { ...alertAction({ id: 'act-l1', level: 1, kind: 'observe.raise-sampling' }) };

    expect((await exec.submit(observe)).status).toBe('applied');
    expect((await exec.submit(level3())).status).toBe('applied');
    expect(adapter.applyCalls).toEqual(['act-l1', 'act-1']);
  });

  it('denies what the gate denies and touches nothing', async () => {
    const { exec, adapter, sent } = setup();
    const rejected = level3({
      votes: [
        { voter: 'dog-a', decision: 'reject' },
        { voter: 'dog-b', decision: 'reject' },
      ],
    });
    const result = await exec.submit(rejected);

    expect(result.status).toBe('denied');
    expect(adapter.applyCalls).toEqual([]);
    expect(exec.listActive()).toEqual([]);
    expect(sent).toHaveLength(1);
  });

  it('denies malformed input without throwing', async () => {
    const { exec, adapter } = setup();
    for (const junk of [null, undefined, 42, 'x', [], {}, { id: 'a' }]) {
      expect((await exec.submit(junk)).status).toBe('denied');
    }
    expect(adapter.applyCalls).toEqual([]);
  });

  it('reports a missing control instead of silently doing nothing', async () => {
    const { exec, sent, types } = setup({ adapters: {} });
    const result = await exec.submit(level3());

    expect(result.status).toBe('no-adapter');
    expect(sent.map((n) => n.kind)).toEqual(['decision', 'apply-failed']);
    expect(types()).toContain('executor.no-adapter');
    expect((await exec.submit(level3())).status).toBe('duplicate');
  });

  it('records a failed apply, frees its budget slot, and tells a human', async () => {
    const { exec, adapter, sent, types } = setup();
    adapter.failApply = true;
    const failed = await exec.submit(level3());

    expect(failed.status).toBe('apply-failed');
    expect(exec.listActive()).toEqual([]);
    expect(types()).toEqual(['gate.decision', 'containment.applying', 'containment.apply-failed']);
    expect(sent.map((n) => n.kind)).toContain('apply-failed');

    adapter.failApply = false;
    expect((await exec.submit(level3({ id: 'act-2' }))).status).toBe('applied');
  });
});

describe('executor: audit first, fail closed', () => {
  it('does nothing when the decision cannot be logged', async () => {
    const { exec, adapter, sent } = setup({ sink: (log) => flakySink(log, () => true) });
    const result = await exec.submit(level3());

    expect(result.status).toBe('audit-failed');
    expect(adapter.applyCalls).toEqual([]);
    expect(sent.map((n) => n.kind)).toEqual(['audit-failed']);
  });

  it('does nothing when the intent to act cannot be logged', async () => {
    const { exec, adapter, types } = setup({ sink: (log) => flakySink(log, (t) => t === 'containment.applying') });
    const result = await exec.submit(level3());

    expect(result.status).toBe('audit-failed');
    expect(adapter.applyCalls).toEqual([]);
    expect(types()).toEqual(['gate.decision']);
  });

  it('undoes a change that was applied but could not be recorded', async () => {
    const { exec, adapter, sent } = setup({ sink: (log) => flakySink(log, (t) => t === 'containment.applied') });
    const result = await exec.submit(level3());

    expect(result.status).toBe('audit-failed');
    expect(adapter.applyCalls).toEqual(['act-1']);
    expect(adapter.revertCalls).toEqual(['act-1']);
    expect(exec.listActive()).toEqual([]);
    expect(sent.at(-1)?.summary).toContain('was undone');
  });

  it('says so loudly when it also cannot undo that change', async () => {
    const { exec, adapter, sent } = setup({ sink: (log) => flakySink(log, (t) => t === 'containment.applied') });
    adapter.failRevert = true;
    await exec.submit(level3());

    expect(sent.at(-1)?.summary).toContain('undoing it failed');
  });

  it('keeps working when the notifier throws, and logs that it did', async () => {
    const { exec, adapter, types } = setup({
      notifier: {
        notify: () => {
          throw new Error('smtp down');
        },
      },
    });
    expect((await exec.submit(level3())).status).toBe('applied');
    expect(adapter.applyCalls).toHaveLength(1);
    expect(types()).toContain('executor.notify-failed');
  });

  it('does not hang on a notifier that never answers', async () => {
    const { exec, types } = setup({
      notifier: { notify: () => new Promise<void>(() => undefined) },
      notifyTimeoutMs: 20,
    });
    expect((await exec.submit(level3())).status).toBe('applied');
    expect(types()).toContain('executor.notify-failed');
  });
});

describe('executor: expiry, revert and revoke', () => {
  it('reverts a containment only once it has expired', async () => {
    const { exec, adapter, clock, types } = setup();
    await exec.submit(level3());

    clock.advance(899);
    expect(await exec.tick()).toEqual({ reverted: [], stuck: [] });
    expect(adapter.revertCalls).toEqual([]);

    clock.advance(2);
    expect(await exec.tick()).toEqual({ reverted: ['act-1'], stuck: [] });
    expect(adapter.revertCalls).toEqual(['act-1']);
    expect(exec.listActive()).toEqual([]);
    expect(types().at(-1)).toBe('containment.reverted');
  });

  it('keeps a containment whose revert fails, retries it, and does not nag', async () => {
    const { exec, adapter, clock, sent } = setup();
    await exec.submit(level3());
    clock.advance(901);

    adapter.failRevert = true;
    expect((await exec.tick()).stuck).toEqual(['act-1']);
    expect((await exec.tick()).stuck).toEqual(['act-1']);
    expect(exec.listActive()).toHaveLength(1);
    expect(sent.filter((n) => n.kind === 'revert-failed')).toHaveLength(1);

    adapter.failRevert = false;
    expect((await exec.tick()).reverted).toEqual(['act-1']);
    expect(sent.at(-1)?.kind).toBe('reverted');
  });

  it('reminds a human again on the tenth failed attempt', async () => {
    const { exec, adapter, clock, sent } = setup();
    await exec.submit(level3());
    clock.advance(901);
    adapter.failRevert = true;
    for (let i = 0; i < 10; i++) await exec.tick();

    expect(sent.filter((n) => n.kind === 'revert-failed')).toHaveLength(2);
  });

  it('does not revert the same containment twice when ticks overlap', async () => {
    const { exec, adapter, clock } = setup();
    await exec.submit(level3());
    clock.advance(901);

    let release: () => void = () => undefined;
    adapter.revertHold = new Promise<void>((resolve) => (release = resolve));
    const first = exec.tick();
    const second = exec.tick();
    release();
    await Promise.all([first, second]);

    expect(adapter.revertCalls).toEqual(['act-1']);
  });

  it('lets only a listed approver revoke early', async () => {
    const { exec, adapter } = setup();
    await exec.submit(level3());

    expect(await exec.revoke('act-1', 'mallory')).toBe(false);
    expect(exec.listActive()).toHaveLength(1);
    expect(await exec.revoke('act-1', 'alice')).toBe(true);
    expect(adapter.revertCalls).toEqual(['act-1']);
    expect(await exec.revoke('act-1', 'alice')).toBe(false);
  });
});

describe('executor: human approval', () => {
  it('holds a level 4 action and runs it only with a valid approval for that exact action', async () => {
    const { exec, adapter, clock } = setup();
    const action = level4();
    const held = await exec.submit(action);

    expect(held.status).toBe('pending-human');
    expect(adapter.applyCalls).toEqual([]);
    expect(exec.listPending().map((p) => p.actionId)).toEqual(['act-4']);

    const wrongDigest = await exec.approve('act-4', approval(action, clock, { actionDigest: actionDigest(level4({ target: 'billing' })) }));
    const stranger = await exec.approve('act-4', approval(action, clock, { approver: 'mallory' }));
    const stale = await exec.approve('act-4', approval(action, clock, { approvedAt: new Date(clock.now().getTime() - 7_200_000).toISOString() }));
    for (const result of [wrongDigest, stranger, stale]) expect(result.status).toBe('pending-human');
    expect(adapter.applyCalls).toEqual([]);

    const ok = await exec.approve('act-4', approval(action, clock));
    expect(ok.status).toBe('applied');
    expect(adapter.applyCalls).toEqual(['act-4']);
    expect(exec.listPending()).toEqual([]);
  });

  it('does not act on an approval it cannot log, and keeps the proposal waiting', async () => {
    let failing = false;
    const { exec, adapter, clock } = setup({ sink: (log) => flakySink(log, (t) => failing && t === 'gate.decision') });
    const action = level4();
    await exec.submit(action);

    failing = true;
    expect((await exec.approve('act-4', approval(action, clock))).status).toBe('audit-failed');
    expect(adapter.applyCalls).toEqual([]);
    expect(exec.listPending()).toHaveLength(1);

    failing = false;
    expect((await exec.approve('act-4', approval(action, clock))).status).toBe('applied');
  });

  it('cannot replay an approval once the action has run', async () => {
    const { exec, adapter, clock } = setup();
    const action = level4();
    await exec.submit(action);
    await exec.approve('act-4', approval(action, clock));

    expect((await exec.approve('act-4', approval(action, clock))).status).toBe('denied');
    expect((await exec.submit(action)).status).toBe('duplicate');
    expect(adapter.applyCalls).toEqual(['act-4']);
  });

  it('has no expiry for an approved level 4 action; only a human ends it', async () => {
    const { exec, adapter, clock } = setup();
    const action = level4();
    await exec.submit(action);
    await exec.approve('act-4', approval(action, clock));

    clock.advance(10 * 86_400);
    expect(await exec.tick()).toEqual({ reverted: [], stuck: [] });
    expect(exec.listActive()[0]?.expiresAt).toBeNull();
    expect(await exec.revoke('act-4', 'alice')).toBe(true);
    expect(adapter.revertCalls).toEqual(['act-4']);
  });

  it('lets only a listed approver reject, and a rejected proposal cannot then be approved', async () => {
    const { exec, clock, types } = setup();
    const action = level4();
    await exec.submit(action);

    expect(exec.reject('act-4', 'mallory')).toBe(false);
    expect(exec.reject('act-4', 'alice')).toBe(true);
    expect(types()).toContain('executor.rejected');
    expect((await exec.approve('act-4', approval(action, clock))).status).toBe('denied');
  });

  it('treats the same held proposal as one, and a different proposal under its id as a duplicate', async () => {
    const { exec, sent, types } = setup();
    await exec.submit(level4());
    const decisions = types().filter((t) => t === 'gate.decision').length;
    const notices = sent.length;

    const again = await exec.submit(level4());
    expect(again.status).toBe('pending-human');
    expect(types().filter((t) => t === 'gate.decision')).toHaveLength(decisions);
    expect(sent).toHaveLength(notices);

    const changed = await exec.submit(level4({ reason: 'A different story.' }));
    expect(changed.status).toBe('duplicate');
  });

  it('drops proposals beyond the queue limit and tells a human', async () => {
    const { exec, sent } = setup({ maxPending: 1 });
    await exec.submit(level4({ id: 'act-4a' }));
    const overflow = await exec.submit(level4({ id: 'act-4b' }));

    expect(overflow.status).toBe('queue-full');
    expect(exec.listPending()).toHaveLength(1);
    expect(sent.at(-1)?.summary).toContain('queue');
  });
});

describe('executor: containment budget', () => {
  it('holds a second containment on the same target for a human', async () => {
    const { exec, adapter } = setup();
    await exec.submit(level3());
    const second = await exec.submit(level3({ id: 'act-2' }));

    expect(second.status).toBe('rate-limited');
    expect(second.detail).toContain('target');
    expect(adapter.applyCalls).toEqual(['act-1']);
    expect(exec.listPending()[0]).toMatchObject({ actionId: 'act-2', status: 'rate-limited' });
  });

  it('lets a human approve past the budget, but not with an approval that does not check out', async () => {
    const { exec, adapter, clock } = setup();
    await exec.submit(level3());
    const held = level3({ id: 'act-2' });
    await exec.submit(held);

    for (const bad of [
      approval(held, clock, { approver: 'mallory' }),
      approval(held, clock, { actionDigest: actionDigest(level3({ id: 'act-2', target: 'shop-web:/other' })) }),
    ]) {
      expect((await exec.approve('act-2', bad)).status).toBe('pending-human');
    }
    expect(adapter.applyCalls).toEqual(['act-1']);

    expect((await exec.approve('act-2', approval(held, clock))).status).toBe('applied');
    expect(adapter.applyCalls).toEqual(['act-1', 'act-2']);
  });

  it('caps how many containments run at once across targets', async () => {
    const { exec, adapter } = setup({ budget: { maxActive: 2 } });
    const results = [];
    for (const n of [1, 2, 3]) results.push(await exec.submit(level3({ id: `act-${n}`, target: `shop-web:/p${n}` })));

    expect(results.map((r) => r.status)).toEqual(['applied', 'applied', 'rate-limited']);
    expect(adapter.applyCalls).toHaveLength(2);
  });

  it('caps starts per window, and lets the window pass', async () => {
    const { exec, clock } = setup({ budget: { maxActive: 10, maxPerTarget: 10, maxStartsPerWindow: 2, windowSeconds: 600 } });
    await exec.submit(level3({ id: 'a1', target: 'shop-web:/p1' }));
    await exec.submit(level3({ id: 'a2', target: 'shop-web:/p2' }));

    clock.advance(100);
    expect((await exec.submit(level3({ id: 'a3', target: 'shop-web:/p3' }))).status).toBe('rate-limited');

    clock.advance(600);
    expect((await exec.submit(level3({ id: 'a4', target: 'shop-web:/p4' }))).status).toBe('applied');
  });

  it('does not count a human-approved start against the automatic start rate', async () => {
    const { exec, clock } = setup({ budget: { maxStartsPerWindow: 1 } });
    const isolate = level4();
    await exec.submit(isolate);
    expect((await exec.approve('act-4', approval(isolate, clock))).status).toBe('applied');

    expect((await exec.submit(level3())).status).toBe('applied');
    expect((await exec.submit(level3({ id: 'act-2', target: 'shop-web:/other' }))).status).toBe('rate-limited');
  });

  it('cannot be beaten by submitting many at the same moment', async () => {
    const { exec, adapter } = setup({ budget: { maxActive: 1 } });
    let release: () => void = () => undefined;
    adapter.applyHold = new Promise<void>((resolve) => (release = resolve));

    const all = Promise.all([1, 2, 3].map((n) => exec.submit(level3({ id: `act-${n}`, target: `shop-web:/p${n}` }))));
    release();
    const statuses = (await all).map((r) => r.status).sort();

    expect(statuses).toEqual(['applied', 'rate-limited', 'rate-limited']);
    expect(adapter.applyCalls).toHaveLength(1);
  });

  it('runs one action once even when the same id arrives twice at the same moment', async () => {
    const { exec, adapter } = setup();
    let release: () => void = () => undefined;
    adapter.applyHold = new Promise<void>((resolve) => (release = resolve));

    const both = Promise.all([exec.submit(level3()), exec.submit(level3())]);
    release();
    const statuses = (await both).map((r) => r.status).sort();

    expect(statuses).toEqual(['applied', 'duplicate']);
    expect(adapter.applyCalls).toEqual(['act-1']);
  });
});

describe('executor: restart', () => {
  it('rebuilds active containment from the log and still expires it', async () => {
    const { exec, build, adapter, clock, file } = setup();
    await exec.submit(level3());

    const restarted = build({ log: AuditLog.open(file, { clock: clock.now }) });
    expect(await restarted.recover()).toEqual({ active: 1, uncertain: [] });
    expect(restarted.listActive()[0]).toMatchObject({ actionId: 'act-1', handle: { rule: 'rule-act-1' } });

    clock.advance(901);
    expect((await restarted.tick()).reverted).toEqual(['act-1']);
    expect(adapter.revertCalls).toEqual(['act-1']);
  });

  it('does not forget which ids have run', async () => {
    const { exec, build, adapter, clock, file } = setup();
    await exec.submit(level3());

    const restarted = build({ log: AuditLog.open(file, { clock: clock.now }) });
    await restarted.recover();
    expect((await restarted.submit(level3())).status).toBe('duplicate');
    expect(adapter.applyCalls).toEqual(['act-1']);
  });

  it('lets a proposal that was held back by the budget be proposed again', async () => {
    const { exec, build, clock, file } = setup();
    await exec.submit(level3());
    expect((await exec.submit(level3({ id: 'act-2' }))).status).toBe('rate-limited');

    // Still over budget after a restart: held again, not mistaken for a repeat.
    const first = build({ log: AuditLog.open(file, { clock: clock.now }) });
    await first.recover();
    expect((await first.submit(level3({ id: 'act-2' }))).status).toBe('rate-limited');

    // Once the first containment has expired, the same proposal can run.
    clock.advance(901);
    const second = build({ log: AuditLog.open(file, { clock: clock.now }) });
    await second.recover();
    await second.tick();
    expect((await second.submit(level3({ id: 'act-2' }))).status).toBe('applied');
  });

  it('flags a change whose outcome the log does not record, until a human checks it', async () => {
    const { log, build, sent, clock, file } = setup();
    log.append({
      actor: 'executor',
      type: 'containment.applying',
      data: { actionId: 'act-x', kind: 'contain.rate-limit', target: 'shop-web:/z', expiresAt: null },
    });

    const restarted = build({ log: AuditLog.open(file, { clock: clock.now }) });
    const recovered = await restarted.recover();
    expect(recovered.uncertain).toEqual([{ actionId: 'act-x', kind: 'contain.rate-limit', target: 'shop-web:/z' }]);
    expect(sent.at(-1)?.kind).toBe('uncertain');

    expect(restarted.resolveUncertain('act-x', 'mallory')).toBe(false);
    expect(restarted.resolveUncertain('act-x', 'alice')).toBe(true);
    expect(restarted.listUncertain()).toEqual([]);

    const again = build({ log: AuditLog.open(file, { clock: clock.now }) });
    expect((await again.recover()).uncertain).toEqual([]);
  });

  it('refuses to start from a log that fails verification', async () => {
    const { exec, file } = setup();
    await exec.submit(level3());
    fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace('shop-web', 'shop-wex'));

    await expect(exec.recover()).rejects.toBeInstanceOf(AuditTamperError);
  });
});

describe('executor: minority alert', () => {
  const MODELS = ['model-x', 'model-y'];
  const panelOf = (n: number) =>
    Array.from({ length: n }, (_, i) => ({ id: `dog-${i + 1}`, model: MODELS[i % 2]!, evidenceView: 'raw-logs' }));
  const ballot = (n: number, approve: number, reject: number) =>
    Array.from({ length: n }, (_, i) => ({
      voter: `dog-${i + 1}`,
      decision: (i < approve ? 'approve' : i < approve + reject ? 'reject' : 'abstain') as 'approve' | 'reject' | 'abstain',
    }));
  const sevenDogs = () => ({ policy: policy({ panel: panelOf(7), requireDistinctModels: false }) });

  it('sends a denied proposal that 3 of 7 dogs flagged as its own kind of alert, and still does nothing', async () => {
    const { exec, adapter, sent, types } = setup(sevenDogs());
    const result = await exec.submit(level3({ votes: ballot(7, 3, 4) }));

    expect(result.status).toBe('denied');
    expect(adapter.applyCalls).toEqual([]);
    expect(sent.map((n) => n.kind)).toEqual(['dissent']);
    expect(sent[0]?.summary).toMatch(/^Review needed: .*3 of 7 approved \(4 needed\)/);
    expect(types()).toEqual(['gate.decision']);
  });

  it('keeps ordinary denials as ordinary reports', async () => {
    const { exec, sent } = setup(sevenDogs());
    await exec.submit(level3({ votes: ballot(7, 2, 5) }));

    expect(sent.map((n) => n.kind)).toEqual(['decision']);
    expect(sent[0]?.summary).not.toContain('Review needed');
  });

  it('flags a proposal that is held for a human because no side had a majority', async () => {
    const { exec, sent } = setup(sevenDogs());
    // 4 of 7 answered: 3 approve, 1 rejects; 3 never replied.
    const result = await exec.submit(level3({ votes: ballot(7, 3, 1).slice(0, 4) }));

    expect(result.status).toBe('pending-human');
    expect(sent.map((n) => n.kind)).toEqual(['dissent']);
  });

  it('does not call a decision that ran a dissent, even when some dogs disagreed', async () => {
    const { exec, adapter, sent } = setup({ policy: policy({ panel: panelOf(5), requireDistinctModels: false }) });
    const result = await exec.submit(level3({ votes: ballot(5, 3, 2) }));

    expect(result.status).toBe('applied');
    expect(adapter.applyCalls).toEqual(['act-1']);
    expect(sent.map((n) => n.kind)).toEqual(['decision']);
  });

  it('still raises the alert when the queue of waiting proposals is full', async () => {
    const { exec, sent } = setup({ ...sevenDogs(), maxPending: 1 });
    await exec.submit(level3({ id: 'act-a', votes: ballot(7, 3, 1).slice(0, 4) }));
    const overflow = await exec.submit(level3({ id: 'act-b', votes: ballot(7, 3, 1).slice(0, 4) }));

    expect(overflow.status).toBe('queue-full');
    expect(sent.map((n) => n.kind)).toEqual(['dissent', 'dissent']);
    expect(sent[1]?.summary).toContain('queue');
  });
});

describe('executor: nothing runs that the gate did not clear', () => {
  it('holds for every combination of level, kind, target, votes and duration', async () => {
    const gatePolicy = policy();
    const targets = ['shop-web:/upload', 'guard-dog:agent', 'other:/x'];
    const voteSets: (ProposedAction['votes'] | undefined)[] = [
      approve2,
      [{ voter: 'dog-a', decision: 'approve' }, { voter: 'dog-b', decision: 'reject' }],
      [{ voter: 'dog-a', decision: 'reject' }, { voter: 'dog-b', decision: 'reject' }],
      [{ voter: 'dog-a', decision: 'approve' }, { voter: 'stranger', decision: 'approve' }],
      undefined,
    ];
    const ttls = [900, 99_999, undefined];

    let combinations = 0;
    let ran = 0;
    for (const level of [1, 2, 3, 4] as const) {
      for (const kind of KINDS) {
        for (const target of targets) {
          for (const votes of voteSets) {
            for (const ttlSeconds of ttls) {
              const action: ProposedAction = {
                ...alertAction({ id: `c-${combinations}`, level, kind, target }),
                ...(votes === undefined ? {} : { votes }),
                ...(ttlSeconds === undefined ? {} : { ttlSeconds }),
                ...(level >= 3 ? { reversible: true } : {}),
                ...(level === 4 ? { requiresHumanApproval: true } : {}),
              };
              combinations++;

              const adapter = new FakeAdapter();
              const adapters = Object.fromEntries(KINDS.map((k) => [k, adapter]));
              const memory: { actor: string; type: string }[] = [];
              const exec = new Executor({
                policy: gatePolicy,
                log: {
                  append: (input) => {
                    memory.push(input);
                    return { seq: memory.length, ts: NOW.toISOString(), prev: '', hash: '', ...input };
                  },
                  entries: () => [],
                  verify: () => ({ ok: true, entries: 0, head: null }),
                },
                adapters,
                notifier: { notify: () => undefined },
                clock: () => NOW,
              });

              await exec.submit(action);
              if (adapter.applyCalls.length === 0) continue;
              ran++;

              const decision = evaluateAction(action, { now: NOW }, gatePolicy);
              expect(decision.outcome, JSON.stringify(action)).toBe('execute');
              expect(level, JSON.stringify(action)).not.toBe(4);
              if (kind.startsWith('contain.')) {
                expect(level, JSON.stringify(action)).toBe(3);
                expect(target, JSON.stringify(action)).toBe('shop-web:/upload');
                expect(votes, JSON.stringify(action)).toBe(approve2);
                expect(ttlSeconds, JSON.stringify(action)).toBe(900);
              }
            }
          }
        }
      }
    }

    expect(combinations).toBe(4 * 6 * 3 * 5 * 3);
    expect(ran).toBeGreaterThan(0);
  });
});
