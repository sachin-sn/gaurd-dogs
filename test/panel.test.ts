import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  AuditLog,
  Panel,
  createGatePolicy,
  evaluateAction,
  panelVerdict,
  withVotes,
  type ActionVote,
  type Dog,
  type DogDecision,
  type DogOpinion,
  type DogTask,
  type GatePolicy,
  type PanelResult,
  type ProposedAction,
} from '../src/index.js';

const NOW = new Date('2026-10-23T10:20:00Z');
const tick = () => new Promise<void>((resolve) => setImmediate(resolve));

/** A guard dog the test controls: it records what it was given and answers when told to. */
class TestDog implements Dog {
  tasks: DogTask[] = [];
  signals: AbortSignal[] = [];
  private resolve!: (opinion: DogOpinion) => void;
  private reject!: (error: unknown) => void;
  private readonly promise: Promise<DogOpinion>;

  constructor(
    readonly id: string,
    readonly model: string,
    readonly evidenceView = `view-${id}`,
    private readonly mode: 'manual' | 'throw' | 'return' | 'reject' = 'manual',
    private readonly value: unknown = undefined,
  ) {
    this.promise = new Promise<DogOpinion>((resolve, reject) => {
      this.resolve = resolve;
      this.reject = reject;
    });
  }

  review(task: DogTask, signal: AbortSignal): Promise<DogOpinion> {
    this.tasks.push(task);
    this.signals.push(signal);
    if (this.mode === 'throw') throw new Error('sync failure with sk-' + 'a'.repeat(30));
    if (this.mode === 'return') return Promise.resolve(this.value as DogOpinion);
    if (this.mode === 'reject') return Promise.reject(this.value);
    return this.promise;
  }

  answer(decision: DogDecision, rationale?: string): void {
    this.resolve(rationale === undefined ? { decision } : { decision, rationale });
  }
  fail(error: unknown): void {
    this.reject(error);
  }
}

const MODELS = ['model-x', 'model-y'];
function dogs(n: number, models: readonly string[] = MODELS): TestDog[] {
  return Array.from({ length: n }, (_, i) => new TestDog(`dog-${i}`, models[i % models.length] as string));
}
function policyFor(list: readonly TestDog[], overrides: Parameters<typeof createGatePolicy>[0] extends infer P ? Partial<P> : never = {}): GatePolicy {
  return createGatePolicy({
    panel: list.map((d) => ({ id: d.id, model: d.model, evidenceView: d.evidenceView })),
    preApproved: { 'contain.rate-limit': { maxTtlSeconds: 3600, targets: ['shop-web:*'] } },
    protectedTargets: ['guard-dog:*'],
    approvers: ['alice'],
    ...overrides,
  });
}

function action(overrides: Partial<ProposedAction> = {}): ProposedAction {
  return {
    id: 'act-1',
    proposedBy: 'investigator',
    level: 3,
    kind: 'contain.rate-limit',
    target: 'shop-web:/upload',
    reason: 'Repeated executable uploads.',
    evidence: ['evt-1'],
    createdAt: '2026-10-23T10:16:00Z',
    reversible: true,
    ttlSeconds: 900,
    ...overrides,
  };
}
const caseOf = (a: ProposedAction = action(), evidence: Record<string, unknown> = {}) => ({ action: a, evidence });

function gateSays(policy: GatePolicy, a: ProposedAction) {
  return evaluateAction(a, { now: NOW, knownEvidenceIds: new Set(a.evidence), ceilings: new Map() }, policy);
}

afterEach(() => {
  vi.useRealTimers();
});

describe('Panel construction', () => {
  it('must be exactly the gate policy panel', () => {
    const list = dogs(3);
    const policy = policyFor(list);
    const make = (d: TestDog[]) => new Panel({ policy, dogs: d });

    expect(() => make(list)).not.toThrow();
    expect(() => make(list.slice(0, 2))).toThrow(/missing: dog-2/);
    expect(() => make([...list, new TestDog('dog-9', 'model-x')])).toThrow(/not on the policy's panel/);
    expect(() => make([list[0] as TestDog, list[0] as TestDog, list[1] as TestDog])).toThrow(/duplicate/);
  });

  it('refuses a dog that claims a different model or evidence view than the policy', () => {
    const list = dogs(2);
    const policy = policyFor(list);
    const liar = new TestDog('dog-1', 'model-z', list[1]?.evidenceView);
    const wrongView = new TestDog('dog-1', 'model-y', 'other-view');

    expect(() => new Panel({ policy, dogs: [list[0] as TestDog, liar] })).toThrow(/model "model-z"/);
    expect(() => new Panel({ policy, dogs: [list[0] as TestDog, wrongView] })).toThrow(/evidence view/);
  });

  it('checks the deadline and that each dog can review', () => {
    const list = dogs(2);
    const policy = policyFor(list);
    for (const deadlineMs of [0, -1, 1.5, Number.NaN, 300_001]) {
      expect(() => new Panel({ policy, dogs: list, deadlineMs })).toThrow(RangeError);
    }
    const broken = { id: 'dog-1', model: 'model-y', evidenceView: 'view-dog-1' } as unknown as Dog;
    expect(() => new Panel({ policy, dogs: [list[0] as TestDog, broken] })).toThrow(/no review function/);
  });

  it('rejects a case without an action id', async () => {
    const list = dogs(2);
    const panel = new Panel({ policy: policyFor(list), dogs: list });
    await expect(panel.review({ action: null as unknown as ProposedAction, evidence: {} })).rejects.toThrow(TypeError);
    await expect(panel.review(caseOf(action({ id: '' })))).rejects.toThrow(/id/);
  });
});

describe('Panel review', () => {
  it('collects one vote per dog, in panel order, whatever order they answer in', async () => {
    const list = dogs(3);
    const panel = new Panel({ policy: policyFor(list), dogs: list });
    const pending = panel.review(caseOf());
    list[2]?.answer('approve', 'looks like a webshell');
    list[0]?.answer('approve');
    list[1]?.answer('reject');
    const result = await pending;

    expect(result.votes.map((v) => [v.voter, v.decision])).toEqual([
      ['dog-0', 'approve'],
      ['dog-1', 'reject'],
      ['dog-2', 'approve'],
    ]);
    expect(result.votes[2]?.rationale).toBe('looks like a webshell');
    expect(result.dogs.every((d) => d.status === 'voted')).toBe(true);
    expect(result.decidedEarly).toBe(false);
    expect(result.audited).toBe(true);
  });

  it('returns votes in the policy panel order, however the dogs were passed in', async () => {
    const list = dogs(3);
    const panel = new Panel({ policy: policyFor(list), dogs: [...list].reverse() });
    const pending = panel.review(caseOf());
    list.forEach((d) => d.answer('approve'));
    const result = await pending;

    expect(result.votes.map((v) => v.voter)).toEqual(['dog-0', 'dog-1', 'dog-2']);
    expect(result.dogs.map((d) => d.dog)).toEqual(['dog-0', 'dog-1', 'dog-2']);
  });

  it('gives each dog only its own evidence view, as a private copy', async () => {
    const list = dogs(2);
    const panel = new Panel({ policy: policyFor(list), dogs: list });
    const evidence = {
      'view-dog-0': { lines: ['a'] },
      'view-dog-1': { lines: ['b'] },
      'view-other': 'nobody asked for this',
    };
    const original = action();
    const pending = panel.review(caseOf(original, evidence));
    (list[0]?.tasks[0]?.evidence as { lines: string[] }).lines.push('tampered');
    (list[0]?.tasks[0]?.action as { target: string }).target = 'tampered';
    list.forEach((d) => d.answer('approve'));
    await pending;

    expect(list[1]?.tasks[0]?.evidence).toEqual({ lines: ['b'] });
    expect(list[0]?.tasks[0]?.evidence).toEqual({ lines: ['a', 'tampered'] });
    expect(list[1]?.tasks[0]?.action.target).toBe('shop-web:/upload');
    expect(evidence['view-dog-0']).toEqual({ lines: ['a'] });
    expect(original.target).toBe('shop-web:/upload');
  });

  it('gives a dog undefined, not a prototype property, for a view it has no evidence for', async () => {
    const list = [new TestDog('dog-0', 'model-x', 'constructor'), new TestDog('dog-1', 'model-y', '__proto__')];
    const panel = new Panel({ policy: policyFor(list), dogs: list });
    const pending = panel.review(caseOf(action(), {}));
    list.forEach((d) => d.answer('abstain'));
    await pending;

    // Both dogs were asked (a view with no evidence is not a reason to skip a dog), and got nothing.
    expect(list[0]?.tasks).toHaveLength(1);
    expect(list[1]?.tasks).toHaveLength(1);
    expect(list[0]?.tasks[0]?.evidence).toBeUndefined();
    expect(list[1]?.tasks[0]?.evidence).toBeUndefined();
  });

  it('does not pass along votes that were already on the action', async () => {
    const list = dogs(2);
    const panel = new Panel({ policy: policyFor(list), dogs: list });
    const pending = panel.review(caseOf(action({ votes: [{ voter: 'dog-0', decision: 'approve' }, { voter: 'dog-1', decision: 'approve' }] })));
    list.forEach((d) => d.answer('reject'));
    const result = await pending;

    expect(list[0]?.tasks[0]?.action).not.toHaveProperty('votes');
    expect(result.votes.map((v) => v.decision)).toEqual(['reject', 'reject']);
  });

  it('takes the voter id from the panel, never from what a dog says', async () => {
    const forged = new TestDog('dog-0', 'model-x', 'view-dog-0', 'return', { decision: 'approve', voter: 'dog-1', id: 'dog-1' });
    const honest = new TestDog('dog-1', 'model-y');
    const list = [forged, honest];
    const panel = new Panel({ policy: policyFor(list), dogs: list });
    const pending = panel.review(caseOf());
    honest.answer('reject');
    const result = await pending;

    expect(result.votes.map((v) => [v.voter, v.decision])).toEqual([
      ['dog-0', 'approve'],
      ['dog-1', 'reject'],
    ]);
  });

  it('cleans a rationale: control characters, whitespace and length', async () => {
    const list = dogs(2);
    const panel = new Panel({ policy: policyFor(list), dogs: list });
    const pending = panel.review(caseOf());
    list[0]?.answer('approve', 'line one\u0000\u001b[31m\n\n   line   two ' + 'x'.repeat(1000));
    list[1]?.answer('approve', '   \n  ');
    const result = await pending;

    const rationale = result.votes[0]?.rationale ?? '';
    expect(rationale).not.toMatch(/[\u0000-\u001f]/);
    expect(rationale.startsWith('line one [31m line two')).toBe(true);
    expect(rationale.length).toBeLessThanOrEqual(300);
    expect(result.votes[1]).not.toHaveProperty('rationale');
  });

  it('turns a failing, throwing or confused dog into an abstention, and never throws itself', async () => {
    const secret = 'sk-' + 'a'.repeat(30);
    const cases: { name: string; dog: TestDog; status: string; detail: string }[] = [
      { name: 'throws at once', dog: new TestDog('dog-0', 'model-x', 'view-dog-0', 'throw'), status: 'error', detail: 'the guard dog failed (Error)' },
      {
        name: 'rejects',
        dog: new TestDog('dog-0', 'model-x', 'view-dog-0', 'reject', new TypeError(`request failed, key ${secret}`)),
        status: 'error',
        detail: 'the guard dog failed (TypeError)',
      },
      { name: 'rejects with a string', dog: new TestDog('dog-0', 'model-x', 'view-dog-0', 'reject', 'just a string'), status: 'error', detail: 'the guard dog failed (non-error)' },
      { name: 'rejects with nothing', dog: new TestDog('dog-0', 'model-x', 'view-dog-0', 'reject', undefined), status: 'error', detail: 'the guard dog failed (non-error)' },
      { name: 'answers with an unknown decision', dog: new TestDog('dog-0', 'model-x', 'view-dog-0', 'return', { decision: 'maybe' }), status: 'invalid', detail: 'the answer had no valid decision' },
      { name: 'answers with null', dog: new TestDog('dog-0', 'model-x', 'view-dog-0', 'return', null), status: 'invalid', detail: 'the answer was not an opinion' },
      { name: 'answers with a bare string', dog: new TestDog('dog-0', 'model-x', 'view-dog-0', 'return', 'approve'), status: 'invalid', detail: 'the answer was not an opinion' },
    ];
    for (const c of cases) {
      const list = [c.dog, new TestDog('dog-1', 'model-y')];
      const panel = new Panel({ policy: policyFor(list), dogs: list });
      const result = await panel.review(caseOf());

      expect(result.dogs[0], c.name).toMatchObject({ status: c.status, decision: 'abstain', detail: c.detail });
      expect(result.votes[0], c.name).toMatchObject({ voter: 'dog-0', decision: 'abstain' });
      expect(JSON.stringify(result), c.name).not.toContain(secret);
    }
  });

  it('does not start the remaining dogs once the outcome is settled', async () => {
    // With two dogs, one failure means a majority is impossible and no minority alert can follow,
    // so there is nothing the other dog could say that would matter.
    const list = [new TestDog('dog-0', 'model-x', 'view-dog-0', 'throw'), new TestDog('dog-1', 'model-y')];
    const panel = new Panel({ policy: policyFor(list), dogs: list });
    const result = await panel.review(caseOf());

    expect(result.decidedEarly).toBe(true);
    expect(list[1]?.tasks).toEqual([]);
    expect(result.dogs.map((d) => d.status)).toEqual(['error', 'not-needed']);
  });

  it('runs concurrent reviews without mixing them up', async () => {
    const list = dogs(2);
    const panel = new Panel({ policy: policyFor(list), dogs: list });
    const first = panel.review(caseOf(action({ id: 'act-1' })));
    const second = panel.review(caseOf(action({ id: 'act-2' })));
    // Both reviews ask the same dogs; the second ask got the same pending promise, so answer both together.
    list.forEach((d) => d.answer('approve'));
    const [a, b] = await Promise.all([first, second]);

    expect(a.actionId).toBe('act-1');
    expect(b.actionId).toBe('act-2');
    expect(list[0]?.tasks.map((t) => t.action.id)).toEqual(['act-1', 'act-2']);
  });
});

describe('Panel early decision', () => {
  it('stops waiting when the majority is in, tells the slow dog to stop, and records it as not needed', async () => {
    const list = dogs(3);
    const panel = new Panel({ policy: policyFor(list), dogs: list });
    const pending = panel.review(caseOf());
    list[0]?.answer('approve');
    list[1]?.answer('approve');
    const result = await pending;

    expect(result.decidedEarly).toBe(true);
    expect(list[2]?.signals[0]?.aborted).toBe(true);
    expect(result.votes[2]).toMatchObject({ voter: 'dog-2', decision: 'abstain' });
    expect(result.dogs[2]).toMatchObject({ status: 'not-needed' });
    expect(result.verdict).toContain('info:panel-approved');
  });

  it('ignores an answer that lands in the same instant as the one that settled the outcome', async () => {
    const list = dogs(3);
    const panel = new Panel({ policy: policyFor(list), dogs: list });
    const pending = panel.review(caseOf());
    list[0]?.answer('approve');
    list[1]?.answer('approve');
    list[2]?.answer('reject');
    const result = await pending;

    expect(result.dogs[2]).toMatchObject({ status: 'not-needed', decision: 'abstain' });
    expect(result.votes[2]?.decision).toBe('abstain');
  });

  it('ignores whatever a dog says after the review is over, even a failure', async () => {
    const list = dogs(3);
    const panel = new Panel({ policy: policyFor(list), dogs: list });
    const pending = panel.review(caseOf());
    list[0]?.answer('approve');
    list[1]?.answer('approve');
    const result = await pending;
    list[2]?.answer('reject');
    await tick();
    expect(result.votes[2]?.decision).toBe('abstain');

    // A late rejection must not become an unhandled rejection either.
    const more = dogs(3);
    const panel2 = new Panel({ policy: policyFor(more), dogs: more });
    const pending2 = panel2.review(caseOf());
    more[0]?.answer('approve');
    more[1]?.answer('approve');
    await pending2;
    more[2]?.fail(new Error('late'));
    await tick();
  });

  it('does not stop on a majority from a single model while a dog of another model could still change the verdict', async () => {
    const list = dogs(3, ['model-x', 'model-x', 'model-y']);
    const policy = policyFor(list);
    const panel = new Panel({ policy, dogs: list });
    const pending = panel.review(caseOf());
    list[0]?.answer('approve');
    list[1]?.answer('approve');
    await tick();
    list[2]?.answer('approve');
    const result = await pending;

    expect(result.decidedEarly).toBe(false);
    expect(result.verdict).toContain('info:panel-approved');
    expect(gateSays(policy, withVotes(action(), result)).outcome).toBe('execute');
  });

  it('settles a one-model majority once no outstanding dog could add a second model', async () => {
    const list = dogs(3, ['model-x', 'model-x', 'model-x']);
    const policy = policyFor(list);
    const panel = new Panel({ policy, dogs: list });
    const pending = panel.review(caseOf());
    list[0]?.answer('approve');
    list[1]?.answer('approve');
    const result = await pending;

    expect(result.decidedEarly).toBe(true);
    expect(result.verdict).toContain('soft:panel-not-diverse');
  });

  it('does not stop after the rejections while the dogs that are left could still raise the minority alert', async () => {
    // Seven dogs, four reject: no majority is possible. But three more could approve,
    // and three approvals are what make a human hear about it.
    const list = dogs(7);
    const policy = policyFor(list);
    expect(policy.dissentAlertMin).toBe(3);
    const panel = new Panel({ policy, dogs: list });
    const pending = panel.review(caseOf());
    for (const i of [0, 1, 2, 3]) list[i]?.answer('reject');
    await tick();
    expect(list[4]?.signals[0]?.aborted).toBe(false);
    for (const i of [4, 5, 6]) list[i]?.answer('approve');
    const result = await pending;

    expect(result.decidedEarly).toBe(false);
    expect(result.verdict).toContain('info:minority-flag');
    const decision = gateSays(policy, withVotes(action(), result));
    expect(decision.outcome).not.toBe('execute');
    expect(decision.codes).toContain('minority-flag');
    expect(decision.notify.summary.startsWith('Review needed: ')).toBe(true);
  });

  it('keeps waiting while one more approval would make a majority, then finishes when everyone has answered', async () => {
    const list = dogs(7);
    const panel = new Panel({ policy: policyFor(list), dogs: list });
    const pending = panel.review(caseOf());
    for (const i of [0, 1, 2]) list[i]?.answer('approve');
    for (const i of [3, 4, 5]) list[i]?.answer('reject');
    await tick();
    expect(list[6]?.signals[0]?.aborted).toBe(false);
    list[6]?.answer('reject');
    const result = await pending;

    expect(result.decidedEarly).toBe(false);
    expect(result.verdict).toContain('info:minority-flag');
  });

  it('stops as soon as the rejection and the minority alert are both certain', async () => {
    // Nine dogs need five. Five reject, so it is rejected; three approved, so the alert is raised.
    // The last dog could make it four approvals, still short of five: nothing changes.
    const list = dogs(9);
    const policy = policyFor(list);
    expect(policy.dissentAlertMin).toBe(3);
    const panel = new Panel({ policy, dogs: list });
    const pending = panel.review(caseOf());
    for (const i of [0, 1, 2]) list[i]?.answer('approve');
    for (const i of [3, 4, 5, 6]) list[i]?.answer('reject');
    await tick();
    expect(list[8]?.signals[0]?.aborted).toBe(false);
    list[7]?.answer('reject');
    const result = await pending;

    expect(result.decidedEarly).toBe(true);
    expect(result.dogs[8]).toMatchObject({ status: 'not-needed' });
    expect(result.verdict).toContain('hard:panel-rejected');
    expect(result.verdict).toContain('info:minority-flag');
  });

  it('settles a hopeless case straight away: no majority, and no alert possible', async () => {
    // Five dogs: four reject. The last cannot reach a majority, and one approval is below the alert threshold of two.
    const list = dogs(5);
    const panel = new Panel({ policy: policyFor(list), dogs: list });
    const pending = panel.review(caseOf());
    for (const i of [0, 1, 2, 3]) list[i]?.answer('reject');
    const result = await pending;

    expect(result.decidedEarly).toBe(true);
    expect(result.verdict).toContain('hard:panel-rejected');
    expect(result.verdict).not.toContain('minority-flag');
    expect(result.dogs[4]).toMatchObject({ status: 'not-needed' });
  });

  it('does not settle a rejection while two more approvals could still raise the minority alert', async () => {
    const list = dogs(5);
    const panel = new Panel({ policy: policyFor(list), dogs: list });
    const pending = panel.review(caseOf());
    for (const i of [0, 1, 2]) list[i]?.answer('reject');
    await tick();
    expect(list[3]?.signals[0]?.aborted).toBe(false);
    list[3]?.answer('approve');
    list[4]?.answer('approve');
    const result = await pending;

    expect(result.decidedEarly).toBe(false);
    expect(result.verdict).toContain('info:minority-flag');
  });

  it('keeps waiting while a deny could still turn into a human review, or the other way round', async () => {
    // Five dogs, two reject and two fail: approvals cannot reach three, but a third rejection would turn "wait for a human" into "denied".
    const list = dogs(5);
    const policy = policyFor(list);
    const panel = new Panel({ policy, dogs: list });
    const pending = panel.review(caseOf());
    list[0]?.answer('reject');
    list[1]?.answer('reject');
    list[2]?.fail(new Error('down'));
    list[3]?.fail(new Error('down'));
    await tick();
    expect(list[4]?.signals[0]?.aborted).toBe(false);
    list[4]?.answer('approve');
    const result = await pending;

    expect(result.verdict).toContain('soft:panel-split');
    expect(result.verdict).not.toContain('hard:panel-rejected');
  });
});

describe('Panel early decision never changes the verdict', () => {
  // For every panel size, every combination of answers and several arrival orders:
  // the verdict with early stopping must equal the verdict of waiting for everyone.
  const decisions: DogDecision[] = ['approve', 'reject', 'abstain'];

  function* combinations(n: number): Generator<DogDecision[]> {
    const total = 3 ** n;
    for (let i = 0; i < total; i++) {
      const combo: DogDecision[] = [];
      let rest = i;
      for (let j = 0; j < n; j++) {
        combo.push(decisions[rest % 3] as DogDecision);
        rest = Math.floor(rest / 3);
      }
      yield combo;
    }
  }

  const orders = (n: number): number[][] => {
    const forward = Array.from({ length: n }, (_, i) => i);
    const middleOut = forward.map((i) => (i + Math.floor(n / 2)) % n);
    return [forward, [...forward].reverse(), middleOut];
  };

  const setups: { name: string; models: string[]; options: { requireDistinctModels?: boolean; rule?: 'majority' | 'unanimous' } }[] = [
    { name: 'two models, distinct required', models: ['model-x', 'model-y'], options: {} },
    { name: 'one model, distinct required', models: ['model-x'], options: {} },
    { name: 'three models, distinct not required', models: ['model-x', 'model-y', 'model-z'], options: { requireDistinctModels: false } },
    { name: 'two models, unanimous', models: ['model-x', 'model-y'], options: { rule: 'unanimous' } },
  ];

  for (const setup of setups) {
    it(`holds for panels of 2 to 6 dogs (${setup.name})`, async () => {
      let earlyCases = 0;
      let cases = 0;
      for (let n = 2; n <= 6; n++) {
        for (const combo of combinations(n)) {
          for (const order of orders(n)) {
            const list = dogs(n, setup.models);
            const policy = policyFor(list, setup.options);
            const panel = new Panel({ policy, dogs: list });
            const pending = panel.review(caseOf());
            for (const index of order) {
              list[index]?.answer(combo[index] as DogDecision);
              await tick();
            }
            const result = await pending;

            const everyone: ActionVote[] = combo.map((decision, i) => ({ voter: `dog-${i}`, decision }));
            expect(result.verdict).toBe(panelVerdict(everyone, policy));
            cases++;
            if (result.decidedEarly) earlyCases++;
          }
        }
      }
      expect(cases).toBeGreaterThan(2000);
      expect(earlyCases).toBeGreaterThan(cases / 10); // early stopping really happens
    }, 120_000);
  }

  it('holds for seven dogs on the minority-alert boundary', async () => {
    for (const split of [
      [3, 4],
      [2, 5],
      [4, 3],
      [3, 3],
      [1, 6],
    ] as const) {
      for (const reverse of [false, true]) {
        const list = dogs(7);
        const policy = policyFor(list);
        const panel = new Panel({ policy, dogs: list });
        const combo: DogDecision[] = [
          ...Array<DogDecision>(split[0]).fill('approve'),
          ...Array<DogDecision>(split[1]).fill('reject'),
          ...Array<DogDecision>(7 - split[0] - split[1]).fill('abstain'),
        ];
        const order = Array.from({ length: 7 }, (_, i) => i);
        if (reverse) order.reverse();
        const pending = panel.review(caseOf());
        for (const index of order) {
          list[index]?.answer(combo[index] as DogDecision);
          await tick();
        }
        const result = await pending;
        const everyone: ActionVote[] = combo.map((decision, i) => ({ voter: `dog-${i}`, decision }));
        expect(result.verdict).toBe(panelVerdict(everyone, policy));
      }
    }
  });
});

describe('Panel deadline', () => {
  it('marks dogs that have not answered by the deadline as timed out, and tells them to stop', async () => {
    vi.useFakeTimers();
    const list = dogs(3);
    const policy = policyFor(list);
    const panel = new Panel({ policy, dogs: list, deadlineMs: 5000, now: () => Date.now() });
    const pending = panel.review(caseOf());
    let finished = false;
    void pending.then(() => (finished = true));

    await vi.advanceTimersByTimeAsync(100);
    list[0]?.answer('approve');
    await vi.advanceTimersByTimeAsync(4800);
    expect(finished).toBe(false);
    await vi.advanceTimersByTimeAsync(100);
    const result = await pending;

    expect(result.elapsedMs).toBe(5000);
    expect(result.decidedEarly).toBe(false);
    expect(result.dogs.map((d) => d.status)).toEqual(['voted', 'timed-out', 'timed-out']);
    expect(result.dogs[0]?.ms).toBe(100);
    expect(result.dogs[1]?.detail).toBe('no answer within 5000 ms');
    expect(list[1]?.signals[0]?.aborted).toBe(true);
    // One approval of three is not a majority: silent dogs have not agreed.
    expect(gateSays(policy, withVotes(action(), result)).outcome).not.toBe('execute');
  });

  it('leaves no timer behind, whether it finishes early, on time or by failure', async () => {
    vi.useFakeTimers();
    const early = dogs(3);
    const panelA = new Panel({ policy: policyFor(early), dogs: early, now: () => Date.now() });
    const a = panelA.review(caseOf());
    early.slice(0, 2).forEach((d) => d.answer('approve'));
    await a;
    expect(vi.getTimerCount()).toBe(0);

    const all = dogs(2);
    const panelB = new Panel({ policy: policyFor(all), dogs: all, now: () => Date.now() });
    const b = panelB.review(caseOf());
    all.forEach((d) => d.answer('approve'));
    await b;
    expect(vi.getTimerCount()).toBe(0);

    const failing = [new TestDog('dog-0', 'model-x', 'view-dog-0', 'throw'), new TestDog('dog-1', 'model-y', 'view-dog-1', 'throw')];
    const panelC = new Panel({ policy: policyFor(failing), dogs: failing, now: () => Date.now() });
    await panelC.review(caseOf());
    expect(vi.getTimerCount()).toBe(0);
  });

  it('does not wait for a dog that ignores the abort signal', async () => {
    vi.useFakeTimers();
    const stubborn = { id: 'dog-0', model: 'model-x', evidenceView: 'v0', review: () => new Promise<DogOpinion>(() => undefined) };
    const quick = { id: 'dog-1', model: 'model-y', evidenceView: 'v1', review: async (): Promise<DogOpinion> => ({ decision: 'approve' }) };
    const list = [stubborn, quick];
    const policy = createGatePolicy({ panel: list.map(({ id, model, evidenceView }) => ({ id, model, evidenceView })) });
    const panel = new Panel({ policy, dogs: list, deadlineMs: 1000, now: () => Date.now() });
    const pending = panel.review(caseOf());
    await vi.advanceTimersByTimeAsync(1000);
    const result = await pending;

    expect(result.dogs.map((d) => d.status)).toEqual(['timed-out', 'voted']);
  });
});

describe('withVotes', () => {
  it('attaches the votes, replacing any that were there', async () => {
    const list = dogs(2);
    const panel = new Panel({ policy: policyFor(list), dogs: list });
    const original = action({ votes: [{ voter: 'dog-0', decision: 'approve' }, { voter: 'dog-1', decision: 'approve' }] });
    const pending = panel.review(caseOf(original));
    list.forEach((d) => d.answer('reject'));
    const result = await pending;
    const voted = withVotes(original, result);

    expect(voted.votes?.map((v) => v.decision)).toEqual(['reject', 'reject']);
    expect(voted).toMatchObject({ id: original.id, target: original.target });
    voted.votes?.push({ voter: 'x', decision: 'approve' });
    expect(result.votes).toHaveLength(2);
  });

  it('refuses an action that changed after the review', async () => {
    const list = dogs(2);
    const panel = new Panel({ policy: policyFor(list), dogs: list });
    const pending = panel.review(caseOf());
    list.forEach((d) => d.answer('approve'));
    const result = await pending;

    for (const changed of [
      action({ target: 'shop-web:*' }),
      action({ level: 4 }),
      action({ ttlSeconds: 3600 }),
      action({ reason: 'Something else.' }),
      action({ evidence: ['evt-1', 'evt-2'] }),
      action({ id: 'act-2' }),
    ]) {
      expect(() => withVotes(changed, result)).toThrow(/different action/);
    }
    // A new timestamp is not a change of substance.
    expect(() => withVotes(action({ createdAt: '2026-10-23T10:30:00Z' }), result)).not.toThrow();
  });
});

describe('Panel and the gate', () => {
  async function run(answers: (DogDecision | 'silent')[], models = MODELS) {
    vi.useFakeTimers();
    const list = dogs(answers.length, models);
    const policy = policyFor(list);
    const panel = new Panel({ policy, dogs: list, deadlineMs: 1000, now: () => Date.now() });
    const pending = panel.review(caseOf());
    answers.forEach((a, i) => {
      if (a !== 'silent') list[i]?.answer(a);
    });
    await vi.advanceTimersByTimeAsync(1000);
    const result: PanelResult = await pending;
    vi.useRealTimers();
    return { result, decision: gateSays(policy, withVotes(action(), result)) };
  }

  it('two dogs must both agree', async () => {
    expect((await run(['approve', 'approve'])).decision.outcome).toBe('execute');
    expect((await run(['approve', 'reject'])).decision.outcome).not.toBe('execute');
    expect((await run(['approve', 'silent'])).decision.outcome).not.toBe('execute');
  });

  it('three dogs need two', async () => {
    expect((await run(['approve', 'approve', 'reject'])).decision.outcome).toBe('execute');
    expect((await run(['approve', 'silent', 'silent'])).decision.outcome).not.toBe('execute');
  });

  it('five dogs need three, and two raise the minority alert', async () => {
    expect((await run(['approve', 'approve', 'approve', 'reject', 'reject'])).decision.outcome).toBe('execute');
    const two = await run(['approve', 'approve', 'reject', 'reject', 'reject']);
    expect(two.decision.outcome).not.toBe('execute');
    expect(two.decision.codes).toContain('minority-flag');
  });

  it('seven dogs: three for and four against is rejected, and a human is told', async () => {
    const { decision } = await run(['approve', 'approve', 'approve', 'reject', 'reject', 'reject', 'reject']);
    expect(decision.outcome).toBe('deny');
    expect(decision.codes).toContain('minority-flag');
    expect(decision.notify.summary.startsWith('Review needed: ')).toBe(true);
  });

  it('a slow dog never counts as agreement, so two of five answering is not enough', async () => {
    const { result, decision } = await run(['approve', 'approve', 'silent', 'silent', 'silent']);
    expect(result.dogs.filter((d) => d.status === 'timed-out')).toHaveLength(3);
    expect(decision.outcome).not.toBe('execute');
  });

  it('approvals from a single model are not enough', async () => {
    const { decision } = await run(['approve', 'approve'], ['model-x']);
    expect(decision.outcome).toBe('await-human');
    expect(decision.codes).toContain('panel-not-diverse');
  });
});

describe('Panel audit', () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  });

  it('records the review: who answered, what, how fast, and what the gate will conclude', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gd-panel-'));
    dirs.push(dir);
    const log = AuditLog.open(path.join(dir, 'audit.jsonl'));
    const list = dogs(3);
    const panel = new Panel({ policy: policyFor(list), dogs: list, log });
    const pending = panel.review(caseOf());
    list[0]?.answer('approve', 'executable under the web root');
    list[1]?.answer('approve');
    const result = await pending;

    const entries = log.entries().filter((e) => e.type === 'panel.review');
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({ actor: 'panel' });
    expect(entries[0]?.data).toMatchObject({
      actionId: 'act-1',
      actionDigest: result.actionDigest,
      verdict: result.verdict,
      decidedEarly: true,
    });
    const dogsLogged = (entries[0]?.data as { dogs: { dog: string; status: string; rationale?: string }[] }).dogs;
    expect(dogsLogged.map((d) => [d.dog, d.status])).toEqual([
      ['dog-0', 'voted'],
      ['dog-1', 'voted'],
      ['dog-2', 'not-needed'],
    ]);
    expect(dogsLogged[0]?.rationale).toBe('executable under the web root');
    expect(log.verify().ok).toBe(true);
  });

  it('reports a failed audit write without losing the votes', async () => {
    const list = dogs(2);
    const log = {
      append: () => {
        throw new Error('disk full');
      },
    };
    const panel = new Panel({ policy: policyFor(list), dogs: list, log });
    const pending = panel.review(caseOf());
    list.forEach((d) => d.answer('approve'));
    const result = await pending;

    expect(result.audited).toBe(false);
    expect(result.votes).toHaveLength(2);
  });
});
