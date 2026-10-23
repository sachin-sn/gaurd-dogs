/**
 * The panel runner. It puts one case to every guard dog on the panel at once,
 * collects their votes, and returns them ready to attach to a proposal. It does
 * not decide anything: the gate reads the votes and applies the majority rule.
 *
 *   case (action + evidence) -> every dog, in parallel, each with its own view
 *                            -> votes -> withVotes(action, result) -> gate
 *
 * What it guarantees:
 *
 * - A dog that is slow, fails, or answers nonsense has not agreed. It is
 *   recorded as an abstention with the reason, never as a missing dog, and
 *   never as a yes.
 * - Voter ids come from the panel, not from what a dog says. A dog cannot vote
 *   as another dog.
 * - Each dog sees only its own evidence view, as a private copy.
 * - Waiting stops early only when nothing still outstanding could change what
 *   the gate concludes (see `outcomeIsSettled`). The result is the same as
 *   waiting for everyone, only sooner. A dog's rationale is untrusted model
 *   output: it is sanitised and capped before it goes anywhere.
 * - Votes are bound to the action they were cast on. Change the target, the
 *   level or the duration afterwards and they no longer attach.
 */

import type { AuditLog } from '../audit/log.js';
import type { ActionVote, JsonValue, ProposedAction } from '../core/types.js';
import { actionDigest, panelVerdict } from '../gate/gate.js';
import type { GatePolicy } from '../gate/policy.js';
import { sanitizeEvidence } from '../rules/sanitize.js';

export type DogDecision = ActionVote['decision'];

export interface DogOpinion {
  decision: DogDecision;
  /** Why. Untrusted: it is model output. */
  rationale?: string;
}

/** What one guard dog is asked to review. A private copy, so changing it affects nobody else. */
export interface DogTask {
  /** The action under review, without any votes. */
  action: Omit<ProposedAction, 'votes'>;
  /** The slice of evidence for this dog's view. Untrusted data: delimit it before it reaches a model. */
  evidence: unknown;
}

/**
 * A guard dog on the panel. `id`, `model` and `evidenceView` must match the
 * gate policy's panel exactly, because the gate decides on those.
 *
 * `review` should stop work when `signal` aborts, which happens when the panel
 * no longer needs the answer. A dog that ignores the signal is not waited for.
 */
export interface Dog {
  id: string;
  model: string;
  evidenceView: string;
  review(task: DogTask, signal: AbortSignal): Promise<DogOpinion>;
}

export interface PanelCase {
  /** The proposal to put to the panel. Any votes already on it are ignored. */
  action: ProposedAction;
  /** Evidence by view name. Each dog receives only the entry for its own `evidenceView`. */
  evidence: Readonly<Record<string, unknown>>;
}

export type DogStatus =
  /** The dog answered with a valid opinion in time. */
  | 'voted'
  /** No answer by the deadline. */
  | 'timed-out'
  /** The dog threw or rejected. */
  | 'error'
  /** The dog answered with something that is not a valid opinion. */
  | 'invalid'
  /** The outcome was settled before this dog answered, so it was told to stop. */
  | 'not-needed';

export interface DogReport {
  dog: string;
  model: string;
  status: DogStatus;
  decision: DogDecision;
  /** Milliseconds from the start of the review until this dog was settled. */
  ms: number;
  detail?: string;
}

export interface PanelResult {
  actionId: string;
  /** Fingerprint of the action the votes were cast on. */
  actionDigest: string;
  /** One vote per dog, in panel order. Silent or failed dogs are abstentions. */
  votes: ActionVote[];
  dogs: DogReport[];
  /** What the gate will conclude from these votes, as a comparable string. */
  verdict: string;
  /** True if waiting stopped before every dog answered, because nothing outstanding could change the verdict. */
  decidedEarly: boolean;
  elapsedMs: number;
  /** False if the review's audit entry could not be written. */
  audited: boolean;
}

export interface PanelOptions {
  policy: GatePolicy;
  dogs: readonly Dog[];
  /** Longest the whole review waits, in milliseconds. Default 20,000. */
  deadlineMs?: number;
  /** Where to record the review. A failed write is reported, never thrown. */
  log?: Pick<AuditLog, 'append'>;
  /** Monotonic milliseconds. Default `performance.now`. */
  now?: () => number;
}

const DECISIONS: readonly DogDecision[] = ['approve', 'reject', 'abstain'];
const MAX_RATIONALE = 300;
const DEFAULT_DEADLINE_MS = 20_000;
const MAX_DEADLINE_MS = 300_000;

interface Slot {
  dog: Dog;
  settled: boolean;
  status: DogStatus;
  decision: DogDecision;
  ms: number;
  detail?: string;
  rationale?: string;
}

export class Panel {
  private readonly policy: GatePolicy;
  private readonly dogs: readonly Dog[];
  private readonly deadlineMs: number;
  private readonly log: Pick<AuditLog, 'append'> | undefined;
  private readonly now: () => number;

  constructor(options: PanelOptions) {
    this.policy = options.policy;
    this.deadlineMs = options.deadlineMs ?? DEFAULT_DEADLINE_MS;
    this.log = options.log;
    this.now = options.now ?? (() => performance.now());
    if (!Number.isInteger(this.deadlineMs) || this.deadlineMs < 1 || this.deadlineMs > MAX_DEADLINE_MS) {
      throw new RangeError(`deadlineMs must be a whole number from 1 to ${MAX_DEADLINE_MS}`);
    }

    // The gate counts a majority of its own panel. If these dogs are not
    // exactly that panel, a missing dog would stay silent forever, or a dog
    // would claim a model the gate does not know about.
    const seen = new Set<string>();
    for (const dog of options.dogs) {
      const member = this.policy.panel.get(dog.id);
      if (member === undefined) throw new RangeError(`"${dog.id}" is not on the policy's panel`);
      if (seen.has(dog.id)) throw new RangeError(`duplicate guard dog "${dog.id}"`);
      seen.add(dog.id);
      if (member.model !== dog.model) {
        throw new RangeError(`"${dog.id}" runs model "${dog.model}" but the policy says "${member.model}"`);
      }
      if (member.evidenceView !== dog.evidenceView) {
        throw new RangeError(`"${dog.id}" has evidence view "${dog.evidenceView}" but the policy says "${member.evidenceView}"`);
      }
      if (typeof dog.review !== 'function') throw new TypeError(`"${dog.id}" has no review function`);
    }
    if (seen.size !== this.policy.panel.size) {
      const missing = [...this.policy.panel.keys()].filter((id) => !seen.has(id));
      throw new RangeError(`the panel needs all ${this.policy.panel.size} guard dogs; missing: ${missing.join(', ')}`);
    }
    // Panel order, so votes always come out in the same order.
    const byId = new Map(options.dogs.map((dog) => [dog.id, dog]));
    this.dogs = [...this.policy.panel.keys()].map((id) => byId.get(id) as Dog);
  }

  /** Put the case to every dog and return their votes. Never throws because of a dog. */
  async review(panelCase: PanelCase): Promise<PanelResult> {
    const action = panelCase.action;
    if (typeof action !== 'object' || action === null || typeof action.id !== 'string' || action.id.length === 0) {
      throw new TypeError('the case needs an action with an id');
    }
    const digest = actionDigest(action);
    const { votes: _ignored, ...unvoted } = action;

    const start = this.now();
    const controller = new AbortController();
    const slots: Slot[] = this.dogs.map((dog) => ({ dog, settled: false, status: 'not-needed', decision: 'abstain', ms: 0 }));
    let outstanding = slots.length;
    let finished = false;
    // An object, so the closures below can set it without TypeScript narrowing it.
    const state = { reason: 'answered' as 'answered' | 'early' | 'deadline' };
    let release!: () => void;
    const done = new Promise<void>((resolve) => {
      release = resolve;
    });

    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (why: typeof state.reason): void => {
      if (finished) return;
      finished = true;
      state.reason = why;
      if (timer !== undefined) clearTimeout(timer);
      controller.abort();
      release();
    };

    const settle = (slot: Slot, outcome: Pick<Slot, 'status' | 'decision'> & { detail?: string; rationale?: string }): void => {
      if (finished || slot.settled) return; // a late answer is ignored
      slot.settled = true;
      slot.status = outcome.status;
      slot.decision = outcome.decision;
      slot.ms = this.now() - start;
      if (outcome.detail !== undefined) slot.detail = outcome.detail;
      if (outcome.rationale !== undefined) slot.rationale = outcome.rationale;
      outstanding--;
      if (outstanding === 0) finish('answered');
      else if (this.outcomeIsSettled(slots)) finish('early');
    };

    timer = setTimeout(() => finish('deadline'), this.deadlineMs);

    for (const slot of slots) {
      // A dog that fails at once can settle the outcome before the rest have started.
      if (finished) break;
      let pending: Promise<DogOpinion>;
      try {
        const task: DogTask = {
          action: structuredClone(unvoted),
          evidence: structuredClone(Object.hasOwn(panelCase.evidence ?? {}, slot.dog.evidenceView) ? panelCase.evidence[slot.dog.evidenceView] : undefined),
        };
        pending = Promise.resolve(slot.dog.review(task, controller.signal));
      } catch (error) {
        settle(slot, { status: 'error', decision: 'abstain', detail: failure(error) });
        continue;
      }
      pending.then(
        (opinion) => settle(slot, readOpinion(opinion)),
        (error: unknown) => settle(slot, { status: 'error', decision: 'abstain', detail: failure(error) }),
      );
    }

    await done;

    const elapsedMs = this.now() - start;
    for (const slot of slots) {
      if (slot.settled) continue;
      slot.ms = elapsedMs;
      slot.decision = 'abstain';
      if (state.reason === 'deadline') {
        slot.status = 'timed-out';
        slot.detail = `no answer within ${this.deadlineMs} ms`;
      } else {
        slot.status = 'not-needed';
        slot.detail = 'the outcome was already settled';
      }
    }

    const votes: ActionVote[] = slots.map((slot) => {
      const vote: ActionVote = { voter: slot.dog.id, decision: slot.decision };
      const note = slot.rationale ?? slot.detail;
      if (note !== undefined) vote.rationale = note;
      return vote;
    });
    const dogs: DogReport[] = slots.map((slot) => ({
      dog: slot.dog.id,
      model: slot.dog.model,
      status: slot.status,
      decision: slot.decision,
      ms: slot.ms,
      ...(slot.detail === undefined ? {} : { detail: slot.detail }),
    }));
    const verdict = panelVerdict(votes, this.policy);

    const result: PanelResult = {
      actionId: action.id,
      actionDigest: digest,
      votes,
      dogs,
      verdict,
      decidedEarly: state.reason === 'early',
      elapsedMs,
      audited: true,
    };
    result.audited = this.audit(result, slots);
    return result;
  }

  /**
   * True when nothing still outstanding could change what the gate concludes.
   * It tries every way the outstanding dogs could vote (approve, reject, or
   * stay silent) and compares the gate's verdict for each. With at most nine
   * dogs that is at most 3^8 cases, which is instant, and it uses the gate's
   * own tally, so it cannot drift from the gate's rules.
   *
   * This is what keeps the minority alert intact: with seven dogs, four
   * rejections do not settle anything while three more could still approve
   * and so raise the alert.
   */
  private outcomeIsSettled(slots: readonly Slot[]): boolean {
    const votes: ActionVote[] = [];
    const outstanding: Slot[] = [];
    for (const slot of slots) {
      if (slot.settled) votes.push({ voter: slot.dog.id, decision: slot.decision });
      else outstanding.push(slot);
    }

    let first: string | undefined;
    const allAgree = (i: number): boolean => {
      if (i === outstanding.length) {
        const verdict = panelVerdict(votes, this.policy);
        first ??= verdict;
        return verdict === first;
      }
      const voter = (outstanding[i] as Slot).dog.id;
      for (const decision of DECISIONS) {
        votes.push({ voter, decision });
        const same = allAgree(i + 1);
        votes.pop();
        if (!same) return false;
      }
      return true;
    };
    return allAgree(0);
  }

  private audit(result: PanelResult, slots: readonly Slot[]): boolean {
    if (this.log === undefined) return true;
    try {
      this.log.append({
        actor: 'panel',
        type: 'panel.review',
        data: {
          actionId: result.actionId,
          actionDigest: result.actionDigest,
          verdict: result.verdict,
          decidedEarly: result.decidedEarly,
          elapsedMs: Math.round(result.elapsedMs),
          dogs: slots.map((slot) => {
            const entry: { [key: string]: JsonValue } = {
              dog: slot.dog.id,
              model: slot.dog.model,
              status: slot.status,
              decision: slot.decision,
              ms: Math.round(slot.ms),
            };
            if (slot.detail !== undefined) entry['detail'] = slot.detail;
            if (slot.rationale !== undefined) entry['rationale'] = slot.rationale;
            return entry;
          }),
        },
      });
      return true;
    } catch {
      return false;
    }
  }
}

/**
 * Attach the panel's votes to the action they were cast on. Votes already on
 * the action are replaced, and an action that has changed since the review
 * (a wider target, a longer duration, a different reason) is refused.
 */
export function withVotes(action: ProposedAction, result: PanelResult): ProposedAction {
  if (actionDigest(action) !== result.actionDigest) {
    throw new Error('these votes were cast on a different action');
  }
  return { ...action, votes: result.votes.map((vote) => ({ ...vote })) };
}

function readOpinion(opinion: unknown): Pick<Slot, 'status' | 'decision'> & { detail?: string; rationale?: string } {
  if (typeof opinion !== 'object' || opinion === null) {
    return { status: 'invalid', decision: 'abstain', detail: 'the answer was not an opinion' };
  }
  const { decision, rationale } = opinion as { decision?: unknown; rationale?: unknown };
  if (typeof decision !== 'string' || !DECISIONS.includes(decision as DogDecision)) {
    return { status: 'invalid', decision: 'abstain', detail: 'the answer had no valid decision' };
  }
  const result: Pick<Slot, 'status' | 'decision'> & { rationale?: string } = { status: 'voted', decision: decision as DogDecision };
  if (typeof rationale === 'string') {
    const cleaned = sanitizeEvidence(rationale, MAX_RATIONALE);
    if (cleaned.length > 0) result.rationale = cleaned;
  }
  return result;
}

/** Only the kind of failure, never its message: errors from model APIs can quote the request. */
function failure(error: unknown): string {
  const name = error instanceof Error ? sanitizeEvidence(error.name, 40) : 'non-error';
  return `the guard dog failed (${name})`;
}
