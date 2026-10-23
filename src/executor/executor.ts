import { AuditTamperError, type AuditLog } from '../audit/log.js';
import type { JsonValue, ProposedAction } from '../core/types.js';
import {
  auditDecision,
  evaluateAction,
  type GateContext,
  type GateDecision,
  type HumanApproval,
} from '../gate/gate.js';
import type { ActionKind, GatePolicy } from '../gate/policy.js';
import { sanitizeEvidence } from '../rules/sanitize.js';

/**
 * The executor is the only way a proposal becomes a change in the world.
 *
 * - Every proposal goes through the gate here, so there is no path around it.
 * - Fail closed: the decision, and then the intent to act, are written to the
 *   audit log BEFORE anything is done. If the log cannot be written, nothing runs.
 * - Containment always has an owner for its undo: it expires and is reverted by
 *   `tick`, or a human revokes it. A failed revert is retried and reported.
 * - Automatic containment has a budget, so a flood of proposals (or an attacker
 *   steering the guard dogs) cannot contain the whole estate.
 * - An action id runs at most once, so an approved action cannot be replayed.
 * - Checks and claims happen in one synchronous step, so two concurrent
 *   submissions cannot both pass the same duplicate or budget check.
 *
 * The real controls (a WAF, a firewall API) sit behind `ControlAdapter`. The
 * executor only ever acts through them, and only with what the gate cleared.
 */

export interface ControlAdapter {
  /**
   * Carry the action out. Return whatever is needed to undo it, as JSON.
   * If it throws, the executor treats the action as not applied, so an adapter
   * must not leave a half-applied change behind.
   */
  apply(action: ProposedAction): Promise<{ handle: JsonValue }>;
  /** Undo it. Must be safe to call more than once: after a restart it may run again. */
  revert(handle: JsonValue, info: { actionId: string; kind: ActionKind; target: string }): Promise<void>;
}

export interface Notification {
  kind:
    | 'alert'
    | 'decision'
    /** A minority of the panel flagged something that was not acted on. Worth a higher-attention channel than 'decision'. */
    | 'dissent'
    | 'apply-failed'
    | 'revert-failed'
    | 'audit-failed'
    | 'reverted'
    | 'uncertain';
  actionId: string;
  /** Sanitised, human-readable. */
  summary: string;
}

export interface Notifier {
  notify(notification: Notification): void | Promise<void>;
}

export type AuditSink = Pick<AuditLog, 'append' | 'entries' | 'verify'>;

export interface BudgetLimits {
  /** Most containments active at once. */
  maxActive: number;
  /** Most containments active against one target. */
  maxPerTarget: number;
  /** Most automatic containments started in any window. */
  maxStartsPerWindow: number;
  windowSeconds: number;
}

export const defaultBudget: BudgetLimits = {
  maxActive: 5,
  maxPerTarget: 1,
  maxStartsPerWindow: 10,
  windowSeconds: 600,
};

export interface ExecutorOptions {
  policy: GatePolicy;
  log: AuditSink;
  adapters: Partial<Record<ActionKind, ControlAdapter>>;
  notifier: Notifier;
  budget?: Partial<BudgetLimits>;
  clock?: () => Date;
  /** Most proposals held for a human at once. Default 500. */
  maxPending?: number;
  /** How long to wait for the notifier before giving up on one message. Default 5000. */
  notifyTimeoutMs?: number;
}

export type SubmitStatus =
  | 'applied'
  | 'pending-human'
  | 'rate-limited'
  | 'denied'
  | 'duplicate'
  | 'no-adapter'
  | 'apply-failed'
  | 'audit-failed'
  | 'queue-full';

export interface SubmitResult {
  status: SubmitStatus;
  decision: GateDecision | null;
  detail?: string;
}

export type SubmitContext = Omit<GateContext, 'now' | 'humanApproval'>;

export interface ActiveContainment {
  actionId: string;
  kind: ActionKind;
  target: string;
  handle: JsonValue;
  appliedAt: string;
  /** Null for actions with no expiry, which only a human can revoke. */
  expiresAt: string | null;
  revertAttempts: number;
}

export interface PendingAction {
  actionId: string;
  digest: string;
  since: string;
  status: 'pending-human' | 'rate-limited';
  reason: string;
}

/** A change that was about to be made when the process stopped, and whose outcome the log does not record. */
export interface UncertainAction {
  actionId: string;
  kind: ActionKind;
  target: string;
}

interface PendingEntry extends PendingAction {
  action: ProposedAction;
  context: SubmitContext;
}

function errorText(error: unknown): string {
  return sanitizeEvidence(error instanceof Error ? error.message : String(error), 200);
}

/**
 * For a decision that did not run. If enough guard dogs flagged it anyway, it goes
 * out as 'dissent' so it is not lost among routine reports. (A decision that ran,
 * even after a human cleared a minority-flagged one, is already known to the human.)
 */
function decisionKind(decision: GateDecision): Notification['kind'] {
  return decision.codes.includes('minority-flag') ? 'dissent' : 'decision';
}

function isContainment(kind: ActionKind): boolean {
  return kind.startsWith('contain.');
}

function asRecord(value: JsonValue): Record<string, JsonValue> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? value : null;
}

export class Executor {
  private readonly policy: GatePolicy;
  private readonly log: AuditSink;
  private readonly adapters: Partial<Record<ActionKind, ControlAdapter>>;
  private readonly notifier: Notifier;
  private readonly budget: BudgetLimits;
  private readonly clock: () => Date;
  private readonly maxPending: number;
  private readonly notifyTimeoutMs: number;

  private readonly active = new Map<string, ActiveContainment>();
  /** Containments claimed but not yet recorded as active. Counted against the budget. */
  private readonly starting = new Map<string, { kind: ActionKind; target: string }>();
  private readonly pending = new Map<string, PendingEntry>();
  private readonly uncertain = new Map<string, UncertainAction>();
  private readonly executedIds = new Set<string>();
  private readonly reverting = new Set<string>();
  private startTimes: number[] = [];

  constructor(options: ExecutorOptions) {
    this.policy = options.policy;
    this.log = options.log;
    this.adapters = options.adapters;
    this.notifier = options.notifier;
    this.budget = { ...defaultBudget, ...options.budget };
    this.clock = options.clock ?? (() => new Date());
    this.maxPending = options.maxPending ?? 500;
    this.notifyTimeoutMs = options.notifyTimeoutMs ?? 5000;
  }

  listActive(): ActiveContainment[] {
    return [...this.active.values()].map((entry) => ({ ...entry }));
  }

  listPending(): PendingAction[] {
    return [...this.pending.values()].map(({ actionId, digest, since, status, reason }) => ({
      actionId,
      digest,
      since,
      status,
      reason,
    }));
  }

  listUncertain(): UncertainAction[] {
    return [...this.uncertain.values()].map((entry) => ({ ...entry }));
  }

  /**
   * Rebuild what is active, and which ids have run, from the audit log. Call
   * once at start-up so containment survives a restart and still expires.
   * Throws `AuditTamperError` if the log fails verification: do not start
   * acting on a log you cannot trust.
   *
   * Held proposals are not stored in the log and are lost on restart; the
   * investigators must propose them again.
   */
  async recover(): Promise<{ active: number; uncertain: UncertainAction[] }> {
    const verified = this.log.verify();
    if (!verified.ok) throw new AuditTamperError(verified.seq, verified.reason);

    this.active.clear();
    this.uncertain.clear();
    this.executedIds.clear();

    for (const entry of this.log.entries()) {
      const data = asRecord(entry.data);
      const actionId = data?.['actionId'];
      if (data === null || typeof actionId !== 'string') continue;

      switch (entry.type) {
        case 'gate.decision':
          if (data['outcome'] === 'execute') this.executedIds.add(actionId);
          break;
        case 'executor.rate-limited':
          // The gate cleared it but the budget held it back, so it never ran.
          this.executedIds.delete(actionId);
          break;
        case 'containment.applying':
          this.uncertain.set(actionId, {
            actionId,
            kind: data['kind'] as ActionKind,
            target: String(data['target']),
          });
          break;
        case 'containment.applied': {
          this.uncertain.delete(actionId);
          const expiresAt = data['expiresAt'];
          this.active.set(actionId, {
            actionId,
            kind: data['kind'] as ActionKind,
            target: String(data['target']),
            handle: data['handle'] ?? null,
            appliedAt: entry.ts,
            expiresAt: typeof expiresAt === 'string' ? expiresAt : null,
            revertAttempts: 0,
          });
          break;
        }
        case 'containment.apply-failed':
          this.uncertain.delete(actionId);
          break;
        case 'containment.reverted':
        case 'containment.resolved':
          this.uncertain.delete(actionId);
          this.active.delete(actionId);
          break;
        default:
          break;
      }
    }

    const uncertain = this.listUncertain();
    for (const item of uncertain) {
      await this.tellHuman({
        kind: 'uncertain',
        actionId: item.actionId,
        summary:
          `The service stopped while ${item.kind} on ${sanitizeEvidence(item.target, 80)} was being applied, ` +
          'and the log does not say whether it took effect. Check the control by hand.',
      });
    }
    return { active: this.active.size, uncertain };
  }

  /** A listed approver confirms that an uncertain action has been checked by hand. */
  resolveUncertain(actionId: string, by: string): boolean {
    if (!this.policy.approvers.has(by) || !this.uncertain.has(actionId)) return false;
    const failure = this.tryAudit(() =>
      this.log.append({ actor: `human:${sanitizeEvidence(by, 60)}`, type: 'containment.resolved', data: { actionId } }),
    );
    if (failure !== null) return false;
    this.uncertain.delete(actionId);
    return true;
  }

  /** The single entry point for a proposal. */
  async submit(raw: unknown, context: SubmitContext = {}): Promise<SubmitResult> {
    const now = this.clock();
    const decision = evaluateAction(raw, { ...context, now }, this.policy);

    // Everything up to `claim` is synchronous on purpose: no other submission
    // can slip in between a check and the claim that depends on it.
    const repeat = this.repeatOf(decision);
    if (repeat !== null) return repeat;

    const auditFailure = this.tryAudit(() => auditDecision(this.log, decision));
    if (auditFailure !== null) return this.auditFailed(decision, auditFailure);

    if (decision.outcome === 'deny') {
      await this.tellHuman({ kind: decisionKind(decision), actionId: decision.actionId, summary: decision.notify.summary });
      return { status: 'denied', decision };
    }

    const action = raw as ProposedAction;

    if (decision.outcome === 'await-human') {
      const parked = this.park(action, decision, context, now, decision.reasons.join(' '), 'pending-human');
      await this.announceHold(parked, decision);
      return parked;
    }

    if (isContainment(action.kind)) {
      const reason = this.overBudget(action, now);
      if (reason !== null) {
        const parked = this.park(action, decision, context, now, reason, 'rate-limited');
        await this.announceHold(parked, decision);
        return parked;
      }
    }

    this.claim(action, decision, true, now);
    await this.tellHuman({
      kind: action.kind === 'alert.notify' ? 'alert' : 'decision',
      actionId: decision.actionId,
      summary: decision.notify.summary,
    });
    return this.run(action, decision);
  }

  /** A listed approver approves a held proposal. The gate checks the approval again. */
  async approve(actionId: string, approval: HumanApproval): Promise<SubmitResult> {
    const entry = this.pending.get(actionId);
    if (entry === undefined) return { status: 'denied', decision: null, detail: 'nothing is waiting under that id' };

    const now = this.clock();
    const decision = evaluateAction(entry.action, { ...entry.context, now, humanApproval: approval }, this.policy);
    const auditFailure = this.tryAudit(() => auditDecision(this.log, decision, 'response-gate:approval'));
    if (auditFailure !== null) return this.auditFailed(decision, auditFailure);

    if (decision.outcome === 'deny') {
      this.pending.delete(actionId);
      await this.tellHuman({ kind: decisionKind(decision), actionId, summary: decision.notify.summary });
      return { status: 'denied', decision };
    }
    // Without a valid approval a rate-limited proposal would clear the gate on its own and
    // slip past the budget, so only a recognised approval gets through here.
    if (decision.outcome === 'await-human' || !decision.codes.includes('human-approved')) {
      return { status: 'pending-human', decision, detail: 'the approval did not clear the holds' };
    }

    this.pending.delete(actionId);
    this.claim(entry.action, decision, false, now);
    await this.tellHuman({ kind: 'decision', actionId, summary: decision.notify.summary });
    return this.run(entry.action, decision);
  }

  /** A listed approver turns a held proposal down. */
  reject(actionId: string, by: string): boolean {
    if (!this.policy.approvers.has(by) || !this.pending.has(actionId)) return false;
    const failure = this.tryAudit(() =>
      this.log.append({ actor: `human:${sanitizeEvidence(by, 60)}`, type: 'executor.rejected', data: { actionId } }),
    );
    if (failure !== null) return false;
    this.pending.delete(actionId);
    return true;
  }

  /** A listed approver ends a containment early. */
  async revoke(actionId: string, by: string): Promise<boolean> {
    if (!this.policy.approvers.has(by)) return false;
    const entry = this.active.get(actionId);
    if (entry === undefined) return false;
    return this.revert(entry, `revoked by ${sanitizeEvidence(by, 60)}`);
  }

  /** Undo every containment that has expired. Call on a timer. Failures are kept and retried on the next call. */
  async tick(): Promise<{ reverted: string[]; stuck: string[] }> {
    const now = this.clock().getTime();
    const reverted: string[] = [];
    const stuck: string[] = [];
    for (const entry of [...this.active.values()]) {
      if (entry.expiresAt === null || Date.parse(entry.expiresAt) > now) continue;
      if (await this.revert(entry, 'expired')) reverted.push(entry.actionId);
      else stuck.push(entry.actionId);
    }
    return { reverted, stuck };
  }

  // ---- internals ----

  /** An id that has run, or a different proposal under an id that is waiting, is a repeat. */
  private repeatOf(decision: GateDecision): SubmitResult | null {
    const id = decision.actionId;
    if (this.executedIds.has(id)) return this.duplicate(decision, 'this action id has already run');

    const waiting = decision.digest === null ? undefined : this.pending.get(id);
    if (waiting === undefined) return null;
    if (waiting.digest !== decision.digest) {
      return this.duplicate(decision, 'a different proposal is already waiting under this id');
    }
    // The same proposal again: report where it stands without logging or notifying twice.
    return { status: waiting.status, decision, detail: 'already waiting' };
  }

  private duplicate(decision: GateDecision, detail: string): SubmitResult {
    const failure = this.tryAudit(() =>
      this.log.append({ actor: 'executor', type: 'executor.duplicate', data: { actionId: decision.actionId, detail } }),
    );
    return { status: 'duplicate', decision, detail: failure === null ? detail : `${detail} (and the audit log failed)` };
  }

  private async auditFailed(decision: GateDecision, detail: string): Promise<SubmitResult> {
    await this.tellHuman({
      kind: 'audit-failed',
      actionId: decision.actionId,
      summary: `The audit log could not be written, so nothing was done for this proposal: ${detail}`,
    });
    return { status: 'audit-failed', decision, detail };
  }

  /** Returns null on success, or a short error description. Never throws. */
  private tryAudit(write: () => unknown): string | null {
    try {
      write();
      return null;
    } catch (error) {
      return errorText(error);
    }
  }

  private async tellHuman(notification: Notification): Promise<void> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('the notifier did not answer in time')), this.notifyTimeoutMs);
      });
      await Promise.race([Promise.resolve(this.notifier.notify(notification)), timeout]);
    } catch (error) {
      this.tryAudit(() =>
        this.log.append({
          actor: 'executor',
          type: 'executor.notify-failed',
          data: { actionId: notification.actionId, kind: notification.kind, error: errorText(error) },
        }),
      );
    } finally {
      clearTimeout(timer);
    }
  }

  /** Keep a proposal for a human. Synchronous, so the pending map and the log never disagree under concurrency. */
  private park(
    action: ProposedAction,
    decision: GateDecision,
    context: SubmitContext,
    now: Date,
    reason: string,
    status: 'pending-human' | 'rate-limited',
  ): SubmitResult {
    if (this.pending.size >= this.maxPending) return { status: 'queue-full', decision, detail: 'too many proposals are waiting' };

    if (status === 'rate-limited') {
      const failure = this.tryAudit(() =>
        this.log.append({ actor: 'executor', type: 'executor.rate-limited', data: { actionId: decision.actionId, reason } }),
      );
      if (failure !== null) return { status: 'audit-failed', decision, detail: failure };
    }
    this.pending.set(decision.actionId, {
      action,
      context,
      actionId: decision.actionId,
      digest: decision.digest ?? '',
      since: now.toISOString(),
      status,
      reason,
    });
    return { status, decision, detail: reason };
  }

  private async announceHold(parked: SubmitResult, decision: GateDecision): Promise<void> {
    const actionId = decision.actionId;
    if (parked.status === 'pending-human') {
      await this.tellHuman({ kind: decisionKind(decision), actionId, summary: decision.notify.summary });
    } else if (parked.status === 'rate-limited') {
      await this.tellHuman({
        kind: 'decision',
        actionId,
        summary: `${decision.notify.summary} Held back by the containment budget: ${parked.detail ?? ''}`,
      });
    } else if (parked.status === 'queue-full') {
      await this.tellHuman({
        kind: decisionKind(decision),
        actionId,
        summary: `The queue of proposals waiting for a human is full, so this one was dropped. ${decision.notify.summary}`,
      });
    } else if (parked.status === 'audit-failed') {
      await this.tellHuman({
        kind: 'audit-failed',
        actionId,
        summary: `The audit log could not be written, so this proposal was not held: ${parked.detail ?? ''}`,
      });
    }
  }

  private overBudget(action: ProposedAction, now: Date): string | null {
    const windowMs = this.budget.windowSeconds * 1000;
    this.startTimes = this.startTimes.filter((t) => now.getTime() - t < windowMs);

    const live = [...this.active.values(), ...this.starting.values()].filter((entry) => isContainment(entry.kind));
    if (live.length >= this.budget.maxActive) {
      return `${live.length} containments are already active (limit ${this.budget.maxActive}).`;
    }
    const onTarget = live.filter((entry) => entry.target === action.target).length;
    if (onTarget >= this.budget.maxPerTarget) {
      return `that target already has ${onTarget} active (limit ${this.budget.maxPerTarget}).`;
    }
    if (this.startTimes.length >= this.budget.maxStartsPerWindow) {
      return `${this.startTimes.length} containments started in the last ${this.budget.windowSeconds} seconds (limit ${this.budget.maxStartsPerWindow}).`;
    }
    return null;
  }

  /** Take the id and a budget slot in the same synchronous step as the checks. */
  private claim(action: ProposedAction, decision: GateDecision, automatic: boolean, now: Date): void {
    this.executedIds.add(decision.actionId);
    if (isContainment(action.kind)) {
      this.starting.set(decision.actionId, { kind: action.kind, target: action.target });
      if (automatic) this.startTimes.push(now.getTime());
    }
  }

  private async run(action: ProposedAction, decision: GateDecision): Promise<SubmitResult> {
    const actionId = decision.actionId;
    try {
      if (action.kind === 'alert.notify') return { status: 'applied', decision };

      const adapter = this.adapters[action.kind];
      if (adapter === undefined) {
        const detail = `no control is connected for ${action.kind}`;
        await this.tellHuman({ kind: 'apply-failed', actionId, summary: `Cleared to run, but ${detail}.` });
        return this.noAdapter(decision, detail);
      }

      const expiresAt = decision.expiresAt ?? null;
      const intent = this.tryAudit(() =>
        this.log.append({
          actor: 'executor',
          type: 'containment.applying',
          data: { actionId, kind: action.kind, target: action.target, expiresAt },
        }),
      );
      if (intent !== null) return this.auditFailed(decision, intent);

      let handle: JsonValue;
      try {
        ({ handle } = await adapter.apply(action));
      } catch (error) {
        const detail = errorText(error);
        this.tryAudit(() =>
          this.log.append({ actor: 'executor', type: 'containment.apply-failed', data: { actionId, error: detail } }),
        );
        await this.tellHuman({ kind: 'apply-failed', actionId, summary: `Applying ${action.kind} failed: ${detail}` });
        return { status: 'apply-failed', decision, detail };
      }

      const failure = this.tryAudit(() =>
        this.log.append({
          actor: 'executor',
          type: 'containment.applied',
          data: { actionId, kind: action.kind, target: action.target, expiresAt, handle },
        }),
      );
      if (failure !== null) {
        // The change is live but unrecorded, so nothing would ever undo it. Undo it now.
        let undone = true;
        try {
          await adapter.revert(handle, { actionId, kind: action.kind, target: action.target });
        } catch {
          undone = false;
        }
        if (undone) {
          this.tryAudit(() =>
            this.log.append({ actor: 'executor', type: 'containment.reverted', data: { actionId, why: 'could not be recorded' } }),
          );
        }
        await this.tellHuman({
          kind: 'audit-failed',
          actionId,
          summary: undone
            ? 'A change was applied but could not be recorded. It was undone; check the control by hand.'
            : 'A change was applied but could not be recorded, and undoing it failed. Check the control by hand now.',
        });
        return { status: 'audit-failed', decision, detail: failure };
      }

      this.active.set(actionId, {
        actionId,
        kind: action.kind,
        target: action.target,
        handle,
        appliedAt: this.clock().toISOString(),
        expiresAt,
        revertAttempts: 0,
      });
      return { status: 'applied', decision };
    } finally {
      this.starting.delete(actionId);
    }
  }

  private noAdapter(decision: GateDecision, detail: string): SubmitResult {
    this.tryAudit(() =>
      this.log.append({ actor: 'executor', type: 'executor.no-adapter', data: { actionId: decision.actionId, detail } }),
    );
    return { status: 'no-adapter', decision, detail };
  }

  private async revert(entry: ActiveContainment, why: string): Promise<boolean> {
    if (this.reverting.has(entry.actionId)) return false;
    this.reverting.add(entry.actionId);
    try {
      const adapter = this.adapters[entry.kind];
      entry.revertAttempts += 1;
      try {
        if (adapter === undefined) throw new Error(`no control is connected for ${entry.kind}`);
        await adapter.revert(entry.handle, { actionId: entry.actionId, kind: entry.kind, target: entry.target });
      } catch (error) {
        const detail = errorText(error);
        this.tryAudit(() =>
          this.log.append({
            actor: 'executor',
            type: 'containment.revert-failed',
            data: { actionId: entry.actionId, attempt: entry.revertAttempts, error: detail },
          }),
        );
        if (entry.revertAttempts === 1 || entry.revertAttempts % 10 === 0) {
          await this.tellHuman({
            kind: 'revert-failed',
            actionId: entry.actionId,
            summary:
              `Could not undo ${entry.kind} on ${sanitizeEvidence(entry.target, 80)} ` +
              `(attempt ${entry.revertAttempts}): ${detail}. It stays active and will be retried.`,
          });
        }
        return false;
      }

      this.active.delete(entry.actionId);
      const failure = this.tryAudit(() =>
        this.log.append({ actor: 'executor', type: 'containment.reverted', data: { actionId: entry.actionId, why } }),
      );
      await this.tellHuman(
        failure === null
          ? {
              kind: 'reverted',
              actionId: entry.actionId,
              summary: `${entry.kind} on ${sanitizeEvidence(entry.target, 80)} was undone (${why}).`,
            }
          : {
              kind: 'audit-failed',
              actionId: entry.actionId,
              summary: `${entry.kind} was undone but the log could not record it; after a restart it will be undone again.`,
            },
      );
      return true;
    } finally {
      this.reverting.delete(entry.actionId);
    }
  }
}
