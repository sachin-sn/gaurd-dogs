import { createHash } from 'node:crypto';
import { canonicalize, type AuditEntry, type AuditLog } from '../audit/log.js';
import type { ActionVote, ProposedAction, ResponseLevel } from '../core/types.js';
import { validateAction } from '../core/validate.js';
import { sanitizeEvidence } from '../rules/sanitize.js';
import { matchesAny } from './glob.js';
import { MIN_LEVEL, type GatePolicy, type PanelMember } from './policy.js';

/**
 * The response gate. Investigators propose; the gate decides; a separate
 * executor acts. The gate is a pure function: it executes nothing itself.
 *
 * Outcomes:
 * - execute:     the action may run now (level 3 with an expiry, or a human approved it)
 * - await-human: the action is plausible but needs a person before it runs
 * - deny:        the proposal is malformed, forged, or was rejected by the panel
 *
 * Every decision, whatever the outcome, carries a notification for a human.
 */

export type GateOutcome = 'execute' | 'await-human' | 'deny';

export type GateCode =
  // Hard: the proposal cannot be trusted. Human approval does not override these.
  | 'schema'
  | 'kind-level-mismatch'
  | 'unknown-evidence'
  | 'duplicate-voter'
  | 'unknown-voter'
  | 'panel-rejected'
  // Soft: a person can clear these.
  | 'requires-human-level-4'
  | 'above-intel-ceiling'
  | 'not-pre-approved'
  | 'ttl-exceeds-policy'
  | 'target-out-of-scope'
  | 'protected-target'
  | 'panel-split'
  | 'panel-not-diverse'
  // Information.
  | 'minority-flag'
  | 'automatic-level-1-2'
  | 'panel-approved'
  | 'human-approved'
  | 'invalid-approval';

const REASONS: Readonly<Record<GateCode, string>> = {
  schema: 'The proposal does not match the action schema.',
  'kind-level-mismatch': 'The action kind needs a higher response level than the one it was proposed at.',
  'unknown-evidence': 'The proposal cites evidence that the gate does not know about.',
  'duplicate-voter': 'The same guard dog appears more than once in the votes.',
  'unknown-voter': 'A vote came from someone who is not on the panel.',
  'panel-rejected': 'The panel voted against the action.',
  'requires-human-level-4': 'Level 4 actions always need a human.',
  'above-intel-ceiling': 'The evidence cited allows only a lower response level until a human verifies it.',
  'not-pre-approved': 'Policy does not pre-approve this kind of containment.',
  'ttl-exceeds-policy': 'The requested duration is longer than policy allows without a human.',
  'target-out-of-scope': 'The target is outside the scope policy pre-approves for this kind of action.',
  'protected-target': 'The target is protected and is never contained automatically.',
  'panel-split': 'The panel did not agree.',
  'minority-flag': 'Several guard dogs flagged this, too few to act on. A human should look.',
  'panel-not-diverse': 'The panel agreed, but the approving guard dogs share one model.',
  'automatic-level-1-2': 'Observe and alert actions run automatically and are always reported.',
  'panel-approved': 'The panel agreed.',
  'human-approved': 'A valid human approval cleared the holds.',
  'invalid-approval': 'A human approval was supplied but did not check out, so it was ignored.',
};

export interface HumanApproval {
  approver: string;
  approvedAt: string;
  /** From `actionDigest`. Ties the approval to this exact action. */
  actionDigest: string;
}

export interface GateContext {
  now: Date;
  /** Ids of events and informer records that exist. When given, level 3 and 4 may cite only these. */
  knownEvidenceIds?: ReadonlySet<string>;
  /** Highest level each cited record allows (from `ExposureFinding.maxLevel`). Evidence not listed is unrestricted. */
  ceilings?: ReadonlyMap<string, ResponseLevel>;
  humanApproval?: HumanApproval;
}

/** How the panel voted. Dogs that abstained or did not answer are counted in `silent`. */
export interface VoteCount {
  approve: number;
  reject: number;
  silent: number;
  /** Approvals needed to act. */
  required: number;
  panelSize: number;
}

export interface GateDecision {
  outcome: GateOutcome;
  actionId: string;
  digest: string | null;
  level: ResponseLevel | null;
  /** Null when the proposal was not put to a vote (level 1 and 2, or an untrustworthy vote list). */
  votes: VoteCount | null;
  codes: GateCode[];
  reasons: string[];
  /** When a level 3 containment must be undone. Set only for `execute` with a duration. */
  expiresAt?: string;
  /** Every proposed action is reported to a human, whatever the outcome. */
  notify: { summary: string };
}

/**
 * A fingerprint of what an action does and why. It leaves out votes and
 * timestamps, so a late vote does not invalidate an approval, but changing the
 * target, level, reason, evidence or duration does.
 */
export function actionDigest(action: ProposedAction): string {
  const substance = {
    id: action.id,
    level: action.level,
    kind: action.kind,
    target: action.target,
    reason: action.reason,
    evidence: action.evidence,
    ttlSeconds: action.ttlSeconds ?? null,
    reversible: action.reversible ?? null,
    requiresHumanApproval: action.requiresHumanApproval ?? null,
  };
  return createHash('sha256').update(canonicalize(substance), 'utf8').digest('hex');
}

function idOf(raw: unknown): string {
  if (typeof raw === 'object' && raw !== null && 'id' in raw) {
    const id = (raw as { id: unknown }).id;
    if (typeof id === 'string' && id.length > 0) return sanitizeEvidence(id, 128);
  }
  return 'unknown';
}

interface Tally {
  hard: GateCode[];
  soft: GateCode[];
  info: GateCode[];
  count?: VoteCount;
}

function tallyVotes(votes: readonly ActionVote[] | undefined, policy: GatePolicy): Tally {
  const result: Tally = { hard: [], soft: [], info: [] };
  const seen = new Set<string>();
  const approving: PanelMember[] = [];
  let rejecting = 0;

  for (const vote of votes ?? []) {
    const member = policy.panel.get(vote.voter);
    if (member === undefined) {
      result.hard.push('unknown-voter');
      continue;
    }
    if (seen.has(vote.voter)) {
      result.hard.push('duplicate-voter');
      continue;
    }
    seen.add(vote.voter);
    if (vote.decision === 'approve') approving.push(member);
    else if (vote.decision === 'reject') rejecting++;
  }
  if (result.hard.length > 0) return result;

  // Majority of the whole panel, not of the votes that came back: a dog that is
  // silent or abstains has not agreed.
  const size = policy.panel.size;
  const required = policy.rule === 'unanimous' ? size : Math.floor(size / 2) + 1;
  result.count = {
    approve: approving.length,
    reject: rejecting,
    silent: size - approving.length - rejecting,
    required,
    panelSize: size,
  };

  if (approving.length >= required) {
    const models = new Set(approving.map((member) => member.model));
    if (policy.requireDistinctModels && models.size < 2) result.soft.push('panel-not-diverse');
    else result.info.push('panel-approved');
    return result;
  }

  if (rejecting >= required) result.hard.push('panel-rejected');
  else result.soft.push('panel-split');
  // Not enough to act, but too many to ignore: tell a human even though nothing runs.
  if (approving.length >= policy.dissentAlertMin) result.info.push('minority-flag');
  return result;
}

/**
 * What a set of votes amounts to in the gate's eyes, as one comparable string:
 * the hard, soft and informational codes the tally produces. Two vote sets with
 * the same verdict lead the gate to the same place, so the panel runner can ask
 * "would the votes still outstanding change anything?" with the gate's own
 * logic instead of a copy that could drift.
 */
export function panelVerdict(votes: readonly ActionVote[], policy: GatePolicy): string {
  const tally = tallyVotes(votes, policy);
  return [
    ...tally.hard.map((code) => `hard:${code}`),
    ...tally.soft.map((code) => `soft:${code}`),
    ...tally.info.map((code) => `info:${code}`),
  ]
    .sort()
    .join(',');
}

function approvalIsValid(
  approval: HumanApproval | undefined,
  digest: string,
  now: Date,
  policy: GatePolicy,
): boolean | undefined {
  if (approval === undefined) return undefined;
  if (!policy.approvers.has(approval.approver)) return false;
  if (approval.actionDigest !== digest) return false;
  const at = Date.parse(approval.approvedAt);
  if (Number.isNaN(at)) return false;
  const age = now.getTime() - at;
  const allowedClockSkewMs = 60_000;
  return age <= policy.approvalTtlSeconds * 1000 && age >= -allowedClockSkewMs;
}

function build(
  outcome: GateOutcome,
  parts: {
    actionId: string;
    digest: string | null;
    level: ResponseLevel | null;
    votes?: VoteCount;
    codes: GateCode[];
    summary: string;
    expiresAt?: string;
  },
): GateDecision {
  const unique = [...new Set(parts.codes)];
  return {
    outcome,
    actionId: parts.actionId,
    digest: parts.digest,
    level: parts.level,
    votes: parts.votes ?? null,
    codes: unique,
    reasons: unique.map((code) => REASONS[code]),
    ...(parts.expiresAt === undefined ? {} : { expiresAt: parts.expiresAt }),
    notify: { summary: parts.summary },
  };
}

const OUTCOME_TEXT: Readonly<Record<GateOutcome, string>> = {
  execute: 'cleared to run',
  'await-human': 'waiting for a human',
  deny: 'denied',
};

export function evaluateAction(raw: unknown, ctx: GateContext, policy: GatePolicy): GateDecision {
  const checked = validateAction(raw);
  if (!checked.ok) {
    const actionId = idOf(raw);
    return build('deny', {
      actionId,
      digest: null,
      level: null,
      codes: ['schema'],
      summary: `A malformed action proposal was denied (id: ${sanitizeEvidence(actionId, 60)}).`,
    });
  }

  const action = checked.value;
  const digest = actionDigest(action);
  const hard: GateCode[] = [];
  const soft: GateCode[] = [];
  const info: GateCode[] = [];
  let count: VoteCount | undefined;

  if (action.level < MIN_LEVEL[action.kind]) hard.push('kind-level-mismatch');

  if (action.level <= 2) {
    info.push('automatic-level-1-2');
  } else {
    if (ctx.knownEvidenceIds !== undefined) {
      const known = ctx.knownEvidenceIds;
      if (action.evidence.some((id) => !known.has(id))) hard.push('unknown-evidence');
    }

    const ceilings = ctx.ceilings;
    if (ceilings !== undefined) {
      const cited = action.evidence.flatMap((id) => {
        const ceiling = ceilings.get(id);
        return ceiling === undefined ? [] : [ceiling];
      });
      if (cited.length > 0 && action.level > Math.min(...cited)) soft.push('above-intel-ceiling');
    }

    const votes = tallyVotes(action.votes, policy);
    count = votes.count;
    hard.push(...votes.hard);
    soft.push(...votes.soft);
    info.push(...votes.info);

    if (action.level === 4) {
      soft.push('requires-human-level-4');
    } else {
      const pre = policy.preApproved[action.kind];
      if (pre === undefined) {
        soft.push('not-pre-approved');
      } else {
        if (action.ttlSeconds !== undefined && action.ttlSeconds > pre.maxTtlSeconds) soft.push('ttl-exceeds-policy');
        if (!matchesAny(pre.targets, action.target)) soft.push('target-out-of-scope');
      }
    }
    if (matchesAny(policy.protectedTargets, action.target)) soft.push('protected-target');
  }

  const approval = approvalIsValid(ctx.humanApproval, digest, ctx.now, policy);
  if (approval === true) info.push('human-approved');
  if (approval === false) info.push('invalid-approval');

  const flagged = info.includes('minority-flag');
  const panelNote =
    count === undefined
      ? ''
      : `Panel: ${count.approve} of ${count.panelSize} approved (${count.required} needed), ` +
        `${count.reject} rejected, ${count.silent} did not vote. `;
  // A flag with the action running can only mean a human has since approved it, so the warning is over.
  const summaryFor = (outcome: GateOutcome): string => {
    const warn = flagged && outcome !== 'execute';
    return (
      (warn ? 'Review needed: ' : '') +
      `Level ${action.level} ${action.kind} on ${sanitizeEvidence(action.target, 80)}: ${OUTCOME_TEXT[outcome]}. ` +
      panelNote +
      (warn ? 'Several guard dogs flagged this, too few to act on. ' : '') +
      `Reason given: ${sanitizeEvidence(action.reason, 160)}`
    );
  };

  const base = {
    actionId: sanitizeEvidence(action.id, 128),
    digest,
    level: action.level,
    ...(count === undefined ? {} : { votes: count }),
  };

  if (hard.length > 0) {
    return build('deny', { ...base, codes: [...hard, ...soft, ...info], summary: summaryFor('deny') });
  }
  if (soft.length > 0 && approval !== true) {
    return build('await-human', { ...base, codes: [...soft, ...info], summary: summaryFor('await-human') });
  }

  const expiresAt =
    action.ttlSeconds === undefined ? undefined : new Date(ctx.now.getTime() + action.ttlSeconds * 1000).toISOString();
  return build('execute', {
    ...base,
    codes: [...info],
    summary: summaryFor('execute'),
    ...(expiresAt === undefined ? {} : { expiresAt }),
  });
}

/** Record a decision in the audit log. Only the decision is stored, never free text from the proposal. */
export function auditDecision(log: Pick<AuditLog, 'append'>, decision: GateDecision, actor = 'response-gate'): AuditEntry {
  return log.append({
    actor,
    type: 'gate.decision',
    data: {
      actionId: decision.actionId,
      digest: decision.digest,
      level: decision.level,
      votes: decision.votes === null ? null : { ...decision.votes },
      outcome: decision.outcome,
      codes: decision.codes,
      expiresAt: decision.expiresAt ?? null,
    },
  });
}
