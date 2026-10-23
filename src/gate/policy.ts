import type { ProposedAction, ResponseLevel } from '../core/types.js';

export type ActionKind = ProposedAction['kind'];

/**
 * The lowest response level an action kind may be proposed at. A proposal
 * labelled with a lower level than its kind demands is a mislabel (or an
 * attempt to dodge the checks for a higher level) and is denied.
 */
export const MIN_LEVEL: Readonly<Record<ActionKind, ResponseLevel>> = {
  'observe.raise-sampling': 1,
  'alert.notify': 2,
  'contain.rate-limit': 3,
  'contain.block-source': 3,
  'contain.quarantine-file': 3,
  'contain.isolate-service': 4,
};

/** Kinds that policy may pre-approve for automatic level 3 containment. */
const PRE_APPROVABLE: readonly ActionKind[] = [
  'contain.rate-limit',
  'contain.block-source',
  'contain.quarantine-file',
];

export interface PanelMember {
  id: string;
  /** The model behind this guard dog. Panels should not all share one. */
  model: string;
  /** Which slice of the evidence this guard dog sees (for example "raw-logs" or "summaries"). */
  evidenceView: string;
}

export interface PreApproval {
  /** Longest containment the gate may start without a human. */
  maxTtlSeconds: number;
  /** Targets this kind may touch automatically, as globs where `*` matches anything. */
  targets: readonly string[];
}

export interface GatePolicyInput {
  /** The panel: at least two guard dogs with distinct ids. */
  panel: readonly PanelMember[];
  /**
   * How votes combine. Default: unanimous for a panel of two, majority for
   * three or more. A split always goes to a human.
   */
  rule?: 'unanimous' | 'majority';
  /** Require the approving members to span at least two models. Default true. */
  requireDistinctModels?: boolean;
  /** Level 3 actions that may run automatically, per kind. Anything else waits for a human. */
  preApproved?: Partial<Record<ActionKind, PreApproval>>;
  /**
   * Targets that are never contained automatically, such as the guard dogs'
   * own services, the audit log and the alert sink. A human can still approve.
   */
  protectedTargets?: readonly string[];
  /** Humans whose approval the gate accepts. */
  approvers?: readonly string[];
  /** How long a human approval stays valid. Default 3600. */
  approvalTtlSeconds?: number;
}

export interface GatePolicy {
  readonly panel: ReadonlyMap<string, PanelMember>;
  readonly rule: 'unanimous' | 'majority';
  readonly requireDistinctModels: boolean;
  readonly preApproved: Readonly<Partial<Record<ActionKind, PreApproval>>>;
  readonly protectedTargets: readonly string[];
  readonly approvers: ReadonlySet<string>;
  readonly approvalTtlSeconds: number;
}

const MAX_PATTERN_LENGTH = 256;

function checkPatterns(patterns: readonly string[], label: string): void {
  for (const pattern of patterns) {
    if (pattern.length === 0 || pattern.length > MAX_PATTERN_LENGTH) {
      throw new RangeError(`${label}: patterns must be 1 to ${MAX_PATTERN_LENGTH} characters`);
    }
  }
}

/** Validate a policy once, up front, so the gate never runs on a nonsensical one. */
export function createGatePolicy(input: GatePolicyInput): GatePolicy {
  const panel = new Map<string, PanelMember>();
  for (const member of input.panel) {
    if (member.id.length === 0 || member.model.length === 0 || member.evidenceView.length === 0) {
      throw new RangeError('panel members need an id, a model and an evidence view');
    }
    if (panel.has(member.id)) throw new RangeError(`duplicate panel member "${member.id}"`);
    panel.set(member.id, { ...member });
  }
  if (panel.size < 2) throw new RangeError('a panel needs at least two guard dogs');

  const rule = input.rule ?? (panel.size === 2 ? 'unanimous' : 'majority');
  if (panel.size === 2 && rule === 'majority') {
    throw new RangeError('majority voting needs a panel of at least three; use unanimous for two');
  }

  const preApproved: Partial<Record<ActionKind, PreApproval>> = {};
  for (const [kind, approval] of Object.entries(input.preApproved ?? {}) as [ActionKind, PreApproval][]) {
    if (!PRE_APPROVABLE.includes(kind)) {
      throw new RangeError(`"${kind}" cannot be pre-approved; only level 3 containment can`);
    }
    if (!Number.isInteger(approval.maxTtlSeconds) || approval.maxTtlSeconds < 1 || approval.maxTtlSeconds > 86_400) {
      throw new RangeError(`${kind}: maxTtlSeconds must be a whole number from 1 to 86400`);
    }
    if (approval.targets.length === 0) throw new RangeError(`${kind}: list at least one target`);
    checkPatterns(approval.targets, kind);
    if (approval.targets.some((pattern) => /^\*+$/.test(pattern))) {
      throw new RangeError(`${kind}: a bare "*" would pre-approve every target`);
    }
    preApproved[kind] = { maxTtlSeconds: approval.maxTtlSeconds, targets: [...approval.targets] };
  }

  const protectedTargets = [...(input.protectedTargets ?? [])];
  checkPatterns(protectedTargets, 'protectedTargets');

  const approvalTtlSeconds = input.approvalTtlSeconds ?? 3600;
  if (!Number.isInteger(approvalTtlSeconds) || approvalTtlSeconds < 1 || approvalTtlSeconds > 86_400) {
    throw new RangeError('approvalTtlSeconds must be a whole number from 1 to 86400');
  }

  return {
    panel,
    rule,
    requireDistinctModels: input.requireDistinctModels ?? true,
    preApproved,
    protectedTargets,
    approvers: new Set(input.approvers ?? []),
    approvalTtlSeconds,
  };
}
