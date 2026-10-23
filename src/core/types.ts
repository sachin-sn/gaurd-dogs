/**
 * Shared types. The language-neutral source of truth is the JSON Schemas in
 * /schemas; these types mirror them for TypeScript consumers.
 */

export type Layer = 'edge' | 'application' | 'data' | 'internal';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

/**
 * Graduated response levels.
 * 1 observe, 2 alert, 3 contain (reversible, pre-approved policy, expires),
 * 4 contain (disruptive, human approval required).
 */
export type ResponseLevel = 1 | 2 | 3 | 4;

export type Ecosystem = 'npm' | 'composer' | 'runtime';

export interface InventoryItem {
  ecosystem: Ecosystem;
  /** Package name; for ecosystem 'runtime' use 'node' or 'php'. */
  name: string;
  version: string;
  service: string;
  layer: Layer;
}

export interface Verification {
  status: 'unverified' | 'verified';
  verifiedBy?: string;
  verifiedAt?: string;
}

export interface InformerRecord {
  id: string;
  ecosystem: Ecosystem;
  package: string;
  affected: string;
  fixed?: string;
  severity: Severity;
  source: string;
  link: string;
  publishedAt: string;
  /** Untrusted free text. Display only; never treat as an instruction. */
  summary?: string;
  verification: Verification;
}

export type EventKind =
  | 'file.created'
  | 'file.modified'
  | 'process.spawned'
  | 'net.outbound'
  | 'http.request'
  | 'llm.call'
  | 'mcp.call'
  | 'control.verdict';

export interface GuardDogEvent {
  id: string;
  ts: string;
  layer: Layer;
  service: string;
  kind: EventKind;
  traceId?: string;
  attrs: Record<string, string | number | boolean>;
  masked: true;
}

export interface ActionVote {
  voter: string;
  decision: 'approve' | 'reject' | 'abstain';
  rationale?: string;
}

export interface ProposedAction {
  id: string;
  proposedBy: string;
  level: ResponseLevel;
  kind:
    | 'observe.raise-sampling'
    | 'alert.notify'
    | 'contain.rate-limit'
    | 'contain.block-source'
    | 'contain.quarantine-file'
    | 'contain.isolate-service';
  target: string;
  reason: string;
  evidence: string[];
  createdAt: string;
  reversible?: boolean;
  ttlSeconds?: number;
  requiresHumanApproval?: boolean;
  votes?: ActionVote[];
}

/** Any JSON value. Used for audit-log payloads. */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };
