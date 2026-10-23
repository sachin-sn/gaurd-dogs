import semver from 'semver';
import { validateInformerRecord } from '../core/validate.js';
import {
  SEVERITY_RANK,
  type InformerRecord,
  type InventoryItem,
  type ResponseLevel,
  type Severity,
} from '../core/types.js';

export interface MatchOptions {
  /**
   * Informer sources the staging zone is allowed to feed from. A record from any
   * other source is dropped unless a human has verified it.
   */
  allowedSources: ReadonlySet<string>;
}

export interface ExposureFinding {
  recordId: string;
  ecosystem: InformerRecord['ecosystem'];
  package: string;
  installedVersion: string;
  fixedVersion?: string;
  service: string;
  layer: InventoryItem['layer'];
  severity: Severity;
  link: string;
  /**
   * Ceiling on how far any automatic response may go on the strength of this
   * finding alone. Unverified intel can never exceed 2 (alert). Level 3 needs a
   * human-verified high or critical record. Level 4 is never automatic.
   */
  maxLevel: ResponseLevel;
  /** Ask the drift patrol to look harder at this service (cheap, reversible). */
  raiseSampling: boolean;
  /** A critical record that no human has verified yet. */
  needsHumanVerification: boolean;
  reasons: string[];
}

export interface Rejection {
  /** The record id when it could be read, otherwise 'unknown'. */
  recordId: string;
  reason: string;
}

export interface MatchResult {
  findings: ExposureFinding[];
  rejected: Rejection[];
  /** Problems with the local inventory, e.g. a version that cannot be parsed. */
  warnings: string[];
}

function idOf(raw: unknown): string {
  if (typeof raw === 'object' && raw !== null && 'id' in raw) {
    const id = (raw as { id: unknown }).id;
    if (typeof id === 'string' && id.length > 0) return id.slice(0, 128);
  }
  return 'unknown';
}

/** Composer-style "a, b" AND constraints become semver's space-separated form. */
export function normalizeRange(range: string): string | null {
  const candidate = range.replace(/,/g, ' ').trim();
  return semver.validRange(candidate) === null ? null : candidate;
}

function toSemver(version: string): string | null {
  return semver.valid(version) ?? semver.coerce(version)?.version ?? null;
}

function ceilingFor(record: InformerRecord): ResponseLevel {
  const verified = record.verification.status === 'verified';
  const serious = SEVERITY_RANK[record.severity] >= SEVERITY_RANK.high;
  return verified && serious ? 3 : 2;
}

/**
 * Match informer records against the local inventory.
 *
 * Records cross a trust boundary (they come from the staging zone), so they are
 * taken as `unknown`, validated against the schema, and checked against the
 * source allow-list before they are allowed to influence anything. Matching is
 * deterministic; no model is involved.
 */
export function matchAdvisories(
  inventory: readonly InventoryItem[],
  rawRecords: readonly unknown[],
  options: MatchOptions,
): MatchResult {
  const findings = new Map<string, ExposureFinding>();
  const rejected: Rejection[] = [];
  const warnings: string[] = [];

  const installed = inventory.map((item) => ({ item, parsed: toSemver(item.version) }));
  for (const { item, parsed } of installed) {
    if (parsed === null) {
      warnings.push(
        `cannot parse version "${item.version}" of ${item.name} in ${item.service}; it was not matched`,
      );
    }
  }

  for (const raw of rawRecords) {
    const checked = validateInformerRecord(raw);
    if (!checked.ok) {
      rejected.push({ recordId: idOf(raw), reason: `schema: ${checked.errors.join('; ')}` });
      continue;
    }
    const record = checked.value;
    const verified = record.verification.status === 'verified';

    if (!verified && !options.allowedSources.has(record.source)) {
      rejected.push({
        recordId: record.id,
        reason: `source "${record.source}" is not allow-listed and the record is not human-verified`,
      });
      continue;
    }

    const range = normalizeRange(record.affected);
    if (range === null) {
      rejected.push({ recordId: record.id, reason: `invalid version range "${record.affected}"` });
      continue;
    }

    for (const { item, parsed } of installed) {
      if (parsed === null) continue;
      if (item.ecosystem !== record.ecosystem) continue;
      if (item.name.toLowerCase() !== record.package.toLowerCase()) continue;
      if (!semver.satisfies(parsed, range, { includePrerelease: true })) continue;

      // A range with no upper bound can over-match. Trust the stated fix.
      const fixed = record.fixed === undefined ? null : toSemver(record.fixed);
      if (fixed !== null && semver.gte(parsed, fixed)) continue;

      const reasons = [
        verified
          ? `verified by ${record.verification.verifiedBy ?? 'a human'}`
          : `from allow-listed source "${record.source}", not human-verified`,
      ];
      const needsHumanVerification = record.severity === 'critical' && !verified;
      if (needsHumanVerification) {
        reasons.push('critical record awaiting human verification: observe and alert only');
      }

      const finding: ExposureFinding = {
        recordId: record.id,
        ecosystem: record.ecosystem,
        package: record.package,
        installedVersion: item.version,
        ...(record.fixed === undefined ? {} : { fixedVersion: record.fixed }),
        service: item.service,
        layer: item.layer,
        severity: record.severity,
        link: record.link,
        maxLevel: ceilingFor(record),
        raiseSampling: SEVERITY_RANK[record.severity] >= SEVERITY_RANK.high,
        needsHumanVerification,
        reasons,
      };

      const key = `${record.id}|${item.service}|${item.name}|${item.version}`;
      const existing = findings.get(key);
      // The same record can arrive twice; keep the more trusted copy.
      if (existing === undefined || finding.maxLevel > existing.maxLevel) {
        findings.set(key, finding);
      }
    }
  }

  const ordered = [...findings.values()].sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      a.service.localeCompare(b.service) ||
      a.recordId.localeCompare(b.recordId),
  );

  return { findings: ordered, rejected, warnings };
}
