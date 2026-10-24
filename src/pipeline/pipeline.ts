import { createHash } from 'node:crypto';
import type { AuditLog } from '../audit/log.js';
import type { GuardDogEvent, InventoryItem, JsonValue, ProposedAction, ResponseLevel } from '../core/types.js';
import type { Executor, SubmitResult, SubmitStatus } from '../executor/executor.js';
import { matchAdvisories, type ExposureFinding } from '../exposure/matcher.js';
import type { Masker, MaskReport, UnmaskedEvent } from '../masking/masker.js';
import { runTier1 } from '../rules/engine.js';
import { defaultRules, defaultRulesConfig, type Rule, type RuleHit, type RulesConfig } from '../rules/rules.js';
import { sanitizeEvidence } from '../rules/sanitize.js';
import { AlertThrottle, type ThrottleOptions } from './throttle.js';

/**
 * The sidecar pipeline: what happens to an observation between the layer it
 * came from and a human or a control.
 *
 *   raw event -> mask -> tier 1 rules -> throttle -> proposal -> executor (gate, audit, act)
 *   advisory  -> validate, match inventory -> alert + ceilings
 *
 * Everything here is deterministic. No model is called. The pipeline proposes
 * only observe and alert actions (levels 1 and 2). Containment comes from the
 * investigators and their panel, which submit through `submit`.
 *
 * Trust: raw events and advisory records are untrusted. The pipeline never
 * believes a `masked` flag from the wire; it masks every event itself.
 */

export interface PipelineOptions {
  masker: Masker;
  /** Every proposal goes through the executor, and so through the gate. */
  executor: Executor;
  /** Where batch summaries go. Counts only, never event content. */
  log: Pick<AuditLog, 'append'>;
  inventory: readonly InventoryItem[];
  /** Informer sources the staging zone may feed from. */
  allowedSources: ReadonlySet<string> | readonly string[];
  rulesConfig?: RulesConfig;
  rules?: readonly Rule[];
  throttle?: ThrottleOptions;
  /** Actor name on proposals made by the pipeline itself. Default 'tier1'. */
  proposer?: string;
  /** Most events and records remembered as citable evidence. Default 10,000. */
  maxKnownEvidence?: number;
  /** Most events processed per batch; the rest are counted and dropped. Default 10,000. */
  maxBatch?: number;
  /** Most flagged events handed back in one report (see `EventReport.flagged`). Default 200; 0 hands back none. */
  maxFlagged?: number;
  clock?: () => Date;
}

/** A tier 1 hit together with the masked event that caused it, for the stages that look closer. */
export interface FlaggedHit {
  hit: RuleHit;
  /** The event as the rest of the system sees it: masked, never the raw wire copy. */
  event: GuardDogEvent;
  /**
   * What became of the alert for it: `sent` (given to the executor),
   * `duplicate` (an identical alert went out recently) or `flood` (beyond the
   * cap on different alerts per window). A hit that raised no alert of its own
   * is still real evidence, so it is still listed.
   */
  alert: 'sent' | 'duplicate' | 'flood';
}

export interface EventReport {
  received: number;
  /** Events beyond `maxBatch`, not processed. */
  dropped: number;
  /** Events that were valid and masked. */
  accepted: number;
  rejected: number;
  /** A few rejection reasons, for the operator. */
  rejectedSamples: { eventId: string; reason: string }[];
  /** What the masker removed, in total. Counts only. */
  masked: MaskReport;
  hits: number;
  /**
   * The hits of this batch with their masked events, most severe first. At most
   * `maxFlagged`; the number left out is in `flaggedDropped`. Every hit is
   * still counted in `hits` and alerted on whether or not it is listed here.
   */
  flagged: FlaggedHit[];
  flaggedDropped: number;
  /** Alerts not sent: repeats of one already sent, and alerts beyond the global cap. */
  suppressed: { duplicate: number; flood: number };
  ruleErrors: number;
  /** What the executor did with the proposals this batch produced. */
  proposals: Partial<Record<SubmitStatus, number>>;
  /** False if the batch summary could not be written to the audit log. */
  audited: boolean;
}

export interface AdvisoryReport {
  received: number;
  findings: number;
  rejected: number;
  rejectedSamples: { recordId: string; reason: string }[];
  warnings: number;
  proposals: Partial<Record<SubmitStatus, number>>;
  audited: boolean;
}

type Masked = { ok: true; event: GuardDogEvent; report: MaskReport } | { ok: false; eventId: string; reason: string };

const MAX_SAMPLES = 5;

function safeToken(value: string, max: number): string {
  return value.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, max);
}

/**
 * A stable, readable, bounded id. The hash covers everything that makes the
 * action what it is, so the same observation gets the same id (and so cannot be
 * acted on twice) while a changed one gets a new id.
 */
function actionId(prefix: string, readable: readonly string[], identity: readonly string[]): string {
  const hash = createHash('sha256').update(identity.join('\u0000'), 'utf8').digest('hex').slice(0, 16);
  return [prefix, ...readable.map((part, i) => safeToken(part, i === 0 ? 40 : 28)), hash].join(':');
}

function count(into: Partial<Record<SubmitStatus, number>>, status: SubmitStatus): void {
  into[status] = (into[status] ?? 0) + 1;
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

/** The ids of the evidence a raw proposal cites. Reads untrusted input, so it checks every step. */
function citedEvidence(raw: unknown): string[] {
  if (typeof raw !== 'object' || raw === null) return [];
  const evidence = (raw as { evidence?: unknown }).evidence;
  if (!Array.isArray(evidence)) return [];
  return evidence.filter((id): id is string => typeof id === 'string').slice(0, 100);
}

export class Pipeline {
  private readonly masker: Masker;
  private readonly executor: Executor;
  private readonly log: Pick<AuditLog, 'append'>;
  private inventory: readonly InventoryItem[];
  private readonly allowedSources: ReadonlySet<string>;
  private readonly rulesConfig: RulesConfig;
  private readonly rules: readonly Rule[];
  private readonly throttle: AlertThrottle;
  private readonly throttleWindowSeconds: number;
  private readonly throttleMax: number;
  private readonly proposer: string;
  private readonly maxKnownEvidence: number;
  private readonly maxBatch: number;
  private readonly maxFlagged: number;
  private readonly clock: () => Date;

  /** Events and records that may be cited as evidence, oldest first. */
  private readonly known = new Set<string>();
  /** How far each advisory record allows a response to go (from the matcher). */
  private readonly ceilings = new Map<string, ResponseLevel>();

  constructor(options: PipelineOptions) {
    this.masker = options.masker;
    this.executor = options.executor;
    this.log = options.log;
    this.inventory = [...options.inventory];
    this.allowedSources =
      options.allowedSources instanceof Set ? options.allowedSources : new Set(options.allowedSources);
    this.rulesConfig = options.rulesConfig ?? defaultRulesConfig;
    this.rules = options.rules ?? defaultRules;
    this.throttle = new AlertThrottle(options.throttle);
    this.throttleWindowSeconds = options.throttle?.windowSeconds ?? 300;
    this.throttleMax = options.throttle?.maxPerWindow ?? 20;
    this.proposer = options.proposer ?? 'tier1';
    this.maxKnownEvidence = options.maxKnownEvidence ?? 10_000;
    this.maxBatch = options.maxBatch ?? 10_000;
    this.maxFlagged = options.maxFlagged ?? 200;
    if (!Number.isInteger(this.maxFlagged) || this.maxFlagged < 0 || this.maxFlagged > 10_000) {
      throw new RangeError('maxFlagged must be a whole number from 0 to 10000');
    }
    this.clock = options.clock ?? (() => new Date());
  }

  /** Replace the inventory, for example after a deploy. Matching uses it from the next advisory batch. */
  setInventory(inventory: readonly InventoryItem[]): void {
    this.inventory = [...inventory];
  }

  /** True if an event or advisory record can still be cited as evidence. */
  knowsEvidence(id: string): boolean {
    return this.known.has(id);
  }

  /** How much the pipeline is remembering, for monitoring. Both numbers are bounded by `maxKnownEvidence`. */
  stats(): { knownEvidence: number; ceilings: number } {
    return { knownEvidence: this.known.size, ceilings: this.ceilings.size };
  }

  /** Raw events from one layer's sidecar. */
  async ingestEvents(raw: readonly unknown[]): Promise<EventReport> {
    const now = this.clock();
    const batch = raw.length > this.maxBatch ? raw.slice(0, this.maxBatch) : raw;
    const report: EventReport = {
      received: raw.length,
      dropped: raw.length - batch.length,
      accepted: 0,
      rejected: 0,
      rejectedSamples: [],
      masked: {},
      hits: 0,
      flagged: [],
      flaggedDropped: 0,
      suppressed: { duplicate: 0, flood: 0 },
      ruleErrors: 0,
      proposals: {},
      audited: true,
    };

    const events: GuardDogEvent[] = [];
    const serviceOf = new Map<string, string>();
    const eventById = new Map<string, GuardDogEvent>();
    for (const item of batch) {
      const masked = this.mask(item);
      if (!masked.ok) {
        report.rejected++;
        if (report.rejectedSamples.length < MAX_SAMPLES) {
          report.rejectedSamples.push({ eventId: masked.eventId, reason: masked.reason });
        }
        continue;
      }
      events.push(masked.event);
      serviceOf.set(masked.event.id, masked.event.service);
      eventById.set(masked.event.id, masked.event);
      this.remember(masked.event.id);
      for (const [kind, n] of Object.entries(masked.report) as [keyof MaskReport, number][]) {
        report.masked[kind] = (report.masked[kind] ?? 0) + n;
      }
    }
    report.accepted = events.length;

    const tier1 = runTier1(events, this.rulesConfig, this.rules);
    report.hits = tier1.hits.length;
    report.ruleErrors = tier1.ruleErrors.length;

    for (const hit of tier1.hits) {
      const service = serviceOf.get(hit.eventId) ?? 'unknown';
      const admission = this.throttle.admit(`${hit.ruleId}|${service}`, now.getTime());
      this.flag(report, hit, eventById.get(hit.eventId), admission.admit ? 'sent' : admission.reason);

      if (admission.admit) {
        const result = await this.executor.submit(this.alertFor(hit, service, admission.suppressedBefore, now));
        count(report.proposals, result.status);
      } else if (admission.reason === 'duplicate') {
        report.suppressed.duplicate++;
      } else {
        report.suppressed.flood++;
        if (admission.floodNotice) {
          const result = await this.executor.submit(this.floodNotice(hit.eventId, now));
          count(report.proposals, result.status);
        }
      }
    }

    const notable =
      report.rejected > 0 ||
      report.dropped > 0 ||
      report.hits > 0 ||
      report.ruleErrors > 0 ||
      Object.keys(report.masked).length > 0;
    if (notable) {
      report.audited = this.audit('pipeline.events', {
        received: report.received,
        dropped: report.dropped,
        accepted: report.accepted,
        rejected: report.rejected,
        masked: { ...report.masked },
        hits: report.hits,
        suppressedDuplicate: report.suppressed.duplicate,
        suppressedFlood: report.suppressed.flood,
        ruleErrors: report.ruleErrors,
      });
    }
    return report;
  }

  /** Raw informer records from the staging zone. */
  async ingestAdvisories(raw: readonly unknown[]): Promise<AdvisoryReport> {
    const now = this.clock();
    const matched = matchAdvisories(this.inventory, raw, { allowedSources: this.allowedSources });
    const report: AdvisoryReport = {
      received: raw.length,
      findings: matched.findings.length,
      rejected: matched.rejected.length,
      rejectedSamples: matched.rejected.slice(0, MAX_SAMPLES).map((r) => ({
        recordId: sanitizeEvidence(r.recordId, 128),
        reason: sanitizeEvidence(r.reason, 200),
      })),
      warnings: matched.warnings.length,
      proposals: {},
      audited: true,
    };

    for (const finding of matched.findings) {
      this.remember(finding.recordId);
      this.setCeiling(finding.recordId, finding.maxLevel);
      for (const proposal of this.proposalsFor(finding, now)) {
        const result = await this.executor.submit(proposal);
        count(report.proposals, result.status);
      }
    }

    if (report.received > 0) {
      report.audited = this.audit('pipeline.advisories', {
        received: report.received,
        findings: report.findings,
        rejected: report.rejected,
        warnings: report.warnings,
      });
    }
    return report;
  }

  /**
   * A proposal from an investigator or its panel. The pipeline tells the gate
   * which of the cited evidence exists and what ceiling each advisory record
   * allows, as they stand now. The executor keeps that snapshot, so a proposal
   * that waits for a human is judged on what was known when it was made.
   */
  async submit(raw: unknown): Promise<SubmitResult> {
    const cited = citedEvidence(raw);
    const knownEvidenceIds = new Set(cited.filter((id) => this.known.has(id)));
    const ceilings = new Map<string, ResponseLevel>();
    for (const id of cited) {
      const ceiling = this.ceilings.get(id);
      if (ceiling !== undefined) ceilings.set(id, ceiling);
    }
    return this.executor.submit(raw, { knownEvidenceIds, ceilings });
  }

  // ---- internals ----

  private mask(raw: unknown): Masked {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      return { ok: false, eventId: 'unknown', reason: 'the event is not an object' };
    }
    const candidate = raw as Record<string, unknown>;
    const id = typeof candidate['id'] === 'string' && candidate['id'].length > 0 ? sanitizeEvidence(candidate['id'], 128) : 'unknown';
    const attrs = candidate['attrs'];
    if (typeof attrs !== 'object' || attrs === null || Array.isArray(attrs)) {
      return { ok: false, eventId: id, reason: 'attrs must be an object' };
    }
    try {
      // Whatever the wire says about `masked`, the masker decides.
      const result = this.masker.maskEvent(candidate as unknown as UnmaskedEvent);
      return { ok: true, event: result.event, report: result.report };
    } catch (error) {
      return { ok: false, eventId: id, reason: sanitizeEvidence(error instanceof Error ? error.message : String(error), 200) };
    }
  }

  private flag(report: EventReport, hit: RuleHit, event: GuardDogEvent | undefined, alert: FlaggedHit['alert']): void {
    // Every hit comes from an event in this batch, so a missing one means nothing to show.
    if (event === undefined) return;
    if (report.flagged.length >= this.maxFlagged) report.flaggedDropped++;
    else report.flagged.push({ hit, event, alert });
  }

  private remember(id: string): void {
    this.known.delete(id);
    this.known.add(id);
    while (this.known.size > this.maxKnownEvidence) {
      const oldest = this.known.values().next();
      if (oldest.done === true) break;
      this.known.delete(oldest.value);
      this.ceilings.delete(oldest.value);
    }
  }

  /** The latest copy of a record wins. A record that is later verified raises its ceiling; one that changes the other way lowers it. */
  private setCeiling(recordId: string, ceiling: ResponseLevel): void {
    this.ceilings.set(recordId, ceiling);
  }

  private audit(type: string, data: Record<string, JsonValue>): boolean {
    try {
      this.log.append({ actor: 'pipeline', type, data });
      return true;
    } catch {
      return false;
    }
  }

  private base(now: Date): Pick<ProposedAction, 'proposedBy' | 'createdAt'> {
    return { proposedBy: this.proposer, createdAt: now.toISOString() };
  }

  private alertFor(hit: RuleHit, service: string, suppressedBefore: number, now: Date): ProposedAction {
    const detail = Object.entries(hit.evidence)
      .map(([key, value]) => `${sanitizeEvidence(key, 40)}=${sanitizeEvidence(value, 120)}`)
      .join('; ');
    // The human sees only the start of the reason, so what matters most goes first.
    let reason = `[${hit.severity}] ${sanitizeEvidence(hit.summary, 300)}.`;
    if (suppressedBefore > 0) {
      reason += ` ${plural(suppressedBefore, 'similar alert')} suppressed since the last one.`;
    }
    if (detail.length > 0) reason += ` Evidence: ${detail}.`;

    return {
      id: actionId('t1', [hit.ruleId, hit.eventId], [hit.ruleId, hit.eventId]),
      ...this.base(now),
      level: hit.suggestedLevel,
      kind: hit.suggestedLevel === 1 ? 'observe.raise-sampling' : 'alert.notify',
      target: service,
      reason: reason.slice(0, 1000),
      evidence: [hit.eventId],
    };
  }

  private floodNotice(eventId: string, now: Date): ProposedAction {
    const bucket = Math.floor(now.getTime() / (this.throttleWindowSeconds * 1000));
    return {
      id: actionId('flood', [], [String(bucket)]),
      ...this.base(now),
      level: 2,
      kind: 'alert.notify',
      target: 'pipeline',
      reason:
        `More than ${this.throttleMax} different alerts in ${this.throttleWindowSeconds} seconds. ` +
        'Further alerts in this window are being counted, not sent; the counts are in the audit log. ' +
        'This can mean an attack, or a broken event source.',
      evidence: [eventId],
    };
  }

  private proposalsFor(finding: ExposureFinding, now: Date): ProposedAction[] {
    const record = sanitizeEvidence(finding.recordId, 128);
    // Anything a human would want a fresh alert for changes the id: a higher
    // severity, a fix becoming available, or the record being verified (the
    // reasons say whether it is). The same record polled again does not.
    const identity = [
      finding.recordId,
      finding.service,
      finding.package,
      finding.installedVersion,
      finding.severity,
      finding.fixedVersion ?? '',
      finding.reasons.join('|'),
    ];
    const fixed = finding.fixedVersion === undefined ? '' : `, fixed in ${sanitizeEvidence(finding.fixedVersion, 40)}`;
    const alert: ProposedAction = {
      id: actionId('exp', [finding.recordId, finding.service], identity),
      ...this.base(now),
      level: 2,
      kind: 'alert.notify',
      target: finding.service,
      reason: (
        `${finding.severity} advisory ${record} affects ${sanitizeEvidence(finding.package, 80)} ` +
        `${sanitizeEvidence(finding.installedVersion, 40)} on ${sanitizeEvidence(finding.service, 80)}${fixed}. ` +
        (finding.needsHumanVerification
          ? 'Critical and unverified: a human must verify it before any containment. '
          : '') +
        `Intel: ${finding.reasons.map((r) => sanitizeEvidence(r, 120)).join('; ')}. ` +
        `Details: ${sanitizeEvidence(finding.link, 200)}`
      ).slice(0, 1000),
      evidence: [finding.recordId],
    };
    if (!finding.raiseSampling) return [alert];

    const sampling: ProposedAction = {
      id: actionId('expsample', [finding.recordId, finding.service], identity),
      ...this.base(now),
      level: 1,
      kind: 'observe.raise-sampling',
      target: finding.service,
      reason: `Look harder at ${sanitizeEvidence(finding.service, 80)} while ${record} is unpatched.`,
      evidence: [finding.recordId],
    };
    return [alert, sampling];
  }
}
