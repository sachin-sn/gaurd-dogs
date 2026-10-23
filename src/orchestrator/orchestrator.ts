/**
 * The orchestrator: one cycle from flagged events to submitted proposals.
 *
 *   flagged hits -> incidents -> triage (tier 2) -> cases -> investigators (tier 3)
 *                -> panel votes -> pipeline.submit (gate, audit, executor)
 *
 * It decides nothing about the world. Every stage already has its own limits:
 * triage can only escalate, an investigator can only propose from a case's
 * targets and evidence, the panel needs a majority of the whole panel, and the
 * gate and executor decide what runs. What the orchestrator adds is the
 * plumbing between them, and the limits on how much it spends:
 *
 * - **A budget on investigations.** Every investigation is several model calls
 *   and a panel review is up to nine more, and the events that start them can
 *   be fabricated. A window allows only so many cases. Beyond it escalated
 *   incidents are not investigated, and one notice per window says so, so a
 *   flood cannot quietly use up the budget or hide what comes after it. The
 *   tier 1 alert for each of them has already gone out.
 * - **No second panel for the same proposal.** A proposal that was applied or
 *   is waiting for a human is not put to the panel again for a while; the
 *   executor would call it a duplicate anyway, after the models had been paid.
 * - **A failure stays where it happened.** A model that fails, a view that
 *   throws or a case with nothing to act on loses that step for that case and
 *   is counted. It never stops the other cases and never throws out of a cycle.
 *
 * What it does not do is vouch for the targets. They come from the
 * deployer's `targets` function (see `targetsFromIncident`), and a target an
 * attacker can choose is a target a model can be argued into.
 */

import type { AuditLog } from '../audit/log.js';
import type { JsonValue, ProposedAction } from '../core/types.js';
import type { SubmitResult, SubmitStatus } from '../executor/executor.js';
import type { GatePolicy } from '../gate/policy.js';
import type { Case, CaseTarget, Investigation, Investigator } from '../dogs/investigator.js';
import { MAX_TRIAGE_ITEMS, type TriageDog } from '../dogs/triage.js';
import { withVotes, type Panel } from '../panel/panel.js';
import type { EventReport, FlaggedHit, Pipeline } from '../pipeline/pipeline.js';
import { buildCase, groupIncidents, relatedFlagged, triageItem, type Incident } from './incidents.js';

export const MAX_INVESTIGATORS = 3;
const MAX_CONCURRENCY = 10;
const MAX_HANDLED = 1_000;

export type ViewBuilder = (c: Case) => unknown;

export interface OrchestratorOptions {
  /** Where flagged events come from and where proposals go. */
  pipeline: Pick<Pipeline, 'ingestEvents' | 'submit'>;
  /** The gate policy the panel runs under. Used to check that every dog's evidence view exists. */
  policy: GatePolicy;
  panel: Pick<Panel, 'review'>;
  /** One to three, with distinct ids. Use models of different families. Each looks at every case. */
  investigators: readonly Pick<Investigator, 'id' | 'investigate'>[];
  /** Optional. Without it every incident goes to the investigators. */
  triage?: Pick<TriageDog, 'review'>;
  /**
   * What an incident may be acted on through. This decides what a model can
   * ever propose to touch, so build it from fields an attacker cannot choose
   * (see `targetsFromIncident`). An incident with no targets is not investigated.
   */
  targets: (incident: Incident) => readonly CaseTarget[];
  /** The evidence each panel dog sees, by the view name the policy gives that dog. Every view the policy uses is required. */
  views: Readonly<Record<string, ViewBuilder>>;
  /** Where to record each cycle. Counts only. A failed write is reported, never thrown. */
  log?: Pick<AuditLog, 'append'>;
  /** Most incidents considered per cycle; the rest are counted. Default and maximum 20. */
  maxIncidents?: number;
  /** Most flagged events kept per incident. Default 10. */
  maxEventsPerIncident?: number;
  /** Hits within this many seconds are one incident, and give a proposal the same id. Default 900. */
  incidentWindowSeconds?: number;
  /** The investigation budget: at most `maxCases` cases per window. Defaults 20 per 600 seconds. */
  budget?: { windowSeconds?: number; maxCases?: number };
  /** Most distinct proposals per case that go to the panel, least disruptive first. Default 2. */
  maxProposalsPerCase?: number;
  /** Cases worked on at once. Default 3, at most 10. */
  concurrency?: number;
  /** How long a proposal that was applied or is waiting for a human is kept from the panel. Default 900 seconds. */
  handledSeconds?: number;
  clock?: () => Date;
}

export interface CaseOutcome {
  incident: string;
  investigators: { id: string; outcome: Investigation['outcome'] | 'error'; status: string }[];
  proposals: {
    id: string;
    kind: ProposedAction['kind'];
    level: ProposedAction['level'];
    /** What the panel's votes amount to, as the gate will read them. Absent if the panel was not asked. */
    verdict?: string;
    /** What the executor did with it. Absent if it was not submitted. */
    status?: SubmitStatus;
    /** Why it did not get that far, when it did not. */
    skipped?: 'already-handled' | 'over-cap' | 'cancelled' | 'error';
  }[];
}

export interface CycleReport {
  incidents: number;
  skipped: {
    /** Incidents beyond `maxIncidents`. */
    overCycle: number;
    /** Escalated incidents with no targets or no usable evidence. */
    noCase: number;
    /** Escalated incidents left uninvestigated because the budget was spent. */
    overBudget: number;
  };
  /** Null when there is no triage, or it failed (every incident then goes on). */
  triage: { escalated: number; routine: number; fallbacks: number } | null;
  /** One per case that was investigated, in order. */
  cases: CaseOutcome[];
  investigations: { proposal: number; noAction: number; failed: number; errors: number };
  proposals: { distinct: number; duplicate: number; overCap: number; alreadyHandled: number };
  panels: number;
  submitted: Partial<Record<SubmitStatus, number>>;
  /** Budget notices submitted this cycle (at most one per window). */
  notices: number;
  /** Steps that threw instead of answering. */
  errors: number;
  /** True if the caller cancelled and work was left undone. */
  cancelled: boolean;
  /** False if the cycle's audit entry could not be written. */
  audited: boolean;
}

interface Candidate {
  incident: Incident;
  case: Case;
}

const count = (into: Partial<Record<SubmitStatus, number>>, status: SubmitStatus): void => {
  into[status] = (into[status] ?? 0) + 1;
};

// A function, so the check is made again after each await rather than remembered from before it.
const isCancelled = (signal: AbortSignal | undefined): boolean => signal?.aborted === true;

const LEVEL_ORDER = (a: ProposedAction, b: ProposedAction): number => a.level - b.level;

export class Orchestrator {
  private readonly pipeline: Pick<Pipeline, 'ingestEvents' | 'submit'>;
  private readonly panel: Pick<Panel, 'review'>;
  private readonly investigators: readonly Pick<Investigator, 'id' | 'investigate'>[];
  private readonly triage: Pick<TriageDog, 'review'> | undefined;
  private readonly targets: OrchestratorOptions['targets'];
  private readonly views: Readonly<Record<string, ViewBuilder>>;
  private readonly log: Pick<AuditLog, 'append'> | undefined;
  private readonly maxIncidents: number;
  private readonly maxEvents: number;
  private readonly incidentWindowSeconds: number;
  private readonly budgetWindowMs: number;
  private readonly maxCases: number;
  private readonly maxProposals: number;
  private readonly concurrency: number;
  private readonly handledMs: number;
  private readonly clock: () => Date;

  /** Budget state. The bucket only moves forward, so a late cycle cannot refill it. */
  private bucket = -1;
  private spent = 0;
  private noticedBucket = -1;
  /** Proposals not to put to the panel again, by id, until the time given. */
  private readonly handled = new Map<string, number>();

  constructor(options: OrchestratorOptions) {
    this.pipeline = options.pipeline;
    this.panel = options.panel;
    this.triage = options.triage;
    this.targets = options.targets;
    this.log = options.log;
    this.clock = options.clock ?? (() => new Date());

    if (options.investigators.length < 1 || options.investigators.length > MAX_INVESTIGATORS) {
      throw new RangeError(`use 1 to ${MAX_INVESTIGATORS} investigators`);
    }
    if (new Set(options.investigators.map((investigator) => investigator.id)).size !== options.investigators.length) {
      throw new RangeError('investigators need distinct ids');
    }
    this.investigators = [...options.investigators];

    const views = { ...options.views };
    const missing = [...new Set([...options.policy.panel.values()].map((member) => member.evidenceView))].filter(
      (view) => !Object.hasOwn(views, view) || typeof views[view] !== 'function',
    );
    if (missing.length > 0) throw new RangeError(`the panel's dogs read these evidence views, but no view is given for: ${missing.join(', ')}`);
    this.views = views;

    const whole = (name: string, value: number, min: number, max: number): number => {
      if (!Number.isInteger(value) || value < min || value > max) throw new RangeError(`${name} must be a whole number from ${min} to ${max}`);
      return value;
    };
    this.maxIncidents = whole('maxIncidents', options.maxIncidents ?? MAX_TRIAGE_ITEMS, 1, MAX_TRIAGE_ITEMS);
    this.maxEvents = whole('maxEventsPerIncident', options.maxEventsPerIncident ?? 10, 1, 50);
    this.incidentWindowSeconds = whole('incidentWindowSeconds', options.incidentWindowSeconds ?? 900, 1, 86_400);
    this.budgetWindowMs = whole('budget.windowSeconds', options.budget?.windowSeconds ?? 600, 1, 86_400) * 1000;
    this.maxCases = whole('budget.maxCases', options.budget?.maxCases ?? 20, 0, 10_000);
    this.maxProposals = whole('maxProposalsPerCase', options.maxProposalsPerCase ?? 2, 1, 10);
    this.concurrency = whole('concurrency', options.concurrency ?? 3, 1, MAX_CONCURRENCY);
    this.handledMs = whole('handledSeconds', options.handledSeconds ?? 900, 1, 86_400) * 1000;
  }

  /** Ingest a batch of raw events and respond to whatever it flags. */
  async process(raw: readonly unknown[], signal?: AbortSignal): Promise<{ events: EventReport; response: CycleReport }> {
    const events = await this.pipeline.ingestEvents(raw);
    const response = await this.handle(events.flagged, signal);
    return { events, response };
  }

  /** Respond to flagged events. Throws nothing because of a model, a view, the panel or the executor. */
  async handle(flagged: readonly FlaggedHit[], signal?: AbortSignal): Promise<CycleReport> {
    const now = this.clock();
    const report: CycleReport = {
      incidents: 0,
      skipped: { overCycle: 0, noCase: 0, overBudget: 0 },
      triage: null,
      cases: [],
      investigations: { proposal: 0, noAction: 0, failed: 0, errors: 0 },
      proposals: { distinct: 0, duplicate: 0, overCap: 0, alreadyHandled: 0 },
      panels: 0,
      submitted: {},
      notices: 0,
      errors: 0,
      cancelled: false,
      audited: true,
    };
    if (flagged.length === 0) return report;

    const all = groupIncidents(flagged, { now, windowSeconds: this.incidentWindowSeconds, maxEvents: this.maxEvents });
    report.incidents = all.length;
    const considered = all.slice(0, this.maxIncidents);
    report.skipped.overCycle = all.length - considered.length;

    const escalated = await this.triageStep(considered, signal, report);
    const candidates = this.casesFor(escalated, considered, report);
    const admitted = this.admit(candidates, now, report);
    if (report.skipped.overBudget > 0) await this.notice(candidates.slice(admitted.length), now, report);

    const outcomes: (CaseOutcome | undefined)[] = new Array<CaseOutcome | undefined>(admitted.length);
    await this.pool(admitted, async (candidate, index) => {
      outcomes[index] = await this.work(candidate, now, signal, report);
    });
    report.cases = outcomes.filter((outcome): outcome is CaseOutcome => outcome !== undefined);
    report.cancelled = isCancelled(signal);

    report.audited = this.audit(report);
    return report;
  }

  // ---- stages ----

  private async triageStep(incidents: readonly Incident[], signal: AbortSignal | undefined, report: CycleReport): Promise<Incident[]> {
    if (this.triage === undefined) return [...incidents];
    try {
      const result = await this.triage.review(incidents.map(triageItem), signal);
      report.triage = { escalated: result.escalated, routine: result.routine, fallbacks: result.fallbacks };
      const verdicts = new Map(result.verdicts.map((verdict) => [verdict.id, verdict.decision]));
      // Anything triage did not clearly call routine goes on.
      return incidents.filter((incident) => verdicts.get(incident.id) !== 'routine');
    } catch {
      report.errors++;
      return [...incidents];
    }
  }

  private casesFor(escalated: readonly Incident[], considered: readonly Incident[], report: CycleReport): Candidate[] {
    const candidates: Candidate[] = [];
    for (const incident of escalated) {
      let targets: readonly CaseTarget[] = [];
      try {
        targets = this.targets(incident);
      } catch {
        report.errors++;
      }
      const built = buildCase(incident, relatedFlagged(incident, considered), targets);
      if (built === undefined) report.skipped.noCase++;
      else candidates.push({ incident, case: built });
    }
    return candidates;
  }

  /**
   * Spend the window's budget on as many candidates as it allows, most severe
   * first (they arrive in that order). Checked and spent in one synchronous
   * step, so overlapping cycles cannot both spend the same allowance.
   */
  private admit(candidates: readonly Candidate[], now: Date, report: CycleReport): Candidate[] {
    const bucket = Math.floor(now.getTime() / this.budgetWindowMs);
    if (bucket > this.bucket) {
      this.bucket = bucket;
      this.spent = 0;
    }
    const room = Math.max(0, this.maxCases - this.spent);
    const admitted = candidates.slice(0, room);
    this.spent += admitted.length;
    report.skipped.overBudget = candidates.length - admitted.length;
    return admitted;
  }

  /** One notice per window, so being over budget is never silent and never loud. */
  private async notice(left: readonly Candidate[], now: Date, report: CycleReport): Promise<void> {
    if (this.noticedBucket >= this.bucket) return;
    this.noticedBucket = this.bucket;
    const first = left[0]?.case.evidence[0];
    if (first === undefined) return;
    const action: ProposedAction = {
      id: `orch:budget:${this.bucket}`,
      proposedBy: 'orchestrator',
      level: 2,
      kind: 'alert.notify',
      target: 'orchestrator',
      reason:
        `[high] ${left.length} escalated incident${left.length === 1 ? '' : 's'} not investigated: the investigation budget ` +
        `(${this.maxCases} per ${this.budgetWindowMs / 1000} seconds) is spent. Their tier 1 alerts were sent. ` +
        'This can mean an attack, or a noisy event source.',
      evidence: [first.id],
      createdAt: now.toISOString(),
    };
    try {
      await this.pipeline.submit(action);
      report.notices++;
    } catch {
      report.errors++;
    }
  }

  private async work(candidate: Candidate, now: Date, signal: AbortSignal | undefined, report: CycleReport): Promise<CaseOutcome> {
    const outcome: CaseOutcome = { incident: candidate.incident.id, investigators: [], proposals: [] };
    if (isCancelled(signal)) return outcome;

    const results = await Promise.all(
      this.investigators.map(async (investigator): Promise<Investigation | undefined> => {
        try {
          return await investigator.investigate(candidate.case, signal);
        } catch {
          report.investigations.errors++;
          report.errors++;
          return undefined;
        }
      }),
    );

    const found: ProposedAction[] = [];
    const seen = new Set<string>();
    results.forEach((result, index) => {
      const id = (this.investigators[index] as { id: string }).id;
      if (result === undefined) {
        outcome.investigators.push({ id, outcome: 'error', status: 'threw' });
        return;
      }
      outcome.investigators.push({ id, outcome: result.outcome, status: result.status });
      if (result.outcome === 'proposal') report.investigations.proposal++;
      else if (result.outcome === 'no-action') report.investigations.noAction++;
      else report.investigations.failed++;
      if (result.action === undefined) return;
      if (seen.has(result.action.id)) report.proposals.duplicate++;
      else {
        seen.add(result.action.id);
        found.push(result.action);
      }
    });
    report.proposals.distinct += found.length;

    // The gentlest first, so the cap cuts the most disruptive.
    found.sort(LEVEL_ORDER);
    const views = this.viewsFor(candidate.case, report);
    for (const [index, action] of found.entries()) {
      const entry: CaseOutcome['proposals'][number] = { id: action.id, kind: action.kind, level: action.level };
      outcome.proposals.push(entry);
      if (index >= this.maxProposals) {
        entry.skipped = 'over-cap';
        report.proposals.overCap++;
      } else if (this.isHandled(action.id, now)) {
        entry.skipped = 'already-handled';
        report.proposals.alreadyHandled++;
      } else if (isCancelled(signal)) {
        entry.skipped = 'cancelled';
      } else {
        await this.putToPanel(action, views, entry, now, signal, report);
      }
    }
    return outcome;
  }

  private async putToPanel(
    action: ProposedAction,
    views: Record<string, unknown>,
    entry: CaseOutcome['proposals'][number],
    now: Date,
    signal: AbortSignal | undefined,
    report: CycleReport,
  ): Promise<void> {
    let submitted: SubmitResult;
    try {
      report.panels++;
      const reviewed = await this.panel.review({ action, evidence: views });
      entry.verdict = reviewed.verdict;
      if (isCancelled(signal)) {
        entry.skipped = 'cancelled';
        return;
      }
      submitted = await this.pipeline.submit(withVotes(action, reviewed));
    } catch {
      report.errors++;
      entry.skipped = 'error';
      return;
    }
    entry.status = submitted.status;
    count(report.submitted, submitted.status);
    if (submitted.status === 'applied' || submitted.status === 'pending-human') this.markHandled(action.id, now);
  }

  /** The evidence for each view the panel reads. A view that throws is left empty, and the dog abstains on nothing. */
  private viewsFor(c: Case, report: CycleReport): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const [name, build] of Object.entries(this.views)) {
      try {
        out[name] = build(c);
      } catch {
        report.errors++;
      }
    }
    return out;
  }

  private isHandled(id: string, now: Date): boolean {
    const until = this.handled.get(id);
    if (until === undefined) return false;
    if (until <= now.getTime()) {
      this.handled.delete(id);
      return false;
    }
    return true;
  }

  private markHandled(id: string, now: Date): void {
    this.handled.delete(id);
    this.handled.set(id, now.getTime() + this.handledMs);
    while (this.handled.size > MAX_HANDLED) {
      const oldest = this.handled.keys().next();
      if (oldest.done === true) break;
      this.handled.delete(oldest.value);
    }
  }

  private async pool<T>(items: readonly T[], run: (item: T, index: number) => Promise<void>): Promise<void> {
    let next = 0;
    const worker = async (): Promise<void> => {
      while (next < items.length) {
        const index = next++;
        await run(items[index] as T, index);
      }
    };
    await Promise.all(Array.from({ length: Math.min(this.concurrency, items.length) }, worker));
  }

  private audit(report: CycleReport): boolean {
    if (this.log === undefined) return true;
    const data: Record<string, JsonValue> = {
      incidents: report.incidents,
      skipped: { ...report.skipped },
      triage: report.triage === null ? null : { ...report.triage },
      cases: report.cases.length,
      investigations: { ...report.investigations },
      proposals: { ...report.proposals },
      panels: report.panels,
      submitted: Object.fromEntries(Object.entries(report.submitted)),
      notices: report.notices,
      errors: report.errors,
      cancelled: report.cancelled,
    };
    try {
      this.log.append({ actor: 'orchestrator', type: 'orchestrator.cycle', data });
      return true;
    } catch {
      return false;
    }
  }
}
