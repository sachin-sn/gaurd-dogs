/**
 * From flagged events to something an investigator can read.
 *
 * Tier 1 flags single events. Several flags from one rule on one service are
 * one thing happening, so they are grouped into an incident. An incident that
 * triage escalates becomes a case: the events, as evidence the gate will
 * recognise by id, and the targets the investigator is allowed to name.
 *
 * The targets are the part that matters. They decide what the model can ever
 * propose to act on, so `targetsFromIncident` builds them only from attributes
 * the deployer names, and only from text that is already clean.
 */

import { createHash } from 'node:crypto';
import { SEVERITY_RANK, type EventKind, type Severity } from '../core/types.js';
import { MAX_CASE_EVIDENCE, MAX_CASE_TARGETS, type Case, type CaseEvidence, type CaseTarget, type ContainKind } from '../dogs/investigator.js';
import type { TriageItem } from '../dogs/triage.js';
import type { FlaggedHit } from '../pipeline/pipeline.js';
import { sanitizeEvidence } from '../rules/sanitize.js';

const MAX_ID = 128;
const MAX_TARGET = 256;
const TRIAGE_EVENTS = 5;

/** Several hits of one rule on one service, within one time window. */
export interface Incident {
  /** Stable for the same rule, service and window, so repeated proposals get repeated ids. */
  id: string;
  ruleId: string;
  service: string;
  /** The highest severity among its hits. */
  severity: Severity;
  /** From the most severe hit. Cleaned and capped. */
  summary: string;
  /** The hits that are listed here: most severe first, at most the grouping limit. */
  flagged: FlaggedHit[];
  /** All hits in the group, including any not listed. */
  total: number;
}

export interface GroupOptions {
  now: Date;
  /** Hits in the same window belong to the same incident. */
  windowSeconds: number;
  /** Most hits kept per incident. */
  maxEvents: number;
}

const token = (value: string, max: number): string => value.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, max);

const isClean = (value: unknown, max: number): value is string =>
  typeof value === 'string' && value.length > 0 && sanitizeEvidence(value, max) === value;

/** Group hits by rule and service. Incidents come back most severe first, then largest, then by id. */
export function groupIncidents(flagged: readonly FlaggedHit[], options: GroupOptions): Incident[] {
  const bucket = Math.floor(options.now.getTime() / (options.windowSeconds * 1000));
  const groups = new Map<string, FlaggedHit[]>();
  for (const entry of flagged) {
    const key = JSON.stringify([entry.hit.ruleId, entry.event.service]);
    const list = groups.get(key);
    if (list === undefined) groups.set(key, [entry]);
    else list.push(entry);
  }

  const incidents: Incident[] = [];
  for (const list of groups.values()) {
    const sorted = [...list].sort((a, b) => SEVERITY_RANK[b.hit.severity] - SEVERITY_RANK[a.hit.severity]);
    const head = sorted[0] as FlaggedHit;
    const { ruleId } = head.hit;
    const { service } = head.event;
    const hash = createHash('sha256').update([ruleId, service, String(bucket)].join('\u0000'), 'utf8').digest('hex').slice(0, 16);
    incidents.push({
      id: ['inc', token(ruleId, 40), token(service, 24), hash].join(':'),
      ruleId,
      service,
      severity: head.hit.severity,
      summary: sanitizeEvidence(head.hit.summary, 300),
      flagged: sorted.slice(0, options.maxEvents),
      total: sorted.length,
    });
  }
  return incidents.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.total - a.total || a.id.localeCompare(b.id));
}

/** What a reader is shown for one flagged event. Everything in it is masked, and untrusted. */
function piece(entry: FlaggedHit): CaseEvidence {
  const { hit, event } = entry;
  return {
    id: event.id,
    content: {
      rule: hit.ruleId,
      severity: hit.severity,
      ruleSummary: sanitizeEvidence(hit.summary, 200),
      flagged: hit.evidence,
      event: { kind: event.kind, layer: event.layer, service: event.service, ts: event.ts, attrs: event.attrs },
    },
  };
}

/** The item triage sees for an incident: the first few events, in full, and how many there were. */
export function triageItem(incident: Incident): TriageItem {
  return {
    id: incident.id,
    ruleId: incident.ruleId,
    service: incident.service,
    severity: incident.severity,
    summary: `${incident.summary} (${incident.total} flagged event${incident.total === 1 ? '' : 's'})`,
    evidence: { flaggedEvents: incident.total, events: incident.flagged.slice(0, TRIAGE_EVENTS).map((entry) => piece(entry).content) },
  };
}

/**
 * Hits from other incidents on the same service, to be read alongside this
 * one. A chain (an upload, then a shell, then an outbound connection) spans
 * rules, so an investigator that saw only one link could not see it.
 */
export function relatedFlagged(incident: Incident, all: readonly Incident[]): FlaggedHit[] {
  return all.filter((other) => other.id !== incident.id && other.service === incident.service).flatMap((other) => other.flagged);
}

/**
 * Turn an incident into a case. Its own events come first, then related ones,
 * up to the case limit. An event whose id is not clean text is left out (it
 * could not be cited reliably); the case is `undefined` if nothing is left or
 * there is nothing the investigator could act on.
 */
export function buildCase(incident: Incident, related: readonly FlaggedHit[], targets: readonly CaseTarget[]): Case | undefined {
  if (targets.length === 0 || !isClean(incident.id, MAX_ID)) return undefined;
  const seen = new Set<string>();
  const evidence: CaseEvidence[] = [];
  for (const entry of [...incident.flagged, ...related]) {
    if (evidence.length >= MAX_CASE_EVIDENCE) break;
    if (!isClean(entry.event.id, MAX_ID) || seen.has(entry.event.id)) continue;
    seen.add(entry.event.id);
    evidence.push(piece(entry));
  }
  if (evidence.length === 0) return undefined;

  const alongside = new Map<string, number>();
  for (const entry of related) alongside.set(entry.hit.ruleId, (alongside.get(entry.hit.ruleId) ?? 0) + 1);
  const others =
    alongside.size === 0 ? '' : ` Also flagged on this service in the same batch: ${[...alongside].map(([rule, n]) => `${rule} (${n})`).join(', ')}.`;
  const summary = `${incident.summary} ${incident.total} flagged event${incident.total === 1 ? '' : 's'} from rule ${incident.ruleId} on ${incident.service}.${others}`;
  return { id: incident.id, summary: sanitizeEvidence(summary, 600), evidence, targets };
}

/** Where to read a target from: events of these kinds, the attribute holding it, and what may be done to it. */
export interface TargetSource {
  kinds: readonly EventKind[];
  /** The attribute that holds the target, for example `path`. Read from the attribute only if it is text. */
  attr: string;
  actions: readonly ContainKind[];
}

export interface TargetOptions {
  sources: readonly TargetSource[];
  /** Also offer the incident's own service, for these kinds of action. */
  service?: readonly ContainKind[];
}

/**
 * The targets an investigator may name for an incident, read from the
 * attributes the deployer lists, in the order they appear. A value that is not
 * clean text is skipped, never repaired.
 *
 * Choose attributes an attacker cannot set freely. The address a connection
 * came from, read from the socket, is one; an address taken from a request
 * header is not, and a model argued into proposing it will block whoever the
 * attacker names.
 */
export function targetsFromIncident(incident: Incident, options: TargetOptions): CaseTarget[] {
  const found = new Map<string, Set<ContainKind>>();
  const add = (value: unknown, actions: readonly ContainKind[]): void => {
    if (!isClean(value, MAX_TARGET)) return;
    const kinds = found.get(value);
    if (kinds !== undefined) {
      for (const action of actions) kinds.add(action);
    } else if (found.size < MAX_CASE_TARGETS) {
      found.set(value, new Set(actions));
    }
  };

  for (const entry of incident.flagged) {
    for (const source of options.sources) {
      if (source.kinds.includes(entry.event.kind)) add(entry.event.attrs[source.attr], source.actions);
    }
  }
  if (options.service !== undefined) add(incident.service, options.service);
  return [...found].map(([target, kinds]) => ({ target, kinds: [...kinds] }));
}

/** Everything a dog is shown: the evidence as the investigator saw it. */
export function rawView(c: Case): unknown {
  return c.evidence.map((entry) => ({ id: entry.id, content: entry.content }));
}

const MAX_BRIEF_KEYS = 8;
const MAX_FLAGGED_KEYS = 4;

/**
 * A short form of each piece of evidence: its id, the plain values at the top
 * level of its content, and the plain values the rule itself pulled out (the
 * path, the host, the process), all trimmed. A dog that sees only this has a
 * different view from one that reads the raw events, so a payload written to
 * fool one reader is less likely to fool both. It still names what the rule
 * found: without that, a reviewer could not tell whether a proposal is aimed
 * at the right thing.
 */
export function summaryView(c: Case): unknown {
  return c.evidence.map((entry) => {
    const brief: [string, string | number | boolean][] = [];
    const content = entry.content;
    if (typeof content === 'object' && content !== null && !Array.isArray(content)) {
      for (const [key, value] of Object.entries(content).slice(0, MAX_BRIEF_KEYS)) {
        if (typeof value === 'string') brief.push([sanitizeEvidence(key, 40), sanitizeEvidence(value, 80)]);
        else if (typeof value === 'number' || typeof value === 'boolean') brief.push([sanitizeEvidence(key, 40), value]);
      }
      const flagged = (content as { flagged?: unknown }).flagged;
      if (typeof flagged === 'object' && flagged !== null && !Array.isArray(flagged)) {
        for (const [key, value] of Object.entries(flagged).slice(0, MAX_FLAGGED_KEYS)) {
          const name = `flagged.${sanitizeEvidence(key, 30)}`;
          if (typeof value === 'string') brief.push([name, sanitizeEvidence(value, 80)]);
          else if (typeof value === 'number' || typeof value === 'boolean') brief.push([name, value]);
        }
      }
    }
    // The id goes last, so nothing in the content can overwrite it.
    return { ...Object.fromEntries(brief), id: entry.id };
  });
}
