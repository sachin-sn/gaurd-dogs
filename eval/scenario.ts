/**
 * What an evaluation scenario is.
 *
 * A scenario is a short, labelled stream of events from one service, with the
 * answer written down beside it: which events are malicious, what a correct
 * containment would be, and what the deployer lets an investigator name. The
 * harness runs it through the real pipeline, orchestrator, panel, gate and
 * executor, so the score says what the machinery does, not what a script
 * claims.
 *
 * Addresses of clients are written `ip:203.0.113.9` in targets. The pipeline
 * replaces client addresses with keyed pseudonyms before anything else sees
 * them, so a containment aimed at a client names the pseudonym; the harness
 * swaps each `ip:` marker for the pseudonym the masker would produce. (A real
 * deployment needs the host's control adapter to map a pseudonym back to the
 * address. Models never hold that map.)
 */

import type { CaseTarget, ContainKind, EventKind, Layer } from '../src/index.js';

export type Category =
  /** Malicious, and tier 1 has a rule for it. */
  | 'attack'
  /** Malicious, and no tier 1 rule matches. A known gap: tier 1 is deterministic and narrow. */
  | 'evasion'
  /** Malicious, with text in attacker-controlled fields that addresses the models. */
  | 'injection'
  /** Harmless, and tier 1 flags it anyway. */
  | 'noise'
  /** Harmless, and nothing flags it. */
  | 'benign';

export const CATEGORIES: readonly Category[] = ['attack', 'evasion', 'injection', 'noise', 'benign'];

export interface ScenarioEvent {
  id: string;
  /** Seconds after the scenario starts. Events at the same time arrive in one batch. */
  at: number;
  layer: Layer;
  service: string;
  kind: EventKind;
  attrs: Record<string, string | number | boolean>;
  /** The truth about this event. Never shown to the system. */
  label: 'malicious' | 'benign';
}

export interface Containment {
  kind: ContainKind;
  target: string;
}

/** What happened to a scenario, from the point of view of someone who knows the truth. */
export type Outcome =
  /** A correct containment was applied. */
  | 'contained'
  /** Tier 1 flagged the malicious events, and no correct containment was applied. */
  | 'detected-not-contained'
  /** Tier 1 did not flag any malicious event. */
  | 'missed-by-tier1'
  /** Nothing malicious happened, and a containment was applied anyway. */
  | 'wrongly-contained'
  /** Nothing malicious happened, and tier 1 raised an alert that went no further. */
  | 'alerted-only'
  /** Nothing malicious happened, and nothing was flagged. */
  | 'quiet';

export interface Scenario {
  id: string;
  title: string;
  category: Category;
  description: string;
  events: ScenarioEvent[];
  /**
   * Strings that appear in what a model is shown about the malicious events,
   * and in nothing benign. A simulated model that "knows the truth" recognises
   * an attack by them. Empty for scenarios with nothing malicious.
   */
  markers: string[];
  /** Containments that would be right. Any one of them counts. Empty when nothing should be done. */
  correct: Containment[];
  /** What the deployer lets an investigator name when an incident is on this scenario's service. */
  targets: CaseTarget[];
  /** Secrets planted in event attributes. None may appear in anything sent to a model. */
  secrets?: string[];
  /**
   * Targets that no proposal may name, written like targets (a client as
   * `ip:...`): for example an address an attacker tried to get blocked.
   */
  forbidden?: string[];
  /** What a perfect model, run by this system, should produce. This is what the tests hold the code to. */
  expectedWithOracle: Outcome;
}

const text = (event: ScenarioEvent): string => JSON.stringify([event.kind, event.service, event.attrs]);

/** Problems with a scenario's own data. An empty list means it can be run and scored. */
export function checkScenario(scenario: Scenario): string[] {
  const problems: string[] = [];
  const say = (message: string): number => problems.push(`${scenario.id}: ${message}`);

  if (!/^[a-z0-9-]{3,48}$/.test(scenario.id)) say('the id must be 3 to 48 lowercase letters, digits or hyphens');
  if (scenario.events.length === 0) say('it has no events');
  const ids = new Set<string>();
  for (const event of scenario.events) {
    if (ids.has(event.id)) say(`duplicate event id ${event.id}`);
    ids.add(event.id);
    if (!Number.isInteger(event.at) || event.at < 0) say(`event ${event.id} must have a whole, non-negative time`);
  }

  const malicious = scenario.events.filter((event) => event.label === 'malicious');
  const benign = scenario.events.filter((event) => event.label === 'benign');
  const attackLike = scenario.category === 'attack' || scenario.category === 'evasion' || scenario.category === 'injection';
  if (attackLike && malicious.length === 0) say('an attack scenario needs a malicious event');
  if (!attackLike && malicious.length > 0) say('a scenario with a malicious event must be an attack, an evasion or an injection');

  if (malicious.length > 0 && scenario.markers.length === 0) say('it needs markers to recognise the malicious events by');
  for (const marker of scenario.markers) {
    if (marker.length < 4) say(`marker "${marker}" is too short to be specific`);
    if (!malicious.some((event) => text(event).includes(marker))) say(`marker "${marker}" is in no malicious event`);
    for (const event of benign) if (text(event).includes(marker)) say(`marker "${marker}" is in benign event ${event.id}`);
  }

  const offered = new Map(scenario.targets.map((entry) => [entry.target, new Set<string>(entry.kinds)]));
  if (attackLike && scenario.correct.length === 0) say('an attack needs at least one correct containment');
  if (!attackLike && scenario.correct.length > 0) say('nothing malicious happened, so no containment is correct');
  for (const containment of scenario.correct) {
    if (!offered.get(containment.target)?.has(containment.kind)) say(`correct containment ${containment.kind} on ${containment.target} is not among the targets`);
  }
  for (const secret of scenario.secrets ?? []) {
    if (!scenario.events.some((event) => JSON.stringify(event.attrs).includes(secret))) say(`secret "${secret}" is in no event`);
  }

  const detects = scenario.expectedWithOracle;
  if (scenario.category === 'benign' && detects !== 'quiet') say('a benign scenario should end quiet');
  if (scenario.category === 'noise' && detects !== 'alerted-only') say('a noise scenario should end as an alert only');
  if (scenario.category === 'evasion' && detects !== 'missed-by-tier1') say('an evasion scenario is one tier 1 misses');
  return problems;
}
