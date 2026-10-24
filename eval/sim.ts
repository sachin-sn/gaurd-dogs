/**
 * Simulated models.
 *
 * A profile answers the three kinds of request the system makes to a model
 * (triage, investigation, a panel vote) the way a certain kind of model would.
 * It is given the real prompt, so the real prompt builders, parsers and checks
 * all run; only the thinking is replaced.
 *
 * None of these is a claim about what any real model does. They bracket it:
 *
 * - `oracle` is a perfect analyst. It shows what the system does when the
 *   models are right, which isolates the loss that comes from everything else:
 *   what tier 1 cannot see, what grouping and the budget leave out.
 * - `credulous` believes everything: it escalates, proposes and approves
 *   whatever it is shown. It shows what the guards around the models bound.
 * - `skeptic` does nothing: it shows the cost of models that never act.
 *
 * Real models are run with the same harness by supplying a profile that calls
 * them (a later change).
 */

import type { ModelRequest } from '../src/index.js';
import type { Containment, Scenario } from './scenario.js';

export type Role = 'triage' | 'investigator' | 'dog';

/** What a simulated model knows about the scenario it is looking at, in the terms the system uses. */
export interface Truth {
  markers: readonly string[];
  /** Containments that are right, with client addresses already turned into the pseudonyms the system uses. */
  correct: readonly Containment[];
}

export interface Asker {
  actor: string;
  model: string;
}

export interface ModelProfile {
  id: string;
  description: string;
  reply(role: Role, request: ModelRequest, asker: Asker, truth: Truth): string | Promise<string>;
}

/** The JSON a prompt carries in a `<tag-nonce>` block. Undefined if there is none or it is not JSON. */
export function block(user: string, tag: string): unknown {
  const match = new RegExp(`<${tag}-([A-Za-z0-9]+)>\\n([\\s\\S]*?)\\n</${tag}-\\1>`).exec(user);
  if (match === null) return undefined;
  try {
    return JSON.parse(match[2] as string) as unknown;
  } catch {
    return undefined;
  }
}

const asArray = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);
const asRecord = (value: unknown): Record<string, unknown> => (typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {});
const mentions = (value: unknown, markers: readonly string[]): boolean => {
  const text = JSON.stringify(value) ?? '';
  return markers.some((marker) => text.includes(marker));
};

interface Offer {
  target: string;
  kinds: string[];
}

const offers = (caseBlock: unknown): Offer[] =>
  asArray(asRecord(caseBlock)['targets']).map((entry) => {
    const record = asRecord(entry);
    return { target: String(record['target']), kinds: asArray(record['kinds']).map(String) };
  });

const isOffered = (list: readonly Offer[], containment: Containment): boolean =>
  list.some((entry) => entry.target === containment.target && entry.kinds.includes(containment.kind));

export const oracle: ModelProfile = {
  id: 'oracle',
  description: 'A perfect analyst: recognises the attack, names the right containment, and votes accordingly.',
  reply(role, request, _asker, truth) {
    if (role === 'triage') {
      const items = asArray(block(request.user, 'items')).map(asRecord);
      return JSON.stringify({
        results: items.map((item) => ({
          id: item['id'],
          decision: mentions(item['evidence'], truth.markers) ? 'escalate' : 'routine',
          reason: 'scripted',
        })),
      });
    }

    if (role === 'investigator') {
      const available = offers(block(request.user, 'case'));
      const pieces = asArray(block(request.user, 'evidence')).map(asRecord);
      const attack = pieces.filter((piece) => mentions(piece['content'], truth.markers));
      const usable = truth.correct.filter((containment) => isOffered(available, containment));
      if (attack.length === 0 || usable.length === 0) return JSON.stringify({ decision: 'none', reason: 'nothing here calls for action' });
      // Prefer the containment that this case's own first piece of evidence is about.
      const first = JSON.stringify(attack[0]);
      const chosen = usable.find((containment) => first.includes(containment.target)) ?? usable[0];
      if (chosen === undefined) return JSON.stringify({ decision: 'none' });
      return JSON.stringify({
        decision: 'propose',
        kind: chosen.kind,
        target: chosen.target,
        evidence: attack.slice(0, 5).map((piece) => piece['id']),
        ttlSeconds: 600,
        reason: 'The evidence shows the attack and this is the narrowest way to stop it.',
      });
    }

    const proposal = asRecord(block(request.user, 'proposal'));
    const right = truth.correct.some((containment) => containment.kind === proposal['kind'] && containment.target === proposal['target']);
    if (!right) return JSON.stringify({ decision: 'reject', rationale: 'This is not the right target or kind for what the evidence shows.' });
    if (!mentions(block(request.user, 'evidence'), truth.markers)) {
      return JSON.stringify({ decision: 'abstain', rationale: 'The evidence I was given does not show the activity.' });
    }
    return JSON.stringify({ decision: 'approve', rationale: 'The evidence shows the attack and the action fits it.' });
  },
};

export const credulous: ModelProfile = {
  id: 'credulous',
  description: 'Believes everything: escalates every item, proposes the first thing it is offered, approves every proposal.',
  reply(role, request) {
    if (role === 'triage') {
      const items = asArray(block(request.user, 'items')).map(asRecord);
      return JSON.stringify({ results: items.map((item) => ({ id: item['id'], decision: 'escalate', reason: 'scripted' })) });
    }
    if (role === 'investigator') {
      const first = offers(block(request.user, 'case'))[0];
      const piece = asRecord(asArray(block(request.user, 'evidence'))[0]);
      if (first === undefined || first.kinds[0] === undefined || typeof piece['id'] !== 'string') return JSON.stringify({ decision: 'none' });
      return JSON.stringify({ decision: 'propose', kind: first.kinds[0], target: first.target, evidence: [piece['id']], ttlSeconds: 600, reason: 'It looks suspicious.' });
    }
    return JSON.stringify({ decision: 'approve', rationale: 'Looks fine to me.' });
  },
};

export const skeptic: ModelProfile = {
  id: 'skeptic',
  description: 'Never acts: calls everything routine, proposes nothing, rejects every proposal.',
  reply(role, request) {
    if (role === 'triage') {
      const items = asArray(block(request.user, 'items')).map(asRecord);
      return JSON.stringify({ results: items.map((item) => ({ id: item['id'], decision: 'routine', reason: 'scripted' })) });
    }
    if (role === 'investigator') return JSON.stringify({ decision: 'none', reason: 'nothing to do' });
    return JSON.stringify({ decision: 'reject', rationale: 'Not convinced.' });
  },
};

export const profiles: readonly ModelProfile[] = [oracle, credulous, skeptic];

/** The truth about a scenario, as the simulated models see it. */
export const truthOf = (scenario: Scenario, correct: readonly Containment[]): Truth => ({ markers: scenario.markers, correct });
