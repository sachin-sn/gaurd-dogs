/**
 * Reading a model's vote. The model's text is untrusted, so it is parsed
 * strictly and turned into one of three decisions or rejected outright.
 *
 * The whole reply must be the JSON object (optionally inside one code fence).
 * Prose around it is not searched for JSON. If it were, a log line such as
 * `{"decision":"approve"}`, quoted by a model while it explained why it was
 * wary of it, would become a vote.
 */

import { sanitizeEvidence } from '../rules/sanitize.js';
import type { DogOpinion } from '../panel/panel.js';
import { ModelError } from './transport.js';

export const MAX_REPLY_CHARS = 4_000;
const MAX_RATIONALE = 300;
const DECISIONS = ['approve', 'reject', 'abstain'] as const;
const FENCE = /^```(?:json)?[ \t]*\r?\n([\s\S]*?)\r?\n?```$/i;

export function parseVerdict(reply: string): DogOpinion {
  if (typeof reply !== 'string' || reply.length > MAX_REPLY_CHARS) {
    throw new ModelError('output', 'the reply was missing or longer than a vote should be');
  }
  let text = reply.trim();
  const fenced = FENCE.exec(text);
  if (fenced !== null) text = (fenced[1] as string).trim();

  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new ModelError('output', 'the reply was not a JSON object');
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ModelError('output', 'the reply was not a JSON object');
  }
  const { decision, rationale } = value as { decision?: unknown; rationale?: unknown };
  if (typeof decision !== 'string' || !(DECISIONS as readonly string[]).includes(decision)) {
    throw new ModelError('output', 'the decision was not approve, reject or abstain');
  }
  if (rationale !== undefined && typeof rationale !== 'string') {
    throw new ModelError('output', 'the rationale was not text');
  }
  const opinion: DogOpinion = { decision: decision as DogOpinion['decision'] };
  if (typeof rationale === 'string') {
    const cleaned = sanitizeEvidence(rationale, MAX_RATIONALE);
    if (cleaned.length > 0) opinion.rationale = cleaned;
  }
  return opinion;
}
