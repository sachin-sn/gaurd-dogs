import { SEVERITY_RANK } from '../core/types.js';
import { validateEvent } from '../core/validate.js';
import { defaultRules, defaultRulesConfig, type Rule, type RuleHit, type RulesConfig } from './rules.js';

export interface Tier1Result {
  hits: RuleHit[];
  /** Events that failed schema validation, by id when readable. */
  rejected: { eventId: string; reason: string }[];
  /** Rules that threw. One broken rule must not blind the others. */
  ruleErrors: { ruleId: string; eventId: string; message: string }[];
}

function idOf(raw: unknown): string {
  if (typeof raw === 'object' && raw !== null && 'id' in raw) {
    const id = (raw as { id: unknown }).id;
    if (typeof id === 'string' && id.length > 0) return id.slice(0, 128);
  }
  return 'unknown';
}

/**
 * Run tier 1 over a batch of raw events. Events are attacker-influenced, so
 * they are schema-validated first; invalid ones are reported, not evaluated.
 */
export function runTier1(
  rawEvents: readonly unknown[],
  config: RulesConfig = defaultRulesConfig,
  rules: readonly Rule[] = defaultRules,
): Tier1Result {
  const hits: RuleHit[] = [];
  const rejected: Tier1Result['rejected'] = [];
  const ruleErrors: Tier1Result['ruleErrors'] = [];

  for (const raw of rawEvents) {
    const checked = validateEvent(raw);
    if (!checked.ok) {
      rejected.push({ eventId: idOf(raw), reason: checked.errors.join('; ') });
      continue;
    }
    const event = checked.value;
    for (const rule of rules) {
      try {
        const hit = rule.evaluate(event, config);
        if (hit !== null) hits.push(hit);
      } catch (error) {
        ruleErrors.push({
          ruleId: rule.id,
          eventId: event.id,
          message: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }

  hits.sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      a.ruleId.localeCompare(b.ruleId) ||
      a.eventId.localeCompare(b.eventId),
  );
  return { hits, rejected, ruleErrors };
}
