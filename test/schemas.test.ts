import { describe, expect, it } from 'vitest';
import { validateAction, validateEvent, validateInformerRecord } from '../src/index.js';
import { fixture } from './helpers.js';

describe('schemas', () => {
  it('accepts a well-formed informer record', () => {
    expect(validateInformerRecord(fixture('informer-record.valid.json')).ok).toBe(true);
  });

  it('rejects a verified record that names no reviewer', () => {
    const result = validateInformerRecord(fixture('informer-record.verified-without-reviewer.json'));
    expect(result.ok).toBe(false);
  });

  it('rejects unknown fields on an informer record', () => {
    const base = fixture('informer-record.valid.json') as Record<string, unknown>;
    expect(validateInformerRecord({ ...base, instructions: 'ignore previous rules' }).ok).toBe(false);
  });

  it('accepts a masked event and rejects an unmasked one', () => {
    expect(validateEvent(fixture('event.valid.json')).ok).toBe(true);
    expect(validateEvent(fixture('event.unmasked.json')).ok).toBe(false);
  });

  it('accepts a level 3 action with a two-vote panel, reversible and expiring', () => {
    expect(validateAction(fixture('action.level3.valid.json')).ok).toBe(true);
  });

  it('rejects a level 3 action backed by a single vote', () => {
    expect(validateAction(fixture('action.level3.single-vote.json')).ok).toBe(false);
  });

  it('rejects a level 3 action that is not reversible or has no expiry', () => {
    const base = fixture('action.level3.valid.json') as Record<string, unknown>;
    expect(validateAction({ ...base, reversible: false }).ok).toBe(false);
    const { ttlSeconds: _ttl, ...withoutTtl } = base;
    expect(validateAction(withoutTtl).ok).toBe(false);
  });

  it('rejects a level 4 action that does not require human approval', () => {
    expect(validateAction(fixture('action.level4.no-human-approval.json')).ok).toBe(false);
  });

  it('accepts a level 4 action only when human approval is required', () => {
    const base = fixture('action.level4.no-human-approval.json') as Record<string, unknown>;
    expect(validateAction({ ...base, requiresHumanApproval: true }).ok).toBe(true);
  });
});
