import { createRequire } from 'node:module';
import type { ErrorObject, ValidateFunction } from 'ajv';
import actionSchema from '../../schemas/action.schema.json' with { type: 'json' };
import auditEntrySchema from '../../schemas/audit-entry.schema.json' with { type: 'json' };
import eventSchema from '../../schemas/event.schema.json' with { type: 'json' };
import informerRecordSchema from '../../schemas/informer-record.schema.json' with { type: 'json' };
import type { GuardDogEvent, InformerRecord, ProposedAction } from './types.js';

// ajv and ajv-formats are CommonJS packages; load them through require so the
// constructors resolve the same way under tsc, vitest and plain Node ESM.
const require = createRequire(import.meta.url);
const Ajv2020 = require('ajv/dist/2020.js') as typeof import('ajv/dist/2020.js').default;
const addFormats = require('ajv-formats') as typeof import('ajv-formats').default;

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);

export type ValidationResult<T> =
  | { ok: true; value: T }
  | { ok: false; errors: string[] };

function formatErrors(errors: ErrorObject[] | null | undefined): string[] {
  if (!errors || errors.length === 0) return ['invalid'];
  return errors.map((e) => `${e.instancePath || '/'} ${e.message ?? 'is invalid'}`);
}

function makeValidator<T>(schema: object): (input: unknown) => ValidationResult<T> {
  const validate: ValidateFunction = ajv.compile(schema);
  return (input: unknown): ValidationResult<T> => {
    if (validate(input)) return { ok: true, value: input as T };
    return { ok: false, errors: formatErrors(validate.errors) };
  };
}

export const validateEvent = makeValidator<GuardDogEvent>(eventSchema);
export const validateInformerRecord = makeValidator<InformerRecord>(informerRecordSchema);
export const validateAction = makeValidator<ProposedAction>(actionSchema);
export const validateAuditEntry = makeValidator<{
  seq: number;
  ts: string;
  actor: string;
  type: string;
  data: unknown;
  prev: string;
  hash: string;
}>(auditEntrySchema);
