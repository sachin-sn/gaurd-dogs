// Control characters (C0, DEL, C1) and Unicode line/paragraph separators.
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;

/**
 * Make an attacker-influenced string safer to store, display and later quote
 * to a model: strip control characters, collapse whitespace, cap the length.
 *
 * This is hygiene, not a defence against prompt injection. Anything that
 * reaches a model must still be delimited and treated as data, never as
 * instructions.
 */
export function sanitizeEvidence(value: string, maxLength = 200): string {
  const cleaned = value.replace(CONTROL_CHARS, ' ').replace(/\s+/g, ' ').trim();
  if (cleaned.length <= maxLength) return cleaned;
  return `${cleaned.slice(0, Math.max(0, maxLength - 1))}…`;
}
