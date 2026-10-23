/**
 * Parse JSON Lines from a log or a staging-zone file. The text is untrusted, so
 * the parse is bounded: a hostile file cannot make it allocate without limit.
 * It returns what it could read and counts what it skipped. It never throws on
 * bad content.
 *
 * What comes out is `unknown` on purpose. Each item still has to pass schema
 * validation before anything relies on it.
 */

export interface JsonLinesOptions {
  /** Most lines read. Default 10,000. */
  maxLines?: number;
  /** Longest line parsed, in characters. Default 65,536. */
  maxLineLength?: number;
}

export interface JsonLinesResult {
  items: unknown[];
  skipped: {
    /** Lines longer than `maxLineLength`. */
    tooLong: number;
    /** Lines that are not valid JSON. */
    invalid: number;
    /** Lines past `maxLines` that were not read. */
    overLimit: number;
  };
}

export function parseJsonLines(text: string, options: JsonLinesOptions = {}): JsonLinesResult {
  const maxLines = options.maxLines ?? 10_000;
  const maxLineLength = options.maxLineLength ?? 65_536;
  const items: unknown[] = [];
  const skipped = { tooLong: 0, invalid: 0, overLimit: 0 };

  let read = 0;
  let start = 0;
  while (start <= text.length) {
    let end = text.indexOf('\n', start);
    if (end === -1) end = text.length;
    const line = text.slice(start, end).trim();
    start = end + 1;
    if (line.length === 0) continue;

    if (read >= maxLines) {
      skipped.overLimit++;
      continue;
    }
    read++;
    if (line.length > maxLineLength) {
      skipped.tooLong++;
      continue;
    }
    try {
      items.push(JSON.parse(line) as unknown);
    } catch {
      skipped.invalid++;
    }
  }
  return { items, skipped };
}
