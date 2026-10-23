/**
 * Match `text` against a pattern where `*` matches any run of characters
 * (including none) and everything else is literal.
 *
 * Deliberately not a regular expression: patterns come from policy files, and
 * this avoids regex injection and catastrophic backtracking. Worst case is
 * O(pattern length x text length), and both are short.
 */
export function globMatch(pattern: string, text: string): boolean {
  let p = 0;
  let t = 0;
  let star = -1;
  let mark = 0;

  while (t < text.length) {
    if (p < pattern.length && pattern[p] === '*') {
      star = p++;
      mark = t;
    } else if (p < pattern.length && pattern[p] === text[t]) {
      p++;
      t++;
    } else if (star !== -1) {
      p = star + 1;
      t = ++mark;
    } else {
      return false;
    }
  }
  while (p < pattern.length && pattern[p] === '*') p++;
  return p === pattern.length;
}

export function matchesAny(patterns: readonly string[], text: string): boolean {
  return patterns.some((pattern) => globMatch(pattern, text));
}
