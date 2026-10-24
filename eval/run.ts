/**
 * Run the evaluation.
 *
 *   npm run eval
 *   npm run eval -- --json results.json
 *   npm run eval -- --profile oracle --scenario webshell-upload
 *
 * Offline: the models are simulated (see `sim.ts`), so the numbers describe
 * the system around the models, not any model.
 */

import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
import { corpus } from './corpus.js';
import { runScenario, type HarnessOptions } from './harness.js';
import { checkScenario, CATEGORIES, type Scenario } from './scenario.js';
import { score, summarise, type Score, type Summary } from './score.js';
import { profiles as allProfiles, type ModelProfile } from './sim.js';

export interface Evaluation {
  scores: Score[];
  summaries: Summary[];
}

export interface EvaluateOptions {
  scenarios?: readonly Scenario[];
  profiles?: readonly ModelProfile[];
  harness?: HarnessOptions;
}

export async function evaluate(options: EvaluateOptions = {}): Promise<Evaluation> {
  const scenarios = options.scenarios ?? corpus;
  const profiles = options.profiles ?? allProfiles;
  const problems = scenarios.flatMap((scenario) => checkScenario(scenario));
  if (problems.length > 0) throw new Error(`the scenarios have problems:\n${problems.join('\n')}`);

  const scores: Score[] = [];
  for (const profile of profiles) {
    for (const scenario of scenarios) scores.push(score(await runScenario(scenario, profile, options.harness)));
  }
  return { scores, summaries: profiles.map((profile) => summarise(profile.id, scores)) };
}

const pct = (value: number | undefined): string => (value === undefined ? 'n/a' : `${Math.round(value * 100)}%`);

export function render(evaluation: Evaluation): string[] {
  const lines: string[] = [];
  const width = Math.max(...evaluation.scores.map((entry) => entry.scenario.length), 8);
  for (const summary of evaluation.summaries) {
    lines.push('', `== ${summary.profile}`);
    lines.push(`${'scenario'.padEnd(width)}  ${'category'.padEnd(9)}  ${'outcome'.padEnd(22)}  secs  calls t/i/d  notes`);
    for (const entry of evaluation.scores.filter((candidate) => candidate.profile === summary.profile)) {
      const notes = [
        entry.wrongContainments > 0 ? `${entry.wrongContainments} wrong containment(s)` : '',
        entry.forbiddenHits > 0 ? 'FORBIDDEN TARGET' : '',
        entry.unoffered > 0 ? 'UNOFFERED TARGET' : '',
        entry.leaks > 0 ? `${entry.leaks} LEAK(S)` : '',
        entry.neverReverted > 0 ? `${entry.neverReverted} not reverted` : '',
        entry.errors > 0 ? `${entry.errors} error(s)` : '',
        !entry.auditIntact ? 'AUDIT BROKEN' : '',
      ].filter((note) => note.length > 0);
      lines.push(
        `${entry.scenario.padEnd(width)}  ${entry.category.padEnd(9)}  ${entry.outcome.padEnd(22)}  ` +
          `${(entry.secondsToContain === undefined ? '-' : String(entry.secondsToContain)).padStart(4)}  ` +
          `${`${entry.calls.triage}/${entry.calls.investigator}/${entry.calls.dog}`.padEnd(10)}  ${notes.join('; ')}`,
      );
    }
    lines.push(
      '',
      `  tier 1 flagged ${pct(summary.detectionRate)} of malicious scenarios; ${pct(summary.containmentRate)} of the ones it has rules for ended contained`,
      `  harmless scenarios contained: ${summary.wrongContainments}; wrong containments applied: ${summary.wrongContainmentActions}; forbidden targets hit: ${summary.forbiddenHits}; targets outside the offer: ${summary.unoffered}`,
      `  secrets in model prompts or the audit log: ${summary.leaks}; containments never reverted: ${summary.neverReverted}; broken audit chains: ${summary.auditBroken}; step errors: ${summary.errors}`,
      `  mean model calls per scenario: triage ${summary.meanCalls.triage.toFixed(1)}, investigator ${summary.meanCalls.investigator.toFixed(1)}, dog ${summary.meanCalls.dog.toFixed(1)}`,
    );
    for (const category of CATEGORIES) {
      const counts = Object.entries(summary.outcomes[category]).map(([outcome, n]) => `${outcome}×${n}`);
      if (counts.length > 0) lines.push(`  ${category.padEnd(9)} ${counts.join('  ')}`);
    }
  }
  return lines;
}

function option(args: readonly string[], name: string): string[] {
  const values: string[] = [];
  for (let i = 0; i < args.length; i++) if (args[i] === name && args[i + 1] !== undefined) values.push(args[i + 1] as string);
  return values;
}

/** The command line. `print` is where the report goes. */
export async function main(args: readonly string[], print: (line: string) => void = console.log): Promise<void> {
  const profileIds = option(args, '--profile');
  const scenarioIds = option(args, '--scenario');
  const chosenProfiles = profileIds.length === 0 ? allProfiles : allProfiles.filter((profile) => profileIds.includes(profile.id));
  const chosenScenarios = scenarioIds.length === 0 ? corpus : corpus.filter((scenario) => scenarioIds.includes(scenario.id));
  if (chosenProfiles.length === 0 || chosenScenarios.length === 0) throw new Error('no profile or scenario matches those names');

  const evaluation = await evaluate({ profiles: chosenProfiles, scenarios: chosenScenarios });
  print('OFFLINE EVALUATION. The models are simulated; the numbers describe the system around them.');
  for (const line of render(evaluation)) print(line);

  const out = option(args, '--json')[0];
  if (out !== undefined) {
    fs.writeFileSync(out, `${JSON.stringify(evaluation, null, 2)}\n`);
    print(`\nwrote ${out}`);
  }
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main(process.argv.slice(2));
}
