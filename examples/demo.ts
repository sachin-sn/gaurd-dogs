/**
 * Guard Dogs, end to end, offline.
 *
 *   npm run demo
 *
 * Nothing here calls a model or touches the network. The guard dogs are
 * scripted stand-ins whose votes are set per scene, so the demo can show how
 * the machinery around them behaves: planning a mixed panel, masking and
 * throttling events, voting with early decisions and timeouts, the response
 * gate, the executor, a human approval, and expiry. Everything the dogs
 * vote on is synthetic.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  AuditLog,
  Executor,
  Panel,
  Pipeline,
  actionDigest,
  analyzePanel,
  createGatePolicy,
  createMasker,
  createModelRegistry,
  defaultRulesConfig,
  planPanel,
  withVotes,
  type ControlAdapter,
  type Dog,
  type DogOpinion,
  type Notification,
  type PanelMember,
  type PanelResult,
  type ProposedAction,
  type SubmitResult,
  type SubmitStatus,
} from '../src/index.js';

type Script = Record<string, { decision: 'approve' | 'reject'; afterMs: number } | 'hang'>;

export interface SceneOutcome {
  submit: SubmitStatus;
  codes: string[];
  decidedEarly: boolean;
  panel: PanelResult;
  result: SubmitResult;
}

export interface DemoResult {
  scenes: Record<string, SceneOutcome>;
  /** After the human approved the scene that waited for one. */
  humanApproved: SubmitStatus | undefined;
  notifications: Notification[];
  applied: string[];
  reverted: string[];
  auditOk: boolean;
  auditEntries: number;
}

class Clock {
  private t = Date.parse('2026-10-23T10:00:00Z');
  readonly now = (): Date => new Date(this.t);
  advance(seconds: number): void {
    this.t += seconds * 1000;
  }
}

/** A stand-in for a model-backed guard dog: it answers as the current scene's script says. */
class StandInDog implements Dog {
  constructor(
    readonly id: string,
    readonly model: string,
    readonly evidenceView: string,
    private readonly script: () => Script,
  ) {}

  review(_task: unknown, signal: AbortSignal): Promise<DogOpinion> {
    const behaviour = this.script()[this.id];
    return new Promise<DogOpinion>((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      // A real dog passes this signal to its HTTP client, so it stops when the panel no longer needs it.
      signal.addEventListener(
        'abort',
        () => {
          if (timer !== undefined) clearTimeout(timer);
          reject(new Error('stopped'));
        },
        { once: true },
      );
      if (behaviour === undefined || behaviour === 'hang') return;
      timer = setTimeout(() => resolve({ decision: behaviour.decision, rationale: `stand-in: scripted ${behaviour.decision}` }), behaviour.afterMs);
    });
  }
}

export interface DemoOptions {
  /** How long the panel waits for a silent dog. Default 400 ms, which keeps the demo quick. */
  deadlineMs?: number;
}

export async function runDemo(write: (line: string) => void = console.log, options: DemoOptions = {}): Promise<DemoResult> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-dogs-demo-'));
  try {
    return await run(write, dir, options.deadlineMs ?? 400);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function run(write: (line: string) => void, dir: string, deadlineMs: number): Promise<DemoResult> {
  const clock = new Clock();
  const iso = () => clock.now().toISOString();
  const heading = (text: string) => write(`\n== ${text}`);

  write('OFFLINE DEMO. No model is called and nothing leaves this machine.');
  write('The guard dogs below are scripted stand-ins; everything around them is the real code.');

  // ---- 1. Which models, and why -------------------------------------------------
  heading('1. Plan the panel (configuration decides which model each dog uses)');
  const registry = createModelRegistry([
    { id: 'acme-large', provider: 'acme', family: 'acme-a', tier: 'large', endpoint: 'https://api.acme.example.invalid/v1/chat', handling: 'zero-retention', maxInputChars: 24_000 },
    { id: 'acme-large-b', provider: 'acme', family: 'acme-b', tier: 'large', endpoint: 'https://api.acme.example.invalid/v1/chat-b', handling: 'zero-retention', maxInputChars: 24_000 },
    { id: 'borealis-large', provider: 'borealis', family: 'borealis-a', tier: 'large', endpoint: 'https://inference.borealis.example.invalid/v2/complete', handling: 'zero-retention', maxInputChars: 32_000 },
    { id: 'cinder-large', provider: 'cinder', family: 'cinder-a', tier: 'large', endpoint: 'https://llm.cinder.example.invalid/chat', handling: 'standard', maxInputChars: 16_000 },
  ]);
  const requiredHandling = { 'raw-logs': 'zero-retention' } as const;
  const members: PanelMember[] = planPanel(registry, {
    size: 7,
    views: ['raw-logs', 'summaries', 'timeline'],
    requiredHandling,
  });
  for (const m of members) {
    const model = registry.require(m.model);
    write(`  ${m.id}  ${m.model.padEnd(15)} ${model.provider.padEnd(9)} ${model.handling.padEnd(15)} sees ${m.evidenceView}`);
  }
  const policy = createGatePolicy({
    panel: members,
    preApproved: { 'contain.rate-limit': { maxTtlSeconds: 1800, targets: ['shop-web:*'] } },
    protectedTargets: ['guard-dog:*'],
    approvers: ['alice'],
  });
  const analysis = analyzePanel(registry, policy, { requiredHandling });
  write(
    analysis.warnings.length === 0
      ? '  Check: no provider can approve alone, none can block approvals, no correlated models, handling respected.'
      : `  Check: ${analysis.warnings.join(' ')}`,
  );
  const egress = registry.egressHosts(members.map((m) => m.model));
  write(`  Egress allow-list for the dogs, derived from the models in use: ${egress.join(', ')}`);

  // ---- wiring ------------------------------------------------------------------
  const log = AuditLog.open(path.join(dir, 'audit.jsonl'), { clock: clock.now });
  const applied: string[] = [];
  const reverted: string[] = [];
  const firewall: ControlAdapter = {
    async apply(action) {
      applied.push(action.id);
      write(`  [stub firewall] applied ${action.kind} on ${action.target}`);
      return { handle: { rule: `rule-${applied.length}` } };
    },
    async revert(_handle, info) {
      reverted.push(info.actionId);
      write(`  [stub firewall] removed the rule for ${info.target}`);
    },
  };
  const inbox: Notification[] = [];
  const everything: Notification[] = [];
  const executor = new Executor({
    policy,
    log,
    adapters: { 'observe.raise-sampling': firewall, 'contain.rate-limit': firewall },
    notifier: {
      notify: (n) => {
        inbox.push(n);
        everything.push(n);
      },
    },
    clock: clock.now,
  });
  const pipeline = new Pipeline({
    masker: createMasker({ pseudonymKey: 'demo-key-demo-key-demo-key-demo-key' }),
    executor,
    log,
    inventory: [{ ecosystem: 'npm', name: 'example-lib', version: '1.2.0', service: 'shop-web', layer: 'application' }],
    allowedSources: ['example-advisory-feed'],
    rulesConfig: { ...defaultRulesConfig, webRoots: ['/var/www/html'], allowedWriters: ['deploy'], guardDogEgress: [...egress] },
    clock: clock.now,
  });
  const showInbox = () => {
    for (const n of inbox.splice(0)) write(`  -> human [${n.kind}] ${n.summary}`);
  };

  // ---- 2. Events -----------------------------------------------------------------
  heading('2. Events arrive: masked, checked by tier 1, throttled');
  const upload = (id: string) => ({
    id,
    ts: iso(),
    layer: 'application',
    service: 'shop-web',
    kind: 'file.created',
    attrs: { path: '/var/www/html/uploads/img.php', actor: 'www-data', authorization: 'Bearer hunter2hunter2hunter2' },
  });
  const benign = { id: 'evt-benign', ts: iso(), layer: 'application', service: 'shop-web', kind: 'file.created', attrs: { path: '/var/www/html/uploads/photo.jpg', actor: 'www-data' } };
  const events = await pipeline.ingestEvents([upload('evt-100'), ...[1, 2, 3, 4, 5].map((i) => upload(`evt-10${i}`)), benign]);
  write(
    `  ${events.received} events: ${events.hits} hit tier 1, ${events.suppressed.duplicate} repeats suppressed, ` +
      `${Object.values(events.masked).reduce((a, b) => a + b, 0)} secrets masked`,
  );
  showInbox();

  // ---- 3. Advisory ---------------------------------------------------------------
  heading('3. An advisory arrives from outside the fort (unverified)');
  const advisory = {
    id: 'GD-EXAMPLE-0001',
    ecosystem: 'npm',
    package: 'example-lib',
    affected: '>=1.0.0 <1.4.2',
    fixed: '1.4.2',
    severity: 'high',
    source: 'example-advisory-feed',
    link: 'https://example.invalid/advisories/GD-EXAMPLE-0001',
    publishedAt: '2026-10-23T08:00:00Z',
    verification: { status: 'unverified' },
  };
  const advisories = await pipeline.ingestAdvisories([advisory]);
  write(`  ${advisories.findings} service exposed; alert sent and sampling raised. Unverified intel allows nothing stronger than an alert.`);
  showInbox();

  // ---- the panel -----------------------------------------------------------------
  let script: Script = {};
  const dogs = members.map((m) => new StandInDog(m.id, m.model, m.evidenceView, () => script));
  const panel = new Panel({ policy, dogs, deadlineMs, log });
  const answer = (decision: 'approve' | 'reject', afterMs: number) => ({ decision, afterMs });

  const scenes: Record<string, SceneOutcome> = {};
  const investigate = async (key: string, title: string, scene: Script, overrides: Partial<ProposedAction>): Promise<ProposedAction> => {
    heading(title);
    script = scene;
    const action: ProposedAction = {
      id: `act-${key}`,
      proposedBy: 'investigator',
      level: 3,
      kind: 'contain.rate-limit',
      target: 'shop-web:/upload',
      reason: 'Executable uploads into the web root from one source, repeated.',
      evidence: ['evt-100'],
      createdAt: iso(),
      reversible: true,
      ttlSeconds: 900,
      ...overrides,
    };
    const evidence = {
      'raw-logs': { events: ['(masked event lines)'] },
      summaries: { text: 'Executable file created in the web root of shop-web, repeatedly.' },
      timeline: { steps: ['upload', 'upload', 'upload'] },
    };
    const review = await panel.review({ action, evidence });
    const t = review.dogs.reduce((c, d) => ({ ...c, [d.decision]: (c[d.decision] ?? 0) + 1 }), {} as Record<string, number>);
    write(`  votes: ${t['approve'] ?? 0} approve, ${t['reject'] ?? 0} reject, ${t['abstain'] ?? 0} silent or stopped; ${Math.round(review.elapsedMs)} ms${review.decidedEarly ? ', decided early' : ''}`);
    write('  ' + review.dogs.map((d) => `${d.dog}:${d.status === 'voted' ? d.decision : d.status}`).join('  '));
    const result = await pipeline.submit(withVotes(action, review));
    const codes = result.decision?.codes ?? [];
    write(`  gate: ${result.decision?.outcome} [${codes.join(', ')}]  executor: ${result.status}`);
    showInbox();
    scenes[key] = { submit: result.status, codes, decidedEarly: review.decidedEarly, panel: review, result };
    clock.advance(10);
    return action;
  };

  await investigate(
    'swift',
    '4. Four of seven agree: the rest are told to stop',
    { 'dog-1': answer('approve', 20), 'dog-2': answer('approve', 30), 'dog-3': answer('approve', 40), 'dog-4': answer('approve', 50) },
    {},
  );

  await investigate(
    'split',
    '5. Three for, four against: rejected, and a human is told anyway',
    {
      'dog-4': answer('reject', 20), 'dog-5': answer('reject', 30), 'dog-6': answer('reject', 40), 'dog-7': answer('reject', 50),
      'dog-1': answer('approve', 60), 'dog-2': answer('approve', 70), 'dog-3': answer('approve', 80),
    },
    { target: 'shop-web:/checkout' },
  );

  const down = await investigate(
    'down',
    '6. Two dogs go silent: silence is not agreement, so a person decides',
    {
      'dog-1': answer('approve', 20), 'dog-2': answer('approve', 30), 'dog-3': answer('approve', 40),
      'dog-4': answer('reject', 50), 'dog-5': answer('reject', 60), 'dog-6': 'hang', 'dog-7': 'hang',
    },
    { target: 'shop-web:/search' },
  );
  write('  alice reviews it and approves.');
  const approved = await executor.approve(down.id, { approver: 'alice', approvedAt: iso(), actionDigest: actionDigest(down) });
  write(`  executor: ${approved.status}`);
  showInbox();

  await investigate(
    'intel',
    '7. A unanimous panel citing only unverified intel: still a person decides',
    { 'dog-1': answer('approve', 20), 'dog-2': answer('approve', 30), 'dog-3': answer('approve', 40), 'dog-4': answer('approve', 50) },
    { target: 'shop-web:/api', evidence: ['GD-EXAMPLE-0001'] },
  );

  // ---- expiry and audit ------------------------------------------------------------
  heading('8. Time passes: containment expires on its own');
  clock.advance(1200);
  const tick = await executor.tick();
  write(`  reverted: ${tick.reverted.join(', ') || 'none'}`);
  showInbox();

  heading('9. Audit');
  const verify = log.verify();
  const entries = log.entries();
  const types = entries.reduce((c, e) => ({ ...c, [e.type]: (c[e.type] ?? 0) + 1 }), {} as Record<string, number>);
  write(`  ${entries.length} entries, hash chain ${verify.ok ? 'intact' : 'BROKEN'}`);
  write('  ' + Object.entries(types).map(([t, n]) => `${t}×${n}`).join('  '));

  return {
    scenes,
    humanApproved: approved.status,
    notifications: everything,
    applied,
    reverted,
    auditOk: verify.ok,
    auditEntries: entries.length,
  };
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runDemo();
}
