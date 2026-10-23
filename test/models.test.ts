import { describe, expect, it } from 'vitest';
import {
  MAX_PANEL_SIZE,
  analyzePanel,
  createGatePolicy,
  createModelRegistry,
  planPanel,
  type ModelSpec,
  type PanelMember,
} from '../src/index.js';

let n = 0;
function spec(id: string, provider: string, family: string, overrides: Partial<ModelSpec> = {}): ModelSpec {
  n++;
  return {
    id,
    provider,
    family,
    tier: 'large',
    endpoint: `https://${provider}.example.invalid/v1/${n}`,
    handling: 'standard',
    maxInputChars: 20_000,
    ...overrides,
  };
}

const policyOf = (members: PanelMember[], extra: Partial<Parameters<typeof createGatePolicy>[0]> = {}) =>
  createGatePolicy({ panel: members, ...extra });

describe('createModelRegistry', () => {
  it('registers models, lower-cases the host, and hands out frozen copies', () => {
    const input = spec('m-1', 'alpha', 'alpha-large', { endpoint: 'https://API.Alpha.Example.invalid./v1/chat' });
    const registry = createModelRegistry([input]);
    const model = registry.require('m-1');

    expect(model).toMatchObject({
      id: 'm-1',
      provider: 'alpha',
      family: 'alpha-large',
      host: 'api.alpha.example.invalid',
      // What a dog calls is the canonical form of what was validated.
      endpoint: 'https://api.alpha.example.invalid/v1/chat',
    });
    expect(registry.get('m-1')).toBe(model);
    expect(registry.list()).toEqual([model]);
    expect(() => {
      (model as { host: string }).host = 'evil.invalid';
    }).toThrow(TypeError);
    input.endpoint = 'https://changed.invalid/';
    expect(registry.require('m-1').host).toBe('api.alpha.example.invalid');
  });

  it('refuses an unknown model by name', () => {
    const registry = createModelRegistry([spec('m-1', 'alpha', 'f1')]);
    expect(registry.get('nope')).toBeUndefined();
    expect(registry.get('constructor')).toBeUndefined();
    expect(() => registry.require('nope')).toThrow(/not in the registry/);
  });

  it('needs at least one model and unique ids', () => {
    expect(() => createModelRegistry([])).toThrow(/at least one/);
    expect(() => createModelRegistry([spec('m-1', 'a', 'f'), spec('m-1', 'b', 'g')])).toThrow(/duplicate/);
  });

  it('checks names, tier, handling and the input limit', () => {
    const bad: [string, Partial<ModelSpec>][] = [
      ['empty id', { id: '' }],
      ['id with a space', { id: 'a b' }],
      ['id starting with a dash', { id: '-x' }],
      ['proto id', { id: '__proto__' }],
      ['long id', { id: 'x'.repeat(101) }],
      ['provider with a space', { provider: 'a b' }],
      ['empty family', { family: '' }],
      ['unknown tier', { tier: 'medium' as never }],
      ['unknown handling', { handling: 'constructor' as never }],
      ['no handling', { handling: undefined as never }],
      ['zero input limit', { maxInputChars: 0 }],
      ['fractional input limit', { maxInputChars: 1.5 }],
      ['huge input limit', { maxInputChars: 1_000_001 }],
      ['NaN input limit', { maxInputChars: Number.NaN }],
    ];
    for (const [name, overrides] of bad) {
      expect(() => createModelRegistry([spec('m-1', 'alpha', 'f1', overrides)]), name).toThrow(RangeError);
    }
  });

  it('accepts only a plain https endpoint with a host name', () => {
    const bad: [string, unknown][] = [
      ['http', 'http://api.example.invalid/v1'],
      ['ftp', 'ftp://api.example.invalid/v1'],
      ['no scheme', 'api.example.invalid/v1'],
      ['credentials', 'https://user:pass@api.example.invalid/v1'],
      ['user only', 'https://user@api.example.invalid/v1'],
      ['a key in the query', 'https://api.example.invalid/v1?key=abc'],
      ['a fragment', 'https://api.example.invalid/v1#x'],
      ['an IPv4 address', 'https://203.0.113.9/v1'],
      ['an IPv6 address', 'https://[2001:db8::1]/v1'],
      ['three slashes, which some parsers read as a path', 'https:///api.example.invalid/v1'],
      ['a backslash', 'https:\\\\api.example.invalid/v1'],
      ['a backslash after the host', 'https://api.example.invalid\\@evil.invalid/v1'],
      ['a space', 'https://api.example.invalid/v 1'],
      ['a newline', 'https://api.example.invalid/v1\n'],
      ['userinfo trick', 'https://api.example.invalid@evil.invalid/v1'],
      ['not a string', 42],
      ['no host', 'https://'],
    ];
    for (const [name, endpoint] of bad) {
      expect(() => createModelRegistry([spec('m-1', 'alpha', 'f1', { endpoint: endpoint as string })]), name).toThrow(RangeError);
    }
    expect(() => createModelRegistry([spec('m-1', 'alpha', 'f1', { endpoint: 'https://api.example.invalid:8443/v1' })])).not.toThrow();
  });

  it('lists the hosts guard dogs may contact: sorted, without duplicates, only for the models asked about', () => {
    const registry = createModelRegistry([
      spec('m-1', 'beta', 'f1', { endpoint: 'https://b.example.invalid/x' }),
      spec('m-2', 'alpha', 'f2', { endpoint: 'https://A.example.invalid/y' }),
      spec('m-3', 'beta', 'f3', { endpoint: 'https://b.example.invalid/z' }),
    ]);

    expect(registry.egressHosts()).toEqual(['a.example.invalid', 'b.example.invalid']);
    expect(registry.egressHosts(['m-1', 'm-3'])).toEqual(['b.example.invalid']);
    expect(registry.egressHosts([])).toEqual([]);
    expect(() => registry.egressHosts(['m-1', 'nope'])).toThrow(/not in the registry/);
  });
});

describe('planPanel', () => {
  const big = createModelRegistry([
    spec('a-1', 'alpha', 'alpha-1'),
    spec('a-2', 'alpha', 'alpha-2'),
    spec('b-1', 'beta', 'beta-1'),
    spec('c-1', 'gamma', 'gamma-1'),
    spec('a-small', 'alpha', 'alpha-s', { tier: 'small' }),
    spec('b-small', 'beta', 'beta-s', { tier: 'small' }),
  ]);
  const views = ['raw-logs', 'summaries', 'timeline'];

  it('spreads seats over providers first, then over families', () => {
    expect(planPanel(big, { size: 3, views })).toEqual([
      { id: 'dog-1', model: 'a-1', evidenceView: 'raw-logs' },
      { id: 'dog-2', model: 'b-1', evidenceView: 'summaries' },
      { id: 'dog-3', model: 'c-1', evidenceView: 'timeline' },
    ]);
    // A fourth seat goes to the provider with the most families to offer, and a second family of it.
    expect(planPanel(big, { size: 4, views }).map((m) => m.model)).toEqual(['a-1', 'b-1', 'c-1', 'a-2']);
    // Past that, seats repeat models already chosen rather than adding a second model of a family.
    expect(planPanel(big, { size: 7, views }).map((m) => m.model)).toEqual(['a-1', 'b-1', 'c-1', 'a-2', 'b-1', 'c-1', 'a-1']);
  });

  it('is deterministic', () => {
    expect(planPanel(big, { size: 5, views })).toEqual(planPanel(big, { size: 5, views }));
  });

  it('hands out the evidence views in turn', () => {
    expect(planPanel(big, { size: 5, views }).map((m) => m.evidenceView)).toEqual(['raw-logs', 'summaries', 'timeline', 'raw-logs', 'summaries']);
    expect(planPanel(big, { size: 2, views: ['only'] }).map((m) => m.evidenceView)).toEqual(['only', 'only']);
  });

  it('uses the tier asked for, and large by default', () => {
    expect(new Set(planPanel(big, { size: 4, views, tier: 'small' }).map((m) => m.model))).toEqual(new Set(['a-small', 'b-small']));
    expect(planPanel(big, { size: 4, views }).every((m) => !m.model.endsWith('small'))).toBe(true);
  });

  it('honours a required level of data handling per view', () => {
    const registry = createModelRegistry([
      spec('std-1', 'alpha', 'f1'),
      spec('zero-1', 'beta', 'f2', { handling: 'zero-retention' }),
      spec('self-1', 'omega', 'f3', { handling: 'self-hosted' }),
    ]);
    const plan = planPanel(registry, {
      size: 6,
      views: ['raw-logs', 'summaries'],
      requiredHandling: { 'raw-logs': 'zero-retention' },
    });
    const rawModels = plan.filter((m) => m.evidenceView === 'raw-logs').map((m) => m.model);
    expect(rawModels.every((m) => m !== 'std-1')).toBe(true);
    expect(new Set(plan.map((m) => m.model)).size).toBeGreaterThanOrEqual(2);

    const strict = planPanel(registry, { size: 4, views: ['raw-logs', 'summaries'], requiredHandling: { 'raw-logs': 'self-hosted' } });
    expect(strict.filter((m) => m.evidenceView === 'raw-logs').every((m) => m.model === 'self-1')).toBe(true);
  });

  it('says so when no model is good enough for a view', () => {
    const registry = createModelRegistry([spec('std-1', 'alpha', 'f1'), spec('std-2', 'beta', 'f2')]);
    expect(() => planPanel(registry, { size: 3, views: ['raw-logs'], requiredHandling: { 'raw-logs': 'zero-retention' } })).toThrow(
      /meets "zero-retention" handling for the "raw-logs" view/,
    );
  });

  it('refuses to make a panel that cannot be mixed', () => {
    const oneFamily = createModelRegistry([spec('a-1', 'alpha', 'only'), spec('a-2', 'beta', 'only')]);
    expect(() => planPanel(oneFamily, { size: 3, views })).toThrow(/fewer than two families/);
    const noSmall = createModelRegistry([spec('a-1', 'alpha', 'f1'), spec('b-1', 'beta', 'f2')]);
    expect(() => planPanel(noSmall, { size: 3, views, tier: 'small' })).toThrow(/small model/);
    // The handling limit can leave only one family.
    const mixed = createModelRegistry([spec('std-1', 'alpha', 'f1'), spec('zero-1', 'beta', 'f2', { handling: 'zero-retention' })]);
    expect(() => planPanel(mixed, { size: 3, views: ['v'], requiredHandling: { v: 'zero-retention' } })).toThrow(/fewer than two families/);
  });

  it('never puts two models of one family on a panel', () => {
    const registry = createModelRegistry([
      spec('a-v1', 'alpha', 'alpha-line'),
      spec('a-v2', 'alpha', 'alpha-line'),
      spec('b-1', 'beta', 'beta-line'),
    ]);
    for (let size = 2; size <= MAX_PANEL_SIZE; size++) {
      const models = new Set(planPanel(registry, { size, views }).map((m) => m.model));
      expect([...models].filter((m) => m.startsWith('a-')).length).toBe(1);
    }
  });

  it('checks its options', () => {
    for (const size of [0, 1, 10, 2.5, Number.NaN]) {
      expect(() => planPanel(big, { size, views }), `size ${size}`).toThrow(/2 to 9/);
    }
    expect(() => planPanel(big, { size: 3, views: [] })).toThrow(/at least one evidence view/);
    expect(() => planPanel(big, { size: 3, views: [''] })).toThrow(/non-empty/);
    expect(() => planPanel(big, { size: 3, views: ['a', 'a'] })).toThrow(/distinct/);
    expect(() => planPanel(big, { size: 3, views, requiredHandling: { other: 'zero-retention' } })).toThrow(/not one of the views/);
    expect(() => planPanel(big, { size: 3, views, requiredHandling: { 'raw-logs': 'strong' as never } })).toThrow(/handling level/);
    expect(() => planPanel(big, { size: 3, views, idPrefix: '9bad' })).toThrow(/idPrefix/);
    expect(planPanel(big, { size: 2, views, idPrefix: 'rex' }).map((m) => m.id)).toEqual(['rex-1', 'rex-2']);
  });

  describe('for every panel size and several registries', () => {
    const shapes: { name: string; models: ModelSpec[] }[] = [
      { name: 'three single-family providers', models: [spec('p1', 'alpha', 'f1'), spec('p2', 'beta', 'f2'), spec('p3', 'gamma', 'f3')] },
      { name: 'two providers, 2 + 1 families', models: [spec('p1', 'alpha', 'f1'), spec('p2', 'alpha', 'f2'), spec('p3', 'beta', 'f3')] },
      { name: 'four providers', models: [spec('p1', 'a', 'f1'), spec('p2', 'b', 'f2'), spec('p3', 'c', 'f3'), spec('p4', 'd', 'f4')] },
      { name: 'two providers, 3 + 3 families', models: ['1', '2', '3'].flatMap((i) => [spec(`a${i}`, 'alpha', `fa${i}`), spec(`b${i}`, 'beta', `fb${i}`)]) },
      { name: 'one provider, three families', models: [spec('p1', 'solo', 'f1'), spec('p2', 'solo', 'f2'), spec('p3', 'solo', 'f3')] },
      { name: 'duplicate families', models: [spec('p1', 'alpha', 'f1'), spec('p2', 'alpha', 'f1'), spec('p3', 'beta', 'f2'), spec('p4', 'beta', 'f2')] },
    ];

    for (const shape of shapes) {
      it(`keeps its promises: ${shape.name}`, () => {
        const registry = createModelRegistry(shape.models);
        const providers = new Set(shape.models.map((m) => m.provider));
        for (let size = 2; size <= MAX_PANEL_SIZE; size++) {
          const plan = planPanel(registry, { size, views });
          const label = `${shape.name}, size ${size}`;

          expect(plan, label).toHaveLength(size);
          expect(new Set(plan.map((m) => m.id)).size, label).toBe(size);
          expect(plan.map((m) => m.evidenceView), label).toEqual(plan.map((_, i) => views[i % views.length]));

          const used = plan.map((m) => registry.require(m.model));
          expect(new Set(used.map((m) => m.id)).size, label).toBeGreaterThanOrEqual(2);

          // One model per family.
          const perFamily = new Map<string, Set<string>>();
          for (const m of used) perFamily.set(m.family, (perFamily.get(m.family) ?? new Set()).add(m.id));
          expect([...perFamily.values()].every((ids) => ids.size === 1), label).toBe(true);

          // Seats are balanced over providers: no provider has more than one seat more than another.
          const seats = new Map<string, number>([...providers].map((p) => [p, 0]));
          for (const m of used) seats.set(m.provider, (seats.get(m.provider) ?? 0) + 1);
          const counts = [...seats.values()];
          const usedProviders = counts.filter((c) => c > 0).length;
          expect(usedProviders, label).toBe(Math.min(size, providers.size));
          expect(Math.max(...counts) - (size >= providers.size ? Math.min(...counts) : 0), label).toBeLessThanOrEqual(1);

          expect(planPanel(registry, { size, views }), label).toEqual(plan);
        }
      });
    }
  });
});

describe('analyzePanel', () => {
  const registry = createModelRegistry([
    spec('a-1', 'alpha', 'alpha-1'),
    spec('a-2', 'alpha', 'alpha-2'),
    spec('a-1b', 'alpha', 'alpha-1'),
    spec('b-1', 'beta', 'beta-1'),
    spec('c-1', 'gamma', 'gamma-1'),
    spec('z-1', 'zeta', 'zeta-1', { handling: 'zero-retention' }),
  ]);
  const panel = (...models: string[]): PanelMember[] => models.map((model, i) => ({ id: `dog-${i + 1}`, model, evidenceView: `v${i + 1}` }));

  it('has nothing to say about three providers, one dog each', () => {
    const analysis = analyzePanel(registry, policyOf(panel('a-1', 'b-1', 'c-1')));
    expect(analysis).toMatchObject({
      size: 3,
      seatsByProvider: { alpha: 1, beta: 1, gamma: 1 },
      providersThatBlockApproval: [],
      providersThatCanApproveAlone: [],
      correlatedModels: [],
      handlingViolations: [],
      warnings: [],
    });
  });

  it('finds the provider whose outage stops approvals, and the one that could approve alone', () => {
    // Two alpha dogs on two different families, one beta dog.
    const analysis = analyzePanel(registry, policyOf(panel('a-1', 'a-2', 'b-1')));
    expect(analysis.providersThatBlockApproval).toEqual(['alpha']);
    expect(analysis.providersThatCanApproveAlone).toEqual(['alpha']);
    expect(analysis.warnings).toEqual([
      'If alpha is unavailable, the other dogs cannot reach a majority, so nothing is approved until a human acts.',
      "alpha's dogs could approve on their own: they hold a majority and use more than one model.",
    ]);
  });

  it('does not count a provider as able to approve alone if its dogs all run one model, unless diversity is off', () => {
    const members = panel('a-1', 'a-1', 'b-1');
    expect(analyzePanel(registry, policyOf(members)).providersThatCanApproveAlone).toEqual([]);
    expect(analyzePanel(registry, policyOf(members, { requireDistinctModels: false })).providersThatCanApproveAlone).toEqual(['alpha']);
  });

  it('flags models of one family, which the gate counts as different', () => {
    const analysis = analyzePanel(registry, policyOf(panel('a-1', 'a-1b', 'b-1')));
    expect(analysis.correlatedModels).toEqual([['a-1', 'a-1b']]);
    expect(analysis.warnings.some((w) => w.includes('a-1 and a-1b are the same family'))).toBe(true);
  });

  it('on a pair, every provider is needed', () => {
    const analysis = analyzePanel(registry, policyOf(panel('a-1', 'b-1')));
    expect(analysis.providersThatBlockApproval).toEqual(['alpha', 'beta']);
    expect(analysis.providersThatCanApproveAlone).toEqual([]);
  });

  it('under a unanimous rule every provider blocks approval', () => {
    const analysis = analyzePanel(registry, policyOf(panel('a-1', 'b-1', 'c-1'), { rule: 'unanimous' }));
    expect(analysis.providersThatBlockApproval).toEqual(['alpha', 'beta', 'gamma']);
  });

  it('checks the data handling each view needs, including a view named like a prototype property', () => {
    const members: PanelMember[] = [
      { id: 'dog-1', model: 'a-1', evidenceView: 'raw-logs' },
      { id: 'dog-2', model: 'z-1', evidenceView: 'raw-logs' },
      { id: 'dog-3', model: 'b-1', evidenceView: 'constructor' },
    ];
    const analysis = analyzePanel(registry, policyOf(members), { requiredHandling: { 'raw-logs': 'zero-retention' } });
    expect(analysis.handlingViolations).toEqual(['dog-1']);
    expect(analysis.warnings.some((w) => w.startsWith('dog-1 sees a view'))).toBe(true);
  });

  it('refuses a panel that uses a model outside the registry', () => {
    expect(() => analyzePanel(registry, policyOf(panel('a-1', 'rogue-model')))).toThrow(/"dog-2" uses model "rogue-model"/);
  });

  it('agrees with an independent count for every way of seating up to six dogs on four models', () => {
    // Two providers, two families each. The expectation uses plain counting, not the gate.
    const r = createModelRegistry([spec('m1', 'A', 'f1'), spec('m2', 'A', 'f2'), spec('m3', 'B', 'f3'), spec('m4', 'B', 'f4')]);
    const modelIds = ['m1', 'm2', 'm3', 'm4'];
    const provider = (m: string) => (m === 'm1' || m === 'm2' ? 'A' : 'B');
    let checked = 0;

    for (let size = 2; size <= 6; size++) {
      for (let code = 0; code < 4 ** size; code++) {
        const seats: string[] = [];
        for (let i = 0, rest = code; i < size; i++, rest = Math.floor(rest / 4)) seats.push(modelIds[rest % 4] as string);
        const analysis = analyzePanel(r, policyOf(panel(...seats)));
        const required = Math.floor(size / 2) + 1;

        const canApprove = (group: string[]) => group.length >= required && new Set(group).size >= 2;
        const expectedBlockers = ['A', 'B'].filter((p) => !canApprove(seats.filter((m) => provider(m) !== p)));
        const expectedAlone = ['A', 'B'].filter((p) => canApprove(seats.filter((m) => provider(m) === p)));

        // A provider with no seats is not part of the panel, so it is neither a blocker nor able to approve.
        const present = ['A', 'B'].filter((p) => seats.some((m) => provider(m) === p));
        expect(analysis.providersThatBlockApproval, seats.join()).toEqual(expectedBlockers.filter((p) => present.includes(p)));
        expect(analysis.providersThatCanApproveAlone, seats.join()).toEqual(expectedAlone.filter((p) => present.includes(p)));
        checked++;
      }
    }
    expect(checked).toBe(4 ** 2 + 4 ** 3 + 4 ** 4 + 4 ** 5 + 4 ** 6);
  });

  it('shows that a planned panel is as resilient as the registry allows', () => {
    const r = createModelRegistry([spec('p1', 'a', 'f1'), spec('p2', 'b', 'f2'), spec('p3', 'c', 'f3')]);
    for (const size of [3, 5, 7, 9]) {
      const plan = planPanel(r, { size, views: ['v'] });
      const analysis = analyzePanel(r, policyOf(plan));
      expect(analysis.providersThatBlockApproval, `size ${size}`).toEqual([]);
      expect(analysis.providersThatCanApproveAlone, `size ${size}`).toEqual([]);
      expect(analysis.correlatedModels, `size ${size}`).toEqual([]);
    }
  });
});
