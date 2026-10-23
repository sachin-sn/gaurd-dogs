import { describe, expect, it } from 'vitest';
import {
  MAX_CASE_EVIDENCE,
  MAX_CASE_TARGETS,
  buildCase,
  groupIncidents,
  rawView,
  relatedFlagged,
  summaryView,
  targetsFromIncident,
  triageItem,
  type Case,
  type CaseTarget,
  type EventKind,
  type FlaggedHit,
  type Incident,
  type Severity,
} from '../src/index.js';

const NOW = new Date('2026-10-23T12:00:00.000Z');
const OPTIONS = { now: NOW, windowSeconds: 900, maxEvents: 10 };

interface FlagSpec {
  rule?: string;
  service?: string;
  severity?: Severity;
  attrs?: Record<string, string | number | boolean>;
  kind?: EventKind;
  summary?: string;
}

function flag(eventId: string, spec: FlagSpec = {}): FlaggedHit {
  const service = spec.service ?? 'shop-web';
  return {
    hit: {
      ruleId: spec.rule ?? 'drift.webroot-new-executable',
      eventId,
      severity: spec.severity ?? 'high',
      suggestedLevel: 2,
      summary: spec.summary ?? `Executable file created in a web root on ${service}.`,
      evidence: { path: '/var/www/html/uploads/x.php' },
    },
    event: {
      id: eventId,
      ts: '2026-10-23T11:59:00Z',
      layer: 'application',
      service,
      kind: spec.kind ?? 'file.created',
      attrs: spec.attrs ?? { path: '/var/www/html/uploads/x.php', peer: '203.0.113.9' },
      masked: true,
    },
    alert: 'sent',
  };
}

const TARGETS: CaseTarget[] = [{ target: '203.0.113.9', kinds: ['contain.block-source'] }];

function incidentOf(...flagged: FlaggedHit[]): Incident {
  return groupIncidents(flagged, OPTIONS)[0] as Incident;
}

describe('groupIncidents', () => {
  it('groups hits by rule and service', () => {
    const incidents = groupIncidents(
      [flag('a1'), flag('a2'), flag('b1', { service: 'billing' }), flag('c1', { rule: 'net.unexpected-egress' })],
      OPTIONS,
    );
    expect(incidents).toHaveLength(3);
    const shop = incidents.find((i) => i.ruleId === 'drift.webroot-new-executable' && i.service === 'shop-web') as Incident;
    expect(shop.total).toBe(2);
    expect(shop.flagged.map((f) => f.hit.eventId).sort()).toEqual(['a1', 'a2']);
  });

  it('does not mix up a rule and a service whose names run together', () => {
    const incidents = groupIncidents([flag('a', { rule: 'x|y', service: 'z' }), flag('b', { rule: 'x', service: 'y|z' })], OPTIONS);
    expect(incidents).toHaveLength(2);
  });

  it('takes the highest severity and the summary of the most severe hit', () => {
    const incident = incidentOf(
      flag('a', { severity: 'low', summary: 'Low thing.' }),
      flag('b', { severity: 'critical', summary: 'Critical thing.' }),
      flag('c', { severity: 'medium', summary: 'Medium thing.' }),
    );
    expect(incident.severity).toBe('critical');
    expect(incident.summary).toBe('Critical thing.');
    expect(incident.flagged.map((f) => f.hit.severity)).toEqual(['critical', 'medium', 'low']);
  });

  it('cleans and caps the summary', () => {
    const incident = incidentOf(flag('a', { summary: `line one\nline\ttwo ${'z'.repeat(400)}` }));
    expect(incident.summary.startsWith('line one line two zzz')).toBe(true);
    expect(incident.summary).toHaveLength(300);
  });

  it('keeps at most the limit per incident and counts all of them', () => {
    const many = Array.from({ length: 25 }, (_, i) => flag(`e${i}`));
    const incident = groupIncidents(many, { ...OPTIONS, maxEvents: 10 })[0] as Incident;
    expect(incident.flagged).toHaveLength(10);
    expect(incident.total).toBe(25);
    expect((groupIncidents(many, { ...OPTIONS, maxEvents: 25 })[0] as Incident).flagged).toHaveLength(25);
  });

  it('orders incidents by severity, then size, then id', () => {
    const incidents = groupIncidents(
      [
        flag('a', { service: 'svc-a', severity: 'medium' }),
        flag('b1', { service: 'svc-b', severity: 'critical' }),
        flag('c1', { service: 'svc-c', severity: 'high' }),
        flag('c2', { service: 'svc-c', severity: 'high' }),
        flag('d1', { service: 'svc-d', severity: 'high' }),
      ],
      OPTIONS,
    );
    expect(incidents.map((i) => i.service)).toEqual(['svc-b', 'svc-c', 'svc-d', 'svc-a']);
  });

  it('puts a larger incident before a smaller one of the same severity even when its id sorts later', () => {
    const incidents = groupIncidents(
      [
        flag('d1', { service: 'svc-d', severity: 'high' }),
        flag('z1', { service: 'svc-z', severity: 'high' }),
        flag('z2', { service: 'svc-z', severity: 'high' }),
      ],
      OPTIONS,
    );
    expect(incidents.map((i) => i.service)).toEqual(['svc-z', 'svc-d']);
  });

  it('gives the same id within a window and a new one in the next', () => {
    const at = (iso: string) => (groupIncidents([flag('x')], { ...OPTIONS, now: new Date(iso) })[0] as Incident).id;
    expect(at('2026-10-23T12:00:00Z')).toBe(at('2026-10-23T12:14:59Z'));
    expect(at('2026-10-23T12:00:00Z')).not.toBe(at('2026-10-23T12:15:00Z'));
    expect(incidentOf(flag('a')).id).toBe(incidentOf(flag('b'), flag('c')).id);
    expect(incidentOf(flag('a')).id).not.toBe(incidentOf(flag('a', { service: 'billing' })).id);
    expect(incidentOf(flag('a')).id).not.toBe(incidentOf(flag('a', { rule: 'other.rule' })).id);
  });

  it('gives clean, bounded ids however odd the names are', () => {
    const incident = incidentOf(flag('a', { rule: 'rule with/odd:chars\n'.repeat(10), service: 'svc é<>'.repeat(10) }));
    expect(incident.id).toMatch(/^inc:[A-Za-z0-9._-]*:[A-Za-z0-9._-]*:[0-9a-f]{16}$/);
    expect(incident.id.length).toBeLessThanOrEqual(128);
  });

  it('returns nothing for nothing', () => {
    expect(groupIncidents([], OPTIONS)).toEqual([]);
  });
});

describe('triageItem', () => {
  it('shows the first events in full and how many there were', () => {
    const incident = incidentOf(...Array.from({ length: 8 }, (_, i) => flag(`e${i}`)));
    const item = triageItem(incident);
    expect(item).toMatchObject({ id: incident.id, ruleId: incident.ruleId, service: 'shop-web', severity: 'high' });
    expect(item.summary).toContain('(8 flagged events)');
    const evidence = item.evidence as { flaggedEvents: number; events: { event: { attrs: Record<string, unknown> } }[] };
    expect(evidence.flaggedEvents).toBe(8);
    expect(evidence.events).toHaveLength(5);
    expect(evidence.events[0]?.event.attrs['path']).toBe('/var/www/html/uploads/x.php');
  });

  it('says "event" for one', () => {
    expect(triageItem(incidentOf(flag('a'))).summary).toContain('(1 flagged event)');
  });
});

describe('relatedFlagged', () => {
  it('returns the hits of other incidents on the same service only', () => {
    const incidents = groupIncidents(
      [flag('a1'), flag('b1', { rule: 'net.unexpected-egress' }), flag('c1', { service: 'billing' })],
      OPTIONS,
    );
    const own = incidents.find((i) => i.ruleId === 'drift.webroot-new-executable' && i.service === 'shop-web') as Incident;
    expect(relatedFlagged(own, incidents).map((f) => f.hit.eventId)).toEqual(['b1']);
    expect(relatedFlagged(incidents.find((i) => i.service === 'billing') as Incident, incidents)).toEqual([]);
  });
});

describe('buildCase', () => {
  it('builds a case from the incident, with its own events first and then related ones', () => {
    const incident = incidentOf(flag('own-1'), flag('own-2'));
    const related = [flag('rel-1', { rule: 'net.unexpected-egress', kind: 'net.outbound', attrs: { host: '198.51.100.4' } })];
    const built = buildCase(incident, related, TARGETS) as Case;
    expect(built.id).toBe(incident.id);
    expect(built.targets).toEqual(TARGETS);
    expect(built.evidence.map((e) => e.id)).toEqual(['own-1', 'own-2', 'rel-1']);
    expect(built.summary).toContain('2 flagged events from rule drift.webroot-new-executable on shop-web.');
    expect(built.summary).toContain('Also flagged on this service in the same batch: net.unexpected-egress (1).');
    expect(built.evidence[0]?.content).toMatchObject({
      rule: 'drift.webroot-new-executable',
      severity: 'high',
      flagged: { path: '/var/www/html/uploads/x.php' },
      event: { kind: 'file.created', service: 'shop-web', attrs: { path: '/var/www/html/uploads/x.php', peer: '203.0.113.9' } },
    });
  });

  it('has nothing to say about related events when there are none', () => {
    const built = buildCase(incidentOf(flag('a')), [], TARGETS) as Case;
    expect(built.summary).not.toContain('Also flagged');
    expect(built.summary).toContain('1 flagged event from rule');
  });

  it('is nothing without targets', () => {
    expect(buildCase(incidentOf(flag('a')), [], [])).toBeUndefined();
  });

  it('leaves out events whose ids are not clean, and is nothing if none are left', () => {
    const incident = incidentOf(flag('good'), flag('bad id\n'), flag(' padded'), flag(''), flag('x'.repeat(129)));
    expect((buildCase(incident, [], TARGETS) as Case).evidence.map((e) => e.id)).toEqual(['good']);
    expect(buildCase(incidentOf(flag('bad\tid')), [], TARGETS)).toBeUndefined();
  });

  it('cites an event once even if it is in the incident and the related events', () => {
    const own = flag('same');
    const built = buildCase(incidentOf(own), [own, flag('other')], TARGETS) as Case;
    expect(built.evidence.map((e) => e.id)).toEqual(['same', 'other']);
  });

  it('stops at the case limit', () => {
    const incident = incidentOf(...Array.from({ length: 10 }, (_, i) => flag(`own-${i}`)));
    const related = Array.from({ length: 80 }, (_, i) => flag(`rel-${i}`, { rule: 'other.rule' }));
    const built = buildCase(incident, related, TARGETS) as Case;
    expect(built.evidence).toHaveLength(MAX_CASE_EVIDENCE);
    expect(built.evidence.slice(0, 10).every((e) => e.id.startsWith('own-'))).toBe(true);
  });

  it('caps the summary', () => {
    const built = buildCase(incidentOf(flag('a')), Array.from({ length: 30 }, (_, i) => flag(`r${i}`, { rule: `rule-number-${i}-${'x'.repeat(30)}` })), TARGETS) as Case;
    expect(built.summary.length).toBeLessThanOrEqual(600);
  });
});

describe('targetsFromIncident', () => {
  const sources = [
    { kinds: ['file.created' as const], attr: 'path', actions: ['contain.quarantine-file' as const] },
    { kinds: ['file.created' as const, 'http.request' as const], attr: 'peer', actions: ['contain.block-source' as const, 'contain.rate-limit' as const] },
  ];

  it('reads the listed attributes from events of the listed kinds, in order', () => {
    const incident = incidentOf(flag('a', { attrs: { path: '/var/www/html/a.php', peer: '203.0.113.9' } }), flag('b', { attrs: { path: '/var/www/html/b.php', peer: '203.0.113.10' } }));
    const targets = targetsFromIncident(incident, { sources });
    expect(targets).toEqual([
      { target: '/var/www/html/a.php', kinds: ['contain.quarantine-file'] },
      { target: '203.0.113.9', kinds: ['contain.block-source', 'contain.rate-limit'] },
      { target: '/var/www/html/b.php', kinds: ['contain.quarantine-file'] },
      { target: '203.0.113.10', kinds: ['contain.block-source', 'contain.rate-limit'] },
    ]);
  });

  it('merges the actions when a value comes up under two sources, and lists a value once', () => {
    const incident = incidentOf(flag('a', { attrs: { path: 'shared', peer: 'shared' } }), flag('b', { attrs: { path: 'shared' } }));
    expect(targetsFromIncident(incident, { sources })).toEqual([
      { target: 'shared', kinds: ['contain.quarantine-file', 'contain.block-source', 'contain.rate-limit'] },
    ]);
  });

  it('ignores events of other kinds and attributes that are not listed', () => {
    const incident = incidentOf(flag('a', { kind: 'net.outbound', attrs: { path: '/x', peer: '203.0.113.9', other: '10.0.0.1' } }));
    expect(targetsFromIncident(incident, { sources: [{ kinds: ['file.created'], attr: 'peer', actions: ['contain.block-source'] }] })).toEqual([]);
    expect(targetsFromIncident(incident, { sources: [{ kinds: ['net.outbound'], attr: 'nothing', actions: ['contain.block-source'] }] })).toEqual([]);
  });

  it('skips values that are not clean text, rather than repairing them', () => {
    const attrs = (peer: string | number | boolean) => flag('a', { attrs: { peer } });
    for (const bad of ['', ' 203.0.113.9', '203.0.113.9 ', 'a\nb', 'a\tb', 'x'.repeat(257), 7, true]) {
      expect(targetsFromIncident(incidentOf(attrs(bad)), { sources })).toEqual([]);
    }
    expect(targetsFromIncident(incidentOf(attrs('x'.repeat(256))), { sources })).toHaveLength(1);
  });

  it('offers the incident service when asked, and only when asked', () => {
    const incident = incidentOf(flag('a', { attrs: { peer: '203.0.113.9' } }));
    expect(targetsFromIncident(incident, { sources: [] })).toEqual([]);
    expect(targetsFromIncident(incident, { sources: [], service: ['contain.rate-limit', 'contain.isolate-service'] })).toEqual([
      { target: 'shop-web', kinds: ['contain.rate-limit', 'contain.isolate-service'] },
    ]);
    const odd = incidentOf(flag('a', { service: ' odd\n' }));
    expect(targetsFromIncident(odd, { sources: [], service: ['contain.rate-limit'] })).toEqual([]);
  });

  it('offers at most as many targets as a case can hold, keeping the first', () => {
    const hits = Array.from({ length: 30 }, (_, i) => flag(`e${i}`, { attrs: { peer: `198.51.100.${i}` } }));
    const incident = groupIncidents(hits, { ...OPTIONS, maxEvents: 30 })[0] as Incident;
    const targets = targetsFromIncident(incident, { sources });
    expect(targets).toHaveLength(MAX_CASE_TARGETS);
    expect(targets.map((t) => t.target)).toEqual(Array.from({ length: MAX_CASE_TARGETS }, (_, i) => `198.51.100.${i}`));
    // A later action for a value already listed is still merged in.
    const late = [...hits, flag('late', { attrs: { path: '198.51.100.0' } })];
    const merged = targetsFromIncident(groupIncidents(late, { ...OPTIONS, maxEvents: 40 })[0] as Incident, { sources });
    expect(merged[0]?.kinds).toContain('contain.quarantine-file');
  });
});

describe('the views a dog can be given', () => {
  const built = buildCase(incidentOf(flag('a'), flag('b')), [], TARGETS) as Case;

  it('rawView is every piece, in full', () => {
    expect(rawView(built)).toEqual(built.evidence.map((e) => ({ id: e.id, content: e.content })));
  });

  it('summaryView is the id and the plain values at the top of each piece, and nothing nested', () => {
    const summary = summaryView(built) as Record<string, unknown>[];
    expect(summary).toHaveLength(2);
    expect(summary[0]).toEqual({ id: 'a', rule: 'drift.webroot-new-executable', severity: 'high', ruleSummary: 'Executable file created in a web root on shop-web.' });
    expect(JSON.stringify(summary)).not.toContain('203.0.113.9');
  });

  it('summaryView cannot have its id overwritten, and keeps within its bounds', () => {
    const custom: Case = {
      id: 'c',
      summary: 's',
      targets: TARGETS,
      evidence: [
        { id: 'real-id', content: { id: 'forged', a: 'x'.repeat(200), b: 1, c: true, d: { nested: 1 }, e: [1], f: null, g: 'g', h: 'h', i: 'beyond the eighth', 'k\ney': 'v\nv' } },
        { id: 'plain', content: 'just text' },
        { id: 'list', content: [1, 2] },
        { id: 'nothing', content: null },
      ],
    };
    const summary = summaryView(custom) as Record<string, unknown>[];
    expect(summary[0]?.['id']).toBe('real-id');
    expect(summary[0]?.['a']).toBe(`${'x'.repeat(79)}…`);
    expect(Object.keys(summary[0] as object).length).toBeLessThanOrEqual(9);
    expect(summary[0]).not.toHaveProperty('i');
    expect(summary[0]).not.toHaveProperty('d');
    expect(summary[0]).not.toHaveProperty('f');
    expect(summary.slice(1)).toEqual([{ id: 'plain' }, { id: 'list' }, { id: 'nothing' }]);
  });

  it('summaryView leaves the prototype alone even for a key called __proto__', () => {
    const content = JSON.parse('{"__proto__":"polluted","a":"b"}') as unknown;
    const summary = summaryView({ id: 'c', summary: 's', targets: TARGETS, evidence: [{ id: 'x', content }] }) as object[];
    expect(Object.getPrototypeOf(summary[0])).toBe(Object.prototype);
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
  });
});
