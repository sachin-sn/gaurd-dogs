import { describe, expect, it } from 'vitest';
import { runDemo } from '../examples/demo.js';

describe('the demo', () => {
  it('shows what it says it shows, end to end', async () => {
    const lines: string[] = [];
    // A generous deadline: the scene with silent dogs waits for it, and a slow machine must not flip a vote.
    const result = await runDemo((line) => lines.push(line), { deadlineMs: 1500 });
    const text = lines.join('\n');

    // Events are masked before anything is shown, and a burst is one alert.
    expect(text).not.toContain('hunter2');
    expect(text).toContain('7 events: 6 hit tier 1, 5 repeats suppressed');
    const alerts = result.notifications.filter((n) => n.kind === 'alert');
    expect(alerts).toHaveLength(2); // the web-root upload, and the advisory
    expect(alerts[0]?.summary).toContain('Executable file created in a web root on shop-web');

    // Four of seven agree: decided early, the other three told to stop, containment applied.
    const swift = result.scenes['swift'];
    expect(swift).toMatchObject({ submit: 'applied', decidedEarly: true });
    expect(swift?.panel.dogs.filter((d) => d.status === 'not-needed')).toHaveLength(3);
    expect(swift?.codes).toEqual(['panel-approved']);

    // Three for, four against: denied, and a human is told anyway.
    const split = result.scenes['split'];
    expect(split).toMatchObject({ submit: 'denied', decidedEarly: false });
    expect(split?.codes).toEqual(expect.arrayContaining(['panel-rejected', 'minority-flag']));

    // Two dogs silent: not agreement, so it waits for a person, who approves.
    const down = result.scenes['down'];
    expect(down).toMatchObject({ submit: 'pending-human' });
    expect(down?.panel.dogs.filter((d) => d.status === 'timed-out')).toHaveLength(2);
    expect(down?.codes).toEqual(expect.arrayContaining(['panel-split', 'minority-flag']));
    expect(result.humanApproved).toBe('applied');

    // Unanimous, but resting on unverified intel: still a person.
    const intel = result.scenes['intel'];
    expect(intel).toMatchObject({ submit: 'pending-human' });
    expect(intel?.codes).toEqual(expect.arrayContaining(['above-intel-ceiling', 'panel-approved']));

    // Only the two that were cleared ran; neither the denied nor the held ones did.
    expect(result.applied.filter((id) => id.startsWith('act-'))).toEqual(['act-swift', 'act-down']);

    // The human hears about each minority flag with the warning, and is not warned after approving.
    const dissent = result.notifications.filter((n) => n.kind === 'dissent');
    expect(dissent).toHaveLength(2);
    expect(dissent.every((n) => n.summary.startsWith('Review needed: '))).toBe(true);
    const approval = result.notifications.find((n) => n.actionId === 'act-down' && n.kind === 'decision');
    expect(approval?.summary).toContain('cleared to run');
    expect(approval?.summary).not.toContain('Review needed');

    // The whole chain, with nothing hand-fed: three flagged uploads become one incident, triage escalates it,
    // both investigators propose the same containment, and the panel clears it.
    expect(result.chain).toMatchObject({
      incidents: 1,
      triage: { escalated: 1, routine: 0 },
      investigations: { proposal: 2, noAction: 0, failed: 0, errors: 0 },
      proposals: { distinct: 1, duplicate: 1 },
      panels: 1,
      submitted: { applied: 1 },
      errors: 0,
    });
    expect(result.chainAction).toMatch(/^inv:/);
    expect(result.applied).toContain(result.chainAction);
    expect(text).toContain('proposals: 1 distinct');

    // Containment expires on its own.
    expect([...result.reverted].sort()).toEqual(['act-down', 'act-swift', result.chainAction].sort());

    // Everything was recorded, and the record is intact.
    expect(result.auditOk).toBe(true);
    expect(result.auditEntries).toBeGreaterThan(15);
    expect(text).toContain('hash chain intact');
  }, 30_000);
});
