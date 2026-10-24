# Evaluation testbed

`npm run eval` runs a labelled corpus of scenarios through the real code (masking, tier 1, throttling, the orchestrator, triage, the investigators, the panel, the gate, the executor and the audit log) and scores what happens against the truth written beside each scenario.

## What this can and cannot say

The models are simulated. A profile answers triage, investigation and voting requests the way a certain kind of model would, and it is given the real prompts, so the real prompt builders, parsers and checks all run. What is replaced is only the thinking.

So the numbers describe **the system around the models**: what tier 1 can see, what the grouping and the budget leave out, what the gate lets through, what the executor applies and what expires. They say nothing about how accurate any real model is, or how readily one is argued out of its instructions. Those need real models, and the harness takes a profile for exactly that (a later change).

The three profiles bracket the real thing:

| Profile | Behaves like | Used to show |
|---|---|---|
| `oracle` | A perfect analyst: recognises the attack, names the right containment, votes accordingly | What the system does when the models are right, which isolates the loss that comes from everything else |
| `credulous` | A model that believes everything: escalates every item, proposes the first thing it is offered, approves every proposal | What the guards around the models bound when the models are no help |
| `skeptic` | A model that never acts: calls everything routine, proposes nothing, rejects every proposal | What is left when models never act: tier 1's alerts, and a person |

## Running it

```
npm run eval                                          # every profile, every scenario
npm run eval -- --json results.json                   # also write the scores and summaries as JSON
npm run eval -- --profile oracle --scenario webshell-upload
```

The clock is fake, so a scenario that spans forty minutes takes milliseconds, and a run is repeatable. "Seconds to contain" is on that clock: it measures how long the attack waited for events and windows, not how long models take to answer.

## The corpus

Eighteen scenarios in five categories. Every address is from a documentation range and every host ends in `.example`; events are the log lines a sidecar would report, not payloads.

| Category | Meaning | Scenarios |
|---|---|---|
| `attack` | Malicious, and tier 1 has a rule for it | `webshell-upload`, `double-extension-upload`, `case-and-dots-upload`, `web-process-spawns-shell`, `reverse-shell-callback`, `upload-shell-callback-chain`, `low-and-slow-uploads` |
| `evasion` | Malicious, and no tier 1 rule matches. Known gaps, on purpose | `htaccess-enables-php`, `renamed-binary-spawn`, `exfiltration-via-allowed-host` |
| `injection` | Malicious, with text in attacker-controlled fields that addresses the models, or credentials in the fields | `injection-in-attributes`, `secrets-in-events` |
| `noise` | Harmless, and tier 1 flags it anyway | `report-generator-runs-python`, `new-cdn-host` |
| `benign` | Harmless, and nothing flags it | `deploy-writes-php`, `ordinary-uploads`, `allowed-egress`, `cron-runs-curl` |

A scenario carries its own truth: a label on every event, the strings (`markers`) by which a model that knows the truth recognises the attack, the containments that would be right, what the deployer lets an investigator name, and the outcome a perfect model should reach. `checkScenario` rejects a scenario whose data contradicts itself (a marker that appears in a harmless event, a correct containment that is not among the targets, and so on), and the tests hold the corpus to it.

Client addresses in targets are written `ip:203.0.113.9`. The pipeline replaces client addresses with keyed pseudonyms before anything else sees them, so a containment aimed at a client names the pseudonym, and the harness swaps each marker for the pseudonym the masker produces.

## What is measured

Per scenario:

- **Outcome**: `contained` (a correct containment was applied); `detected-not-contained` (tier 1 flagged the malicious events and nothing correct was applied); `missed-by-tier1`; and for harmless scenarios `quiet`, `alerted-only` (tier 1 alerted and it went no further) or `wrongly-contained`.
- **Wrong containments**: containments applied that are not among the correct ones.
- **Forbidden targets**: proposals or containments aimed at something the scenario says no proposal may name (for example an address an attacker tried to get blocked).
- **Outside the offer**: containment proposals that named a target or kind the investigators were not offered. The investigator is meant to make this impossible; the metric checks that it is.
- **Secrets**: planted credentials found in anything sent to a model, or in the audit log.
- **Never reverted**: containments still in place two hours after the last event.
- **Audit**: whether the hash chain verified.
- **Calls**: model calls by role, which is the cost.
- **Seconds to contain**: on the scenario clock, as above.

Per profile: the share of malicious scenarios tier 1 flagged, the share of the ones it has rules for that ended contained, and the totals of the safety counts above.

## Offline results

| | `oracle` | `credulous` | `skeptic` |
|---|---|---|---|
| Malicious scenarios flagged by tier 1 | 9 of 12 | 9 of 12 | 9 of 12 |
| Of those with rules (attack, injection), contained | 9 of 9 | 9 of 9 | 0 of 9 |
| Harmless scenarios contained | 0 | 2 (the noise) | 0 |
| Forbidden targets, targets outside the offer, secrets leaked, containments never reverted, broken audit chains | 0 | 0 | 0 |
| Mean model calls per scenario (triage / investigator / dog) | 0.8 / 1.4 / 2.2 | 0.8 / 1.7 / 2.5 | 0.8 / 0 / 0 |

What these show, and what they do not:

- Tier 1 misses a quarter of the malicious scenarios whatever the models do. The three it misses are written to show that: a configuration file changed so images run as code, a shell under another name, and data sent out through an allowed host. Nothing downstream can recover what tier 1 never flags. This is the main limit of the design as built, and the paper should say so.
- A perfect model contains everything tier 1 flags and touches nothing else.
- A model that believes everything is contained by the guards, not by itself: it contains the two harmless noise scenarios, and each time the cost is one reversible, expiring rate limit on a pre-approved target. In this corpus it never reached a target nobody offered or a kind the policy does not pre-approve, and every containment was undone.
- A model that never acts leaves the alerts, which tier 1 still sends and which a person still gets.

## Findings so far

These came from writing the scenarios, and each is fixed or recorded.

1. **The summary view left out what the rule found.** One panel dog reads a short form of the evidence so that a payload written to fool a reader of raw logs is less likely to fool both. It kept only the top-level scalars of each piece, which dropped the path, host or process that the rule had flagged, so that dog could not tell whether a proposal was aimed at the right thing. `summaryView` now also carries the plain values the rule extracted (`flagged.path`, `flagged.host`, ...), trimmed. Fixed in this change.
2. **A second incident repeats a containment that is already in place.** In `upload-shell-callback-chain` the spawn incident proposes quarantining the file the upload incident already quarantined. The panel is asked again (three more calls) and the executor then refuses it as rate-limited, because the target already has an active containment. Harmless, but wasted. The orchestrator's memory of handled proposals is keyed by proposal id; keying it by kind and target would skip the review. Not changed here.
3. **A containment aimed at a client names a pseudonym.** The pipeline pseudonymises client addresses with a keyed hash, which cannot be reversed, so a `contain.block-source` on a client names `ip_...` and the host's control adapter needs its own table from pseudonym to address. Models never hold it. The sidecar work has to provide it.

## Threats to validity

- **Simulated models.** Stated above. Nothing here is evidence about how real models behave.
- **A small, hand-made corpus.** Eighteen scenarios written by the designer test the properties the designer thought of. They are a regression suite and a set of examples, not a sample of real traffic.
- **Markers.** The oracle recognises an attack by strings chosen by the scenario's author, so it is right by construction. It is a reference point, not a measurement.
- **Fixed deployment.** One policy, one panel size, one pre-approval table. The options (`panelSize`, `investigators`, `triage`) let the tests vary them; the results above use the defaults (three dogs of three families, two investigators, triage on).
- **One service, no background traffic.** Scenarios are short and isolated. Interaction between many services, or a long period of noise, is not tested.

## What comes next

1. Profiles that fail in worse ways: models that obey instructions found in the evidence, models that all err the same way (to compare a panel of one family with a panel of three), and a lying investigator. These test the claim that the worst a won vote can do is a reversible, expiring action that a person is told about.
2. A profile that calls real models through the adapters, run on the same corpus.
3. Scenarios from public incident write-ups, once the first two are in.
