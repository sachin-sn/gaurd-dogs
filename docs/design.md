# Design notes

These are the rules the code already enforces, with pointers to where. The wider design (architecture, threat model, evaluation plan) is evolving; this file records only what is implemented or fixed by a schema.

## Response levels

| Level | Meaning | Constraints |
| --- | --- | --- |
| 1 | Observe (for example raise sampling) | None |
| 2 | Alert a human | None |
| 3 | Contain, reversible | Pre-approved policy, `reversible: true`, an expiry (`ttlSeconds`), and votes from the panel (the schema requires at least two) |
| 4 | Contain, disruptive | `requiresHumanApproval: true` and votes from the panel (at least two) |

The schema checks the shape (`schemas/action.schema.json`): reversible and expiring at level 3, human approval flagged at level 4, at least two votes. The response gate (`src/gate/`, below) checks what a schema cannot: that voters are distinct panel members, that the kind matches the level, and everything else in the next section.

Tier 1 only ever suggests level 1 or 2 (`RuleHit.suggestedLevel`). Containment comes from the panel and the response gate.

## Response gate

Investigators propose, the gate decides, and a separate executor acts. `evaluateAction` (`src/gate/gate.ts`) is a pure function: it takes a proposal, the context (time, known evidence, intel ceilings, any human approval) and a validated policy, and returns a decision. It executes nothing.

**Outcomes.** `execute` (may run now, with an expiry for level 3), `await-human` (plausible, but a person must clear it), or `deny`. Every decision carries a notification summary, because every proposed action is reported to a human. `auditDecision` records the decision, and only the decision, in the audit log.

**Denied outright.** These mean the proposal cannot be trusted, and a human approval does not override them:

- The proposal does not match the schema.
- The kind needs a higher level than the one claimed. A disruptive action labelled level 1 is denied, not run.
- A level 3 or 4 proposal cites evidence the gate does not know. This catches an investigator inventing its evidence.
- A vote comes from someone who is not on the panel, or the same guard dog votes twice.
- A majority of the panel voted against it.

**Held for a human.** A person can clear these:

- Level 4, always.
- The evidence cited allows only a lower level until a human verifies it (the intel ceiling from `ExposureFinding.maxLevel`; the lowest ceiling among everything cited wins).
- Policy does not pre-approve the kind, the duration is longer than policy allows, or the target is outside the pre-approved scope.
- The target is protected (the guard dogs' own services, the audit log, the alert sink).
- Neither side has a majority, or a majority agrees but all the approvers share one model.

**Panel rule.** At least two guard dogs run as a panel, and acting needs a **majority of the whole panel**, not of the votes that came back: 2 of 2, 2 of 3, 3 of 5, 4 of 7. A dog that abstains or does not answer has not agreed. If a majority rejects, the proposal is denied. If neither side has a majority, it waits for a human. `rule: 'unanimous'` is available as a stricter policy. By default, the approving members must span at least two models, so one model's blind spot cannot approve alone. All of this is policy (`createGatePolicy`), so it can be changed.

**Minority alert.** If too few dogs approve to act, but at least `dissentAlertMin` did, nothing runs and a human is alerted anyway: the summary starts "Review needed", and the decision carries the code `minority-flag`. The default threshold is a third of the panel and never fewer than two, so 2 of 5 and 3 of 7 raise the alert and a single dog does not. With 7 dogs, 3 approving and 4 rejecting is denied, and a human is told. Every decision from a vote carries the count (`votes`: approve, reject, silent, required, panelSize), and the audit entry stores it.

**Panel size and latency.** A panel has two to nine dogs (`MAX_PANEL_SIZE`). Odd sizes avoid ties, and three or five is the sensible range. Every dog is a model call that the decision waits on, and the gain shrinks fast: if each dog errs independently 20% of the time, a majority is right about 90% of the time with 3 dogs, 94% with 5, 97% with 7 and 98% with 9. That assumes independent errors, which dogs on one model are not. The latency cost is reduced by how the panel is run (the panel runner is not built yet): ask all dogs in parallel, decide as soon as the outcome cannot change (enough approvals to act, or enough rejections that approval is impossible), and stop waiting for silent dogs after a deadline. Silence never counts as agreement. Patrolling is separate from voting: many dogs can patrol different layers, while each finding goes to one panel.

**Model diversity.** Dogs on one model share its blind spots, and one crafted log line can fool every one of them. The gate therefore requires the approving dogs to span at least two models (`requireDistinctModels`, on by default), and members can be given different views of the evidence (raw logs, summaries, a timeline). Different prompts or temperatures on the same model do not count as different models. Whether mixed panels really resist injection better is a question for the evaluation testbed.

**Human approval.** An approval names the approver and the action's digest (`actionDigest`: id, level, kind, target, reason, evidence and duration, but not votes or timestamps). It is accepted only from a listed approver, for that exact action, within the policy's validity window. Change the target or the reason and the approval no longer applies.

**Policy checks at creation.** A panel needs two to nine distinct members. Only reversible containment kinds can be pre-approved, a bare `*` target is refused, and durations are bounded. Scopes use a simple glob (`*` only), not regular expressions.

A test walks every combination of level, votes, ceiling, target and approval, and asserts the gate says `execute` without a human only for a level 3 action backed by an agreeing, diverse panel within scope and ceiling.

The gate does not rate-limit or keep state. That is the executor's job (next section).

## Executor

`Executor.submit` (`src/executor/executor.ts`) is the only way a proposal becomes a change. It runs every proposal through the gate, so there is no path around it, and acts through a `ControlAdapter` per action kind (a WAF rule, a firewall call). The adapters are the only code that touches a real control.

**Fail closed, audit first.** The gate decision is written to the audit log before anything happens, and a second entry (`containment.applying`) records the intent to act. If either write fails, nothing runs and a human is told. If a change goes live but the result cannot be recorded, the executor undoes it at once, because an unrecorded change is one nothing would ever undo.

**Every containment has an owner for its undo.** Level 3 actions carry an expiry. `tick()` reverts what has expired and keeps what it cannot revert: a failed revert is retried on the next tick and reported to a human on the first failure and every tenth after. A human approver can `revoke` early. A level 4 action approved without a duration has no expiry, so only a human ends it.

**Budget.** Automatic containment is limited so that a flood of proposals, or an attacker steering the guard dogs, cannot contain the whole estate. Defaults: 5 active at once, 1 per target, 10 starts per 10 minutes. A proposal over budget is held for a human (`rate-limited`) and reported. A human approval is exempt from the budget, and does not use up the automatic start rate. Level 1 and 2 actions do not count.

**An id runs once.** Once an action id has been cleared, the same id is refused. Approvals cannot be replayed. The same held proposal sent again is reported as already waiting, without logging or notifying twice; a different proposal under a waiting id is a duplicate. Checks and claims happen in one synchronous step, so two submissions at the same moment cannot both pass the same duplicate or budget check.

**Human approval path.** Held proposals wait for `approve`, which asks the gate again with the approval attached. An approval that does not check out leaves the proposal waiting; it cannot slip a rate-limited proposal past the budget. Only listed approvers can `reject` or `revoke`. The queue of waiting proposals is bounded, and dropping one tells a human.

**Restart.** `recover()` verifies the audit log (and refuses to start if it fails), then rebuilds what is active, which ids have run, and which changes are `uncertain`: an intent was logged but the log never says what happened. Uncertain changes are reported to a human, who checks the control by hand and calls `resolveUncertain`. A proposal the budget held back is not counted as run, so it can be proposed again. Waiting proposals are not stored in the log and are lost on restart; the investigators propose them again.

**Notifications** are best effort with a timeout, so a slow or broken notifier cannot stall the executor. Failures are logged. A proposal that did not run but that enough dogs flagged (the gate's `minority-flag`) is sent as its own kind, `dissent`, so a notifier can route it to a higher-attention channel than the routine `decision` reports.

Audit entry types written by the executor: `gate.decision`, `containment.applying`, `containment.applied`, `containment.apply-failed`, `containment.reverted`, `containment.revert-failed`, `containment.resolved`, `executor.rate-limited`, `executor.rejected`, `executor.duplicate`, `executor.no-adapter`, `executor.notify-failed`.

Adapters must make `apply` all-or-nothing and `revert` safe to call more than once.

Not in the executor: alert throttling (that is the pipeline's job, next section) and persistence of waiting proposals beyond the audit log.

## Pipeline

`Pipeline` (`src/pipeline/pipeline.ts`) is what a sidecar feeds. It owns the path from raw input to proposals and hands every proposal to the executor, so the gate still decides everything.

```
raw events    -> mask -> tier 1 -> throttle -> alert / observe proposal -> executor
advisories    -> validate + match inventory -> alert + observe proposal  -> executor
investigator  -> proposal + evidence snapshot ----------------------------> executor
```

**It masks events itself.** The `masked` flag on the wire is never believed; every event goes through the masker, and a masker error rejects the event. Rejected events are counted, with at most five samples whose reasons are sanitised and carry no event content.

**It proposes only levels 1 and 2.** Tier 1 hits become an alert (`alert.notify`) or a sampling increase (`observe.raise-sampling`). Containment comes only from investigators, through `submit`, and still has to pass the gate.

**Throttling.** An alert is keyed by rule and service. The same key is sent once per window (default 300 s); repeats are counted and the next alert says how many were held back. Alert keys come from events, which a compromised application can fabricate, so there is also a cap on different alerts per window (default 20). Beyond it, one flood notice is sent per window ("this can mean an attack, or a broken event source") and the rest are counted. Nothing is dropped silently: the counts go into the audit entry.

**Ids are deterministic.** An alert id is built from the rule, the event and a hash, with unsafe characters removed. Replaying the same event produces the same id, and the executor refuses an id twice, so a replay raises no second alert. An advisory alert's id also covers the record's severity, its fixed version and whether it is verified, so a higher severity, a newly available fix, or a human verifying the record raises a fresh alert, while polling an unchanged feed does not.

**Reasons start with what matters.** The gate summary shows only the first 160 characters of a reason, so alerts lead with severity and what happened, then the suppressed count, then the evidence. A critical record that is not yet verified says so near the start.

**Evidence for the gate.** The pipeline remembers event ids and advisory record ids it has accepted, in a bounded first-in-first-out set (default 10,000), and the ceiling each record allows. When an investigator submits a proposal, the pipeline works out which of the cited ids are known and what ceiling each allows, and passes that snapshot with the proposal. A proposal that waits for a human is therefore judged on what was known when it was made, not on whatever has been evicted since. Ids that were never seen are not in the snapshot, so containment that cites them is denied.

**Audit.** Each batch with anything notable writes one `pipeline.events` or `pipeline.advisories` entry: counts only, never event content. If that write fails the report says `audited: false` and the alerts still go out. Losing a summary must not silence an alert.

**Bounds.** A batch is capped (default 10,000 events; the excess is counted as dropped), the JSONL reader caps line count and line length, and the throttle and the evidence set are bounded. `stats()` reports their sizes.

## Trust boundary for informer records

Informers sit outside the fort. Their output reaches the guard dogs only as structured records in a staging zone, and guard dogs pull it.

`matchAdvisories` (`src/exposure/matcher.ts`) takes records as `unknown` and:

1. Validates each against `schemas/informer-record.schema.json`. Unknown fields are rejected, so a record cannot carry extra instructions. A record marked `verified` must name a reviewer and a time.
2. Drops any record from a source that is not on the allow-list, unless a human has verified it.
3. Applies a ceiling on the response level that the record alone can justify:

| Record | Ceiling | Flags |
| --- | --- | --- |
| Unverified, any severity | 2 (alert) | `raiseSampling` for high and critical; `needsHumanVerification` for critical |
| Verified low or medium | 2 | none |
| Verified high or critical | 3 (reversible containment, panel required) | `raiseSampling` |

Level 4 is never reachable from a record alone.

Free text (`summary`) is untrusted display data. No code path treats it as an instruction.

## Events are untrusted

Events come from the systems being attacked, so every string in them is attacker-influenced.

- `schemas/event.schema.json` requires `masked: true`, the sidecar's attestation that secrets and personal data were masked before the event left the host. In code, only `maskEvent` (`src/masking/masker.ts`) produces it, and only for an event that is valid against the schema.
- `runTier1` validates events before evaluating them and reports invalid ones.
- Rule evidence is passed through `sanitizeEvidence` (control characters stripped, length capped) before it is stored.
- A throwing rule is recorded and skipped; it cannot stop the other rules.

## Log masking

Masking runs on the sidecar, before an event reaches tier 1 or any model. It is `createMasker` in `src/masking/masker.ts`.

| What | How it is masked |
| --- | --- |
| Private key blocks, JWTs, cloud access keys, common service tokens, `Bearer` and `Basic` credentials | Replaced by a placeholder such as `[jwt]` or `Bearer [redacted]` |
| Credentials in URLs, and `password=`, `token=`, `api_key=` style pairs (query strings, JSON, headers) | The value becomes `[redacted]`; the key and the rest of the text stay readable |
| Email addresses | `[email]` |
| Card numbers | `[card]`, only when the digits pass the Luhn check, so ordinary long numbers survive |
| IP addresses (v4 and v6) | A keyed pseudonym, `ip_` plus 12 hex characters from an HMAC. The same address gets the same pseudonym, so events still correlate, and the key stays on the sidecar |
| Attributes with sensitive names (`authorization`, `cookie`, `password`, `token`, `api-key` and similar) | The whole value is replaced, whatever its content or type |

Decisions the code makes:

- **Destination hosts are kept.** The `host` attribute is exempt from IP pseudonyms, because the unexpected-outbound rule needs it (a raw IP is a stronger signal). A test checks that masked events still trigger the same tier 1 rules.
- **Over-masking is the safe failure.** Patterns favour masking a harmless string over missing a secret.
- **Reports hold counts, never values.** A `MaskReport` says how many of each kind were masked.
- **Hostile input is bounded.** Values are cut to 64 KiB before the patterns run, and to 2048 characters after. A test runs adversarial inputs under a time limit.
- **Idempotent.** Masking masked text changes nothing.

What it does not do: recognise names, phone numbers, free-text personal data or unusual secret formats. Keep secrets out of logs at the source as well.

## Guard dog egress

The drift patrol flags outbound calls that are not on a service's allow-list. Guard dogs themselves call a model API and an alert sink, so `guardDogEgress` is exempt, but only for events whose `actor` is `guard-dog`. An application process that contacts the same host is still flagged.

## Audit log format

One JSON object per line, written in canonical form (keys sorted, no whitespace, RFC 8785 style):

```json
{"actor":"dog-a","data":{},"hash":"<sha256 hex>","prev":"<previous hash>","seq":0,"ts":"2026-10-23T10:00:00.000Z","type":"finding"}
```

- `hash` is the SHA-256 of the canonical JSON of the entry without its `hash` field.
- `prev` is the previous entry's `hash`; the first entry uses 64 zeros.
- `seq` starts at 0 and increases by 1.

Editing, deleting, inserting or reordering an entry breaks the chain and is detected. Removing the tail, or rewriting the whole chain, is detected only against an anchor (`head()`) stored outside the writer's reach. In deployment, also make the file append-only at the OS level.

The format is language-neutral so that a PHP sidecar can write and verify the same chain.
