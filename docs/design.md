# Design notes

These are the rules the code already enforces, with pointers to where. The wider design (architecture, threat model, evaluation plan) is evolving; this file records only what is implemented or fixed by a schema.

## Response levels

| Level | Meaning | Constraints |
| --- | --- | --- |
| 1 | Observe (for example raise sampling) | None |
| 2 | Alert a human | None |
| 3 | Contain, reversible | Pre-approved policy, `reversible: true`, an expiry (`ttlSeconds`), and at least two votes |
| 4 | Contain, disruptive | `requiresHumanApproval: true` and at least two votes |

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
- The panel voted against it.

**Held for a human.** A person can clear these:

- Level 4, always.
- The evidence cited allows only a lower level until a human verifies it (the intel ceiling from `ExposureFinding.maxLevel`; the lowest ceiling among everything cited wins).
- Policy does not pre-approve the kind, the duration is longer than policy allows, or the target is outside the pre-approved scope.
- The target is protected (the guard dogs' own services, the audit log, the alert sink).
- The panel is split, or it agrees but all the approvers share one model.

**Panel rule (proposed, not yet confirmed).** With two guard dogs, both must approve and a split goes to a human. With three or more, a majority approves. Abstaining or not voting counts as neither. By default, the approving members must span at least two models, so one model's blind spot cannot approve alone. All of this is policy (`createGatePolicy`), so it can be changed.

**Human approval.** An approval names the approver and the action's digest (`actionDigest`: id, level, kind, target, reason, evidence and duration, but not votes or timestamps). It is accepted only from a listed approver, for that exact action, within the policy's validity window. Change the target or the reason and the approval no longer applies.

**Policy checks at creation.** A panel needs two distinct members. Only reversible containment kinds can be pre-approved, a bare `*` target is refused, and durations are bounded. Scopes use a simple glob (`*` only), not regular expressions.

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

**Notifications** are best effort with a timeout, so a slow or broken notifier cannot stall the executor. Failures are logged.

Audit entry types written by the executor: `gate.decision`, `containment.applying`, `containment.applied`, `containment.apply-failed`, `containment.reverted`, `containment.revert-failed`, `containment.resolved`, `executor.rate-limited`, `executor.rejected`, `executor.duplicate`, `executor.no-adapter`, `executor.notify-failed`.

Adapters must make `apply` all-or-nothing and `revert` safe to call more than once.

Not in the executor yet: throttling and de-duplicating alerts (a noisy source can still produce many notifications), and persistence of waiting proposals beyond the audit log.

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
