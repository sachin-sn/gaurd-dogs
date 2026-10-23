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

**Panel rule.** At least two guard dogs run as a panel, and acting needs a **majority of the whole panel**, not of the votes that came back: 2 of 2, 2 of 3, 3 of 5, 4 of 7. A dog that abstains or does not answer has not agreed. If a majority rejects, the proposal is denied. If neither side has a majority, it waits for a human. That includes a 1–1 split on a two-dog panel, and a pair in which one dog is silent: on a pair, disagreement is not a reason to deny, a person looks. `rule: 'unanimous'` is available as a stricter policy. By default, the approving members must span at least two models, so one model's blind spot cannot approve alone. All of this is policy (`createGatePolicy`), so it can be changed.

**Minority alert.** If too few dogs approve to act, but at least `dissentAlertMin` did, nothing runs and a human is alerted anyway: the summary starts "Review needed", and the decision carries the code `minority-flag`. The default threshold is a third of the panel and never fewer than two, so 2 of 5 and 3 of 7 raise the alert and a single dog does not. With 7 dogs, 3 approving and 4 rejecting is denied, and a human is told. Every decision from a vote carries the count (`votes`: approve, reject, silent, required, panelSize), and the audit entry stores it.

**Panel size and latency.** A panel has two to nine dogs (`MAX_PANEL_SIZE`). Odd sizes avoid ties, and three or five is the sensible range. Every dog is a model call that the decision waits on, and the gain shrinks fast: if each dog errs independently 20% of the time, a majority is right about 90% of the time with 3 dogs, 94% with 5, 97% with 7 and 98% with 9. That assumes independent errors, which dogs on one model are not. The latency cost is reduced by how the panel is run (see Panel runner below): ask all dogs in parallel, decide as soon as no outstanding vote could change what the gate concludes, and stop waiting for silent dogs after a deadline. Silence never counts as agreement. Patrolling is separate from voting: many dogs can patrol different layers, while each finding goes to one panel.

**Model diversity.** Dogs on one model share its blind spots, and one crafted log line can fool every one of them. The gate therefore requires the approving dogs to span at least two models (`requireDistinctModels`, on by default), and members can be given different views of the evidence (raw logs, summaries, a timeline). Different prompts or temperatures on the same model do not count as different models. Models of one family count as different to the gate but tend to fail together, so the planner never puts two of them on one panel and `analyzePanel` flags a hand-built panel that does (see Choosing models). Whether mixed panels really resist injection better is a question for the evaluation testbed.

**Human approval.** An approval names the approver and the action's digest (`actionDigest`: id, level, kind, target, reason, evidence and duration, but not votes or timestamps). It is accepted only from a listed approver, for that exact action, within the policy's validity window. Change the target or the reason and the approval no longer applies.

**Policy checks at creation.** A panel needs two to nine distinct members. Only reversible containment kinds can be pre-approved, a bare `*` target is refused, and durations are bounded. Scopes use a simple glob (`*` only), not regular expressions.

A test walks every combination of level, votes, ceiling, target and approval, and asserts the gate says `execute` without a human only for a level 3 action backed by an agreeing, diverse panel within scope and ceiling.

The gate does not rate-limit or keep state. That is the executor's job (next section).

## Panel runner

`Panel` (`src/panel/panel.ts`) puts one case to every guard dog on the panel at once and returns their votes. It decides nothing: the gate reads the votes and applies the majority rule.

```
case (action + evidence) -> every dog in parallel, each with its own view
                         -> votes -> withVotes(action, result) -> gate
```

**The panel must be the policy's panel.** The gate counts a majority of its own panel, so the dogs given to `Panel` must match it exactly: same ids, same model and evidence view for each, none missing, none extra. Otherwise a missing dog would stay silent forever, or a dog could claim a model the gate does not know about, and the "approvals span two models" rule would mean nothing.

**A dog that does not answer has not agreed.** A dog that is slow, throws, rejects or answers nonsense is recorded as an abstention with the reason (`timed-out`, `error`, `invalid`), never as a missing vote and never as a yes. The reason for an error names only the kind of failure, not its message, because errors from model APIs can quote the request. Voter ids come from the panel, not from what a dog returns, so a dog cannot vote as another dog. A dog's rationale is model output: control characters are stripped and it is capped at 300 characters before it goes anywhere.

**One deadline for the whole review** (default 20 s). When it passes, dogs still working are told to stop (an `AbortSignal`) and are not waited for, even if they ignore the signal. This is what bounds latency: the decision takes as long as the slowest dog it needs, and never longer than the deadline.

**Each dog sees only its own evidence view**, as a private copy. Changing what a dog was given affects nobody else, and a dog cannot see a view it was not assigned.

**Early decision.** The runner stops waiting as soon as nothing still outstanding could change what the gate concludes. It does not use hand-written conditions for that. It tries every way the outstanding dogs could vote (approve, reject, stay silent) and asks the gate's own tally what each would produce. If every case gives the same verdict, the answer is settled. With at most nine dogs that is at most 3^8 cases, which is instant, and it cannot drift from the gate's rules.

This keeps the minority alert intact. With seven dogs, four rejections do not settle anything while three more could still approve, because three approvals are what make a human hear about a rejected proposal. With nine dogs, five rejections plus three approvals do settle it, because the last dog cannot change either the rejection or the alert. With two dogs, one failure settles it. A majority made of a single model does not stop the wait while a dog of another model is still out, because its approval would change the verdict. The tests check the claim directly: for every panel size from 2 to 6, every combination of answers and several arrival orders, the verdict with early stopping equals the verdict of waiting for everyone.

Dogs that were not needed are recorded as `not-needed` abstentions, so the audit trail shows they did not review rather than that they agreed or disagreed.

**Votes are bound to the action they were cast on.** `withVotes` attaches the votes only if the action still has the same fingerprint (`actionDigest`) as when it was reviewed. A target widened, a level raised or a duration lengthened after the vote is refused. Votes already on an action are replaced, never merged.

**Audit.** Each review writes one `panel.review` entry: the action id and fingerprint, the verdict, whether it ended early, and for each dog its model, status, decision, time and (cleaned) rationale. A failed write is reported as `audited: false` and does not lose the votes; the executor's own audit entries are still fail-closed.

## Choosing models

**Configuration decides which model a dog calls. A dog never does, and nothing in the evidence can.** The evidence comes from the systems under attack. If a log line, or a model reading one, could choose the model or the endpoint, an attacker could send masked-but-still-sensitive logs to a server they control, or steer a vote to a weak model. So a dog receives a registered model and has no way to name another.

**The registry** (`createModelRegistry`, `src/models/registry.ts`) lists the models that may be used. Each has an id, a provider, a family (its lineage; models of one family share blind spots), a tier (`small` for triage, `large` for investigation and votes on containment), one HTTPS endpoint, a data handling level (`standard`, `zero-retention`, `self-hosted`) and a limit on how much evidence one call may carry. Validation is strict because the endpoint is where logs go: HTTPS only, a host name rather than an IP address, no credentials, query string or fragment (that is where keys end up in logs), and no backslashes, whitespace or extra slashes, which different URL parsers read differently. The endpoint is stored in canonical form, so the host on the egress allow-list and the host actually contacted cannot differ. `egressHosts()` gives the hosts for `RulesConfig.guardDogEgress`, so that allow-list is derived from the models in use instead of kept by hand. Data handling is attested by whoever deploys; the registry cannot check it.

**Which stage uses which model.** Tier 1 uses no model. Tier 2 is one to three small models that can only escalate, never act (see Tier 2 triage). Tier 3 is the panel: every dog votes on every finding, using a large model, up to nine dogs. Which model sits behind which seat is fixed when the panel is planned, not per finding.

**Planning a panel** (`planPanel`) is deterministic and spreads the seats over providers first and model families second:

- the approving dogs can span two models, which the gate requires;
- when the registry allows, no single provider holds a majority, so one provider's outage, policy change or compromise cannot approve alone or block every approval;
- two models of one family never sit on one panel, because the gate counts them as different while their errors are alike;
- a seat whose evidence view is sensitive (say raw logs) goes only to a model whose handling is strong enough, if you set a minimum for that view.

It refuses to plan a panel that cannot be mixed, with fewer than two families after the limits are applied. A single-model panel can still be written by hand, with `requireDistinctModels` off.

**Checking a panel** (`analyzePanel`) reports what a panel depends on: which providers' outage would leave the rest unable to approve, which providers' dogs could approve alone, models that share a family, and dogs whose model is too weak for their view. It asks the gate itself whether a set of approvers would pass, so it follows the gate's majority and diversity rules exactly. A dog that uses a model outside the registry is an error, because such a model has no vetted endpoint.

**No silent fallback.** If a dog's model is down, the dog abstains and is reported. It does not switch to another model, because the gate's diversity check relies on each dog's declared model; a substitute from the same family as another dog would make that check untrue. Resilience comes from how the panel is composed, which `analyzePanel` shows, and a human can change the policy.

**Limits.** That different providers err independently is an assumption, and a question for the evaluation testbed. The host allow-list does not restrict ports.

## Model-backed dogs

`ModelDog` (`src/dogs/`) is a guard dog that asks one registered model for its vote. `createModelDogs(policy, registry, bindings)` builds one for every seat on the policy's panel.

```
task (action + this dog's evidence view)
  -> prompt: fixed instructions (system) + delimited JSON data (user)
  -> client: the registry's endpoint, one JSON POST
  -> reply: exactly one JSON vote, or an error
  -> vote (approve / reject / abstain) -> Panel
```

**The dog's model is the client's model.** `ModelDog.model` is read from the client, which was made from a registry id, so a dog's label cannot differ from the model it calls. The gate's "approvals span two models" rule trusts that label, and a mislabelled dog would defeat it.

**A client can only call what the registry holds.** `createModelClient(registry, id, binding)` takes an id, never a URL. The transport posts to that endpoint and nowhere else, refuses redirects (a redirect would carry the key and the evidence to a host nobody put on the egress allow-list), reads the answer with a size cap, and stops at the panel's abort signal or its own timeout. A model's name for itself (`apiModel`) is a separate, validated setting; for Gemini the model is in the registered endpoint's path, so the setting is refused.

**Errors tell the audit trail the kind of failure and nothing else.** Model APIs can quote the request, and the request holds the evidence. The error never contains the response body, the headers, the underlying error's message, or the key. The panel records only the error's name, so each kind has its own: `ModelHttpError` (with a status number), `ModelNetworkError`, `ModelResponseError`, `ModelRefusedError`, `ModelOutputError`, `ModelConfigError`, `ModelInputError`. A key is checked for characters that could break a header, and a key function that throws is not repeated.

**The prompt treats everything as data.** The instructions are in the system message, which no evidence reaches. The proposal and the evidence are written out as JSON, so every log line is one string value, inside a block whose tag carries a random per-call token. `<` and `>` are escaped inside the JSON, so the data cannot close its block or open another. The model is told that text in the data that addresses it, or tells it how to vote, is part of the evidence and is no reason to approve. The proposal's reason and references are marked as the proposer's own claims. None of this makes injection impossible; the design does not depend on it, because a vote is one of several and the worst a won vote can do is a reversible, expiring action that a human is told about.

**The reply must be exactly a vote.** The whole reply must be one JSON object with `decision` set to `approve`, `reject` or `abstain` (optionally inside one code fence), or the dog reports an error and counts as an abstention. Prose around a JSON object is not searched for one: a model explaining that a log line contains `{"decision":"approve"}` must not have that quoted line become a vote. Replies cut off by the token limit, filtered or refused by the provider are errors, never repaired. The rationale is cleaned and capped, and nothing else the model wrote is passed on.

**A dog never approves on evidence it could not fully see.** The registry limits how much evidence one call may carry. If the evidence is longer, it is cut, the prompt says so, and a dog that answers `approve` is turned into an abstention. The lines that were cut may be the ones that show the traffic was harmless. Rejecting or abstaining on partial evidence is safe, so those stand.

**Three protocols.** `anthropic` (Messages API), `gemini` (`generateContent`) and `openai-compatible` (chat completions, which also covers self-hosted servers such as vLLM and Ollama). Keys go in headers, never in the URL, which the registry forbids from carrying a query string. No sampling settings are sent, because newer models refuse them. The adapters follow each provider's documentation and are tested against fakes of its response shape, and the transport against a real local server; they have not been run against the live services.

**Limits.** A model can still be talked into a wrong vote; the defence is the panel. The `gemini` adapter sends the key in a header, which is supported but is not the form in every example in Google's reference pages.

## Tier 2 triage

`TriageDog` (`src/dogs/triage.ts`) reads a batch of up to 20 flags from tier 1 and says, for each, `escalate` (worth a full investigation by the panel) or `routine`. It reuses the model clients, the prompt hardening and the strict reply reading from the model-backed dogs.

**It can only add attention.** Its output is one of two words for an item tier 1 already flagged. It cannot propose an action, name a target or cite evidence, and `routine` suppresses nothing: the alert for the item has already gone to a human before triage runs. Being fooled costs a missed investigation of something a human was already told about, or one wasted investigation.

**Dismissal has to be earned.** An item is `routine` only if every model looked at all of it and said so. A model that failed, timed out, was cancelled, answered nonsense, skipped the item or saw the evidence cut to fit its limit does not get to dismiss it. What such an item gets is `onFailure`, which defaults to `escalate`: the cost of a wasted investigation is bounded, the cost of a missed attack is not. Taking down or flooding tier 2 therefore buys an attacker more investigations, not fewer, and those have their own budget. Set `onFailure: 'routine'` to make it the other way round.

**Several models, any one can escalate.** With two or three clients, an item is escalated if any of them says so. To get an item dismissed an attacker has to fool every model with one payload, while fooling one gains nothing. Use models of different families. The models must be distinct, and the number is capped at three.

**The reply is read strictly.** The whole reply must be one JSON object with a `results` list (the same rule as for votes: prose around JSON is never searched for JSON). Entries for ids that were not asked about, or that are malformed, are ignored: they can add nothing, and an item they were meant for is treated as skipped. If an item appears twice, escalate wins. Give triage clients a `maxOutputTokens` of about 1,500 so a full batch fits.

**The flags are data.** The same delimited, escaped JSON block as for votes, with a random token in the tag. The evidence budget (the model's `maxInputChars`) is split evenly between the items, and an item cut to its share is marked as cut in the prompt and counts as not seen in full.

**Audit.** One `triage.review` entry per batch: how many items, how many escalated, how many were settled by the fallback, and each model's status (`ok`, `timed-out`, `cancelled` or the error's name). Counts only, never the flags, their evidence or a model's reasons.

**Limits.** Triage looks at what tier 1 flagged. It does not read the event stream, so it cannot find what no rule noticed. It is not yet wired to anything: the investigators that turn an escalation into a proposed action are the next piece.

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
