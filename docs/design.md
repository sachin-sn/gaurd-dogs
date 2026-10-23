# Design notes

These are the rules the code already enforces, with pointers to where. The wider design (architecture, threat model, evaluation plan) is evolving; this file records only what is implemented or fixed by a schema.

## Response levels

| Level | Meaning | Constraints |
| --- | --- | --- |
| 1 | Observe (for example raise sampling) | None |
| 2 | Alert a human | None |
| 3 | Contain, reversible | Pre-approved policy, `reversible: true`, an expiry (`ttlSeconds`), and at least two votes |
| 4 | Contain, disruptive | `requiresHumanApproval: true` and at least two votes |

Enforced by `schemas/action.schema.json`. The schema checks the number of votes; the response gate (not built yet) must check that voters are distinct.

Tier 1 only ever suggests level 1 or 2 (`RuleHit.suggestedLevel`). Containment comes from the panel and the response gate.

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

- `schemas/event.schema.json` requires `masked: true`, the sidecar's attestation that secrets and personal data were masked before the event left the host.
- `runTier1` validates events before evaluating them and reports invalid ones.
- Rule evidence is passed through `sanitizeEvidence` (control characters stripped, length capped) before it is stored.
- A throwing rule is recorded and skipped; it cannot stop the other rules.

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
