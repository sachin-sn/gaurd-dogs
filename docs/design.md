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
