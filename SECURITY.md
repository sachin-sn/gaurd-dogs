# Security policy

## Reporting a vulnerability

Please report vulnerabilities in this project privately, using GitHub's **Report a vulnerability** option on the repository's Security tab. Do not open a public issue for a vulnerability.

Include what you found, how to reproduce it, and the version or commit. I aim to acknowledge reports within a week. This is an early research prototype maintained by one person, so please be patient.

## In scope

Flaws in how this project defends itself, for example:

- Ways to make a guard dog act on unverified or forged intel.
- Prompt injection or log poisoning that changes what a guard dog decides.
- Ways to bypass the response levels, the panel requirement or the allow-lists.
- Ways to tamper with the audit log without detection (beyond the limits documented in the README).
- Dependencies with known vulnerabilities that affect the project.

## Out of scope

- Vulnerabilities in the software that guard dogs are meant to watch.
- Missing features that the README lists as not built yet.

## Please do not

- Send working exploits for third-party software.
- Test against systems you do not own or have permission to test.
- Include real secrets or personal data in a report.

## Supported versions

Only the latest commit on `main` is supported while the project is at version 0.x.
