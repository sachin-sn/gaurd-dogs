# Contributing

Thanks for taking an interest. This is an early research prototype, so expect the interfaces to move.

## Ground rules

This project is **defensive**.

- Do not add working exploits, weaponised payloads or tooling aimed at third-party systems.
- Test traffic must be simulated and inert, and run in an isolated environment you own.
- Fixtures must be synthetic. Use `example.invalid` hosts and made-up advisory ids such as `GD-EXAMPLE-0001`. Never commit real secrets, personal data or real production logs.
- Treat every log line, event and informer record as attacker-controlled input. New code that reads them must validate against `schemas/` first.

## Development

Requires Node 22 or newer.

```sh
npm install
npm run check   # typecheck and tests
npm run build
```

## Pull requests

- Keep changes small and focused, with tests. A rule or check that blocks something should have a test for the thing it must not block.
- Changes to a schema in `schemas/` should update the fixtures and `docs/design.md`.
- If a change widens what a guard dog may do automatically, say so in the description and explain why it is safe.
- For security problems, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## License

By contributing, you agree that your contribution is licensed under Apache-2.0.
