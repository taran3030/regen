# Contributing to Regen

Thanks for helping. The easiest way in is a new check.

## Add a header or path check

Checks live in [`checks/`](checks/), one per line, tab-separated:

- **`checks/headers.tsv`**: a response header every site should send, the severity when it's missing, and one line on why it matters.
- **`checks/paths.tsv`**: a path that shouldn't be public, the severity when it answers, and why.

Severities are `critical`, `high`, `medium`, `low` or `info`. Keep the "why" to one plain sentence a developer can act on.

Then run the suite (it needs `bash`, `curl` and `python3`):

```bash
bash tests/run.sh
```

It starts local test servers and checks that every header check passes on a hardened site and fails on a bare one, that an exposed file is caught, and that a single-page app's fallback page isn't mistaken for one. CI runs the same thing on every pull request.

## Bigger changes

Open an issue first for new scanners, profiles or output formats, so we can agree on the shape before you build it. Keep changes small and focused, with a test that fails without your change.

## Rules

- Regen only scans what its user owns or has permission to test. Don't add anything meant to attack, overload or evade detection on someone else's system.
- No real scan results, hostnames or secrets in issues, pull requests or test fixtures.
- Report a vulnerability in Regen itself privately; see [SECURITY.md](SECURITY.md).

By contributing, you agree your contribution is licensed under the [AGPL-3.0](LICENSE).
