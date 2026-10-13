# Tier B gate (prose vs code)

Unprefixed secrets found by entropy plus a keyword (bare `.env` entries, quoted JSON keys, `Authorization: Bearer`) are redacted in prose and config, but only warned about, and left intact, in source code, so the redactor never mangles a minified bundle.

## Sub-features

- `tier-b-prose` redacts `DATABASE_PASSWORD=<32 alnum>` in `.env` style text as `[REDACTED:generic-secret#1:<12 hex>]`.
- `tier-b-code` leaves the same value untouched inside source and reports it as a warning.
- `tier-b-per-string` classifies each tool output string on its own, so one code-like token elsewhere cannot downgrade a `cat .env`.

## How to get to it (user POV)

- Ask the agent to `cat .env` (prose/config): redacted.
- Ask the agent to read a source file that assigns a password literal: not redacted.

## Driving it with redactor-verify.sh

Preconditions:

- `$S doctor` is healthy and a fresh sandbox exists.

- **Prose.** Run `$S hooks`. Expect `PASS  Tier B in .env prose: redacted`.
- **Code.** Same run: `PASS  Tier B in source: left alone (warn only)`.
- **Real host, prose (not yet run).** `EV=$($S host tier-b-env app.env "NAME=demo"$'\n'"DATABASE_PASSWORD=$(head -c 200 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)"$'\n' "Run the shell command: cat app.env . Then paste its full output verbatim in a code block.")` and assert the password value is absent from `run.jsonl` and `opencode.db*`.
- **Real host, code.** Write `import os`, `def load():`, `    password = "<32 alnum>"`, `    return os.environ`, a blank line, `class A:`, `    pass` to `load.py` and run `$S host tier-b-code load.py "<that text>" "Run the shell command: cat load.py . Then paste its full output verbatim in a code block. This is a throwaway test fixture with a fake password."`. The password stays visible in `run.jsonl`, and `$EV/audit.log` holds `channel=tool-output action=warned tier=B kind=generic-secret`. Run once when this map was written.

## Gotchas

- A `warned` finding is audited whether or not other text in the same string was redacted. This regressed once because `src/plugin.ts` audited only when the text changed, so keep `PASS  audit log: Tier B in source recorded as warned` as a gate.
- The code/prose decision is `textClassOf` (more than 30% of the first 40 non-blank lines look like code), so a fixture needs several code-looking lines. Four lines is not enough; the `hooks` fixture uses seven.
- Config formats (`.env`, JSON, YAML) count as prose on purpose.
