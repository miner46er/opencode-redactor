# System prompt redaction

A credential written into any text part of the system prompt (agent instructions, skills) is redacted on every turn. MCP tool descriptions are deliberately not scanned.

## Sub-features

- `system-text-parts` rewrites each `system[].text` that holds a credential and leaves clean parts alone.
- `system-tools-untouched` never edits `tools` descriptions (out of scope by design).

## How to get to it (user POV)

- Put a credential in an agent or skill instruction file that OpenCode folds into the system prompt, then start any session.

## Driving it with redactor-verify.sh

Preconditions:

- `$S doctor` is healthy and a fresh sandbox exists.

- **Model-free.** Run `$S hooks`. Expect `PASS  system prompt: credential removed` and `PASS  system prompt: clean part untouched`, and `PASS  audit log: channel=system recorded`.
- **Real host (not yet run).** Write `proj/AGENTS.md` containing `deploy token: $CANARY` before running `$S host system-pat unused.txt x "Reply with only the word ok."`, then assert the canary is absent from `run.jsonl` and `run.stderr` and `$EV/audit.log` has `channel=system`. It is unconfirmed that this OpenCode version folds `AGENTS.md` into `system[]`; if no `channel=system` line appears, report the path as unreachable, not as passed.

## Gotchas

- The plugin writes to a `readonly` field with a cast (`part.text`); README states this was verified against 2.0.27 only. Re-prove it after any OpenCode upgrade.
- A secret inside an MCP tool description still reaches the provider. That is documented, not a bug.
