# Prompt redaction

A credential typed or pasted into a prompt is replaced with a placeholder before the prompt is persisted and sent. The same credential gets the same placeholder for the whole session, a different session gets a different fingerprint, and redacting twice changes nothing.

## Sub-features

- `prompt-tier-a` replaces `ghp_...` in user text with `[REDACTED:github-pat#1:<12 hex>]` and keeps the surrounding text.
- `prompt-stable-placeholder` gives one credential one placeholder within a session.
- `prompt-session-scope` gives the same credential different fingerprints in different sessions.
- `prompt-idempotent` leaves already-redacted text unchanged.

## How to get to it (user POV)

- Type or paste text containing a credential into the OpenCode prompt.
- `opencode run "<message containing a credential>"`.

## Driving it with redactor-verify.sh

Preconditions:

- `$S doctor` is healthy and a fresh sandbox exists.

- **Model-free.** Run `$S hooks`. Expect `PASS` for `prompt: Tier A value removed`, `prompt: typed placeholder inserted`, `prompt: surrounding text preserved`, `session: same credential -> same placeholder`, `idempotent: redacting redacted text changes nothing`, and `session: other session gets a different fingerprint`.
- **Real host (not yet run).** Run `EV=$($S host prompt-pat unused.txt "x" "My token is $CANARY, please reply with only the word ok.")`. Expect `grep -c "$CANARY"` to be `0` in `run.jsonl`, `run.stderr` and `opencode.db*`, and `$EV/audit.log` to contain `channel=prompt action=redacted tier=A kind=github-pat`. Read the stored user message back with `sqlite3 "$RUN/data/opencode/opencode.db" "select data from session_message" | grep -c REDACTED`.

## Gotchas

- The recipe's host half has not been executed against a real model; only `hooks` was proven. Treat host proof as outstanding.
- Placeholder numbering (`#1`) is per kind per session, so the second distinct `github-pat` in one session is `#2`.
- Each `hooks` run prints a new fingerprint; compare within a run, never against an earlier one.
