# Audit log

Every finding is recorded as one line of metadata (channel, action, tier, kind, fingerprint, offset) in `~/.local/share/opencode/redactor-audit.log`, mode 600. Values are never written. Tool input is scanned and logged as `observed` but never rewritten.

## Sub-features

- `audit-metadata-only` writes no credential value.
- `audit-channels` records `prompt`, `system`, `tool-output` and `tool-input`.
- `audit-tool-input-observed` logs a credential in tool input as `action=observed` and leaves the command intact.
- `audit-mode-600` creates the file with mode 600.
- `audit-warned` logs a Tier B hit in source as `action=warned`, even when nothing else in the text was redacted.

## How to get to it (user POV)

- Read `~/.local/share/opencode/redactor-audit.log` after any redaction.

## Driving it with redactor-verify.sh

Preconditions:

- `$S doctor` is healthy (it requires the audit directory to exist inside the sandbox home).

- **Model-free.** Run `$S hooks`, then read `$EVID/hooks/audit.log`. Expect `PASS` for every `audit log:` line, and lines shaped `<ISO time> channel=<c> action=<a> tier=<A|B> kind=<k> fp=<12 hex> offset=<n>`.
- **Real host.** After `$S host ...`, `$EV/audit.log` holds only that run's lines (the helper deletes the log first). For tool output expect `channel=tool-output action=redacted tier=A kind=github-pat`.
- **Tool input observed.** `$S hooks` prints `PASS  tool input: not rewritten` and `PASS  audit log: tool-input recorded as observed`.

## Gotchas

- The audit path is `homedir()/.local/share/opencode/`, not `XDG_DATA_HOME`. The sandbox creates that directory; without it the plugin silently fails to write.
- Bun ignores a `HOME` assigned at runtime. Always run `hooks` through `$S`, which starts Bun with `HOME` already set; the harness aborts otherwise. Running it bare once wrote to the real audit log.
