# opencode-redactor verification map

This directory is the maintained source for verifying the user-facing behavior of opencode-redactor. Read this index before driving the plugin, then use the matching feature file as the recipe.

## Baseline preconditions

- `S=.claude/skills/verify-opencode-redactor/scripts/redactor-verify.sh`, and `$S new` has created the sandbox.
- `$S doctor` prints `doctor: healthy`.
- Use fresh fabricated canaries per run (`ghp_` + 36 alphanumerics, 32-char random values). Never use a real credential.
- Never drive an OpenCode instance this run did not start. Every `opencode` call passes `--standalone` and runs with stdin from `/dev/null`.
- The audit log is `$RUN/home/.local/share/opencode/redactor-audit.log`, not your real one.

## Driving conventions

- Two drives: `$S hooks` (model-free, fires the real plugin's hooks) and `$S host <label> <file> <content> <prompt>` (real OpenCode and model). Prefer `host` for anything about what the host persists or sends.
- A host run only counts if `run.stderr` shows `[redactor] active` and `run.jsonl` shows the tool actually ran.
- Treat prompts literally. Ask the model to `cat` a file and paste it in a code block; do not ask it to "quote the token", it refuses.
- Evidence goes to `/tmp/opencode-redactor-evidence/<run-id>/<label>/` and survives `cleanup`.

## Proof and skip reporting

- Proof is the action, the resulting state, and a second view: the raw canary input, `grep -c` of the canary in `run.jsonl`, `run.stderr` and `opencode.db*`, the placeholder in the stream, and the matching `audit.log` line.
- Record the feature ID and the drive (`hooks` or `host`) with every artifact.
- Report an unreachable path with the attempted command and the unmet precondition.
- Do not report a path as verified through a different drive. A `hooks` PASS is not host proof.

## Features

| ID | Feature | File | Host recipe run when this map was written |
|---|---|---|---|
| `tool-output-redaction` | Secrets in tool output are redacted before the model and the session store see them | [tool-output-redaction.md](tool-output-redaction.md) | yes |
| `prompt-redaction` | Secrets typed or pasted into a prompt are redacted before persistence; stable, idempotent placeholders | [prompt-redaction.md](prompt-redaction.md) | no (hooks only) |
| `tier-b-gate` | Entropy plus keyword secrets redact in prose and only warn in source | [tier-b-gate.md](tier-b-gate.md) | code half yes, prose half no |
| `system-prompt-redaction` | Secrets in the system prompt text parts are redacted every turn | [system-prompt-redaction.md](system-prompt-redaction.md) | no (hooks only) |
| `audit-log` | Metadata-only, mode 600 record of every finding, including observed tool input | [audit-log.md](audit-log.md) | partly |
