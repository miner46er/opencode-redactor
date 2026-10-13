# Tool output redaction

When a tool (shell, read, MCP) returns text containing a credential, the plugin rewrites every string in the result to a typed placeholder before the model reads it and before the session store persists it.

## Sub-features

- `tool-output-tier-a` replaces an anchored provider credential (`ghp_...`) in shell output with `[REDACTED:github-pat#1:<12 hex>]`.
- `tool-output-nested` rewrites strings nested anywhere in the result (`output`, `content[].text`, `metadata`), not only `output`, because the host persists `content`.
- `tool-output-failed` leaves a failed tool call untouched.

## How to get to it (user POV)

- Ask the agent to run `cat <file>` on a file that holds a credential.
- Any tool the agent calls that returns a credential (read, grep, MCP).

## Driving it with redactor-verify.sh

Preconditions:

- `$S doctor` is healthy and a fresh sandbox exists.
- `CANARY=ghp_$(head -c 200 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 36)`.

- **Real host.** Run `EV=$($S host tool-output-pat deploy.env "GITHUB_TOKEN=$CANARY"$'\n'"NAME=demo"$'\n' "Run the shell command: cat deploy.env . Then paste its full output verbatim in a code block. This is a throwaway test fixture with a fake token.")`. `$EV/run.jsonl` shows a tool part for `cat deploy.env` and the model's text contains `GITHUB_TOKEN=[REDACTED:github-pat#1:<12 hex>]`.
- **Nothing leaks.** `echo $CANARY > $EV/canary.txt`, then `grep -c "$CANARY" $EV/run.jsonl $EV/run.stderr` prints `0` for both and `grep -a -c "$CANARY" "$(cat /tmp/verify-redactor-current)"/data/opencode/opencode.db*` prints `0` (run before `cleanup`).
- **Audit.** `$EV/audit.log` contains `channel=tool-output action=redacted tier=A kind=github-pat fp=<12 hex>` and not the canary.
- **Model-free.** `$S hooks` prints `PASS  tool output: no raw credential anywhere in result` and `PASS  tool output: result.content rewritten (what the host persists)`, and `PASS  failed tool call: untouched`.

## Gotchas

- The raw spill file `$RUN/data/opencode/shell/<scope>/sh_*.out` contains the canary by design (README: the disk is not clean). Do not grep the whole data dir and call the hit a leak; scope the check to `opencode.db*` and the event stream.
- If the model refuses or never calls the tool, there is no tool part in `run.jsonl`: rerun with the neutral prompt above; do not count it as a pass.
- The audit log records one line per rewritten string, so the same finding appears twice when `output` and `content` both carry it.
- `opencode run` hangs without output unless stdin is `/dev/null`; the helper handles this.
