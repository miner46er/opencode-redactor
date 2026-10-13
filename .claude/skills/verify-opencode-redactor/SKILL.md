---
name: verify-opencode-redactor
description: Prove opencode-redactor works by driving it for real, either through a real OpenCode v2 session with the plugin loaded or by firing the plugin's hooks directly. Use after changing anything in src/ (detectors, redact, session, plugin hooks) or when asked whether a secret still leaks to the model, the session store, or the audit log.
---

# Verify opencode-redactor

opencode-redactor is an OpenCode v2 plugin (no UI, no server of its own). A user
"touches" it by typing a prompt or running a tool inside OpenCode and expecting
credentials to be replaced by `[REDACTED:<kind>#<n>:<12 hex>]` before the model, the
session store and the outgoing request see them, with a metadata-only audit line
written to `~/.local/share/opencode/redactor-audit.log`.

Two ways to drive it, both through one script. Read `features/README.md` first, then the
feature file for what you changed.

| Drive | What is real | What is faked | Needs credentials / network | Use for |
|---|---|---|---|---|
| `hooks` | the whole plugin and detectors | the OpenCode host (`ctx`, events) | no | every change; fast; covers all four channels |
| `host` | OpenCode 2.0.27, plugin loading, tool execution, session store, a real model | nothing | yes (your OpenCode login, copied into the sandbox) | proof that the host persists the redacted form |

`bun test` (353 tests) covers detector accuracy. This skill proves the *plugin wired into
a host*, which unit tests do not.

## Launch

```bash
S=.claude/skills/verify-opencode-redactor/scripts/redactor-verify.sh
$S new        # creates /tmp/verify-redactor.XXXXXX, prints it, remembers it as the current run
```

`new` builds the sandbox, with no server to wait for:

- `home/ data/ config/ state/ cache/` and `proj/` under the sandbox. `$HOME` and every `XDG_*_HOME`
  are pointed at them, so OpenCode's database, shell spill files and the plugin's audit
  log (`homedir()`) all land there, not in your real `~/.local/share/opencode`.
- `proj/.opencode/plugins/*.ts` are **symlinks** to this repo's runtime files, so the sandbox always runs
  the working tree. Tests and `corpus.ts` are deliberately left out: OpenCode loads *every* file in that directory as
  a plugin, and the non-plugin ones only produce `failed to load plugin` warnings.
- Your credentials are exported (`opencode auth export`) into `auth.json` (mode 600, sandbox only) and
  imported with `--standalone`. They are never printed. `cleanup` deletes them.

Every `opencode` call uses `--standalone` (private server). Never run a bare `opencode run|auth|plugin ...`
from here: it would talk to your real background service on port 49374.

There is no readiness probe beyond `doctor`; each `host` drive starts and stops its own private server.

## Doctor

```bash
$S doctor
```

Read-only. Checks opencode is v2.x, the sandbox owns the data dir, the plugin files are linked to *this*
repo, no test/corpus files sit in the plugin dir, credentials imported, the audit dir exists, and `bun test`
passes. Run it first, and again whenever a drive behaves oddly. It prints `doctor: healthy` or exits 1.

## Drive

**hooks** (model-free, ~1s):

```bash
$S hooks
```

Loads `src/plugin.ts`, lets it register against a stand-in `ctx`, fires `session.prompt`,
`session.context`, `tool.execute.before`, `tool.execute.after`, and prints PASS/FAIL lines with
fresh random canaries (a `ghp_`+36 alnum PAT, and a 32-char `DATABASE_PASSWORD`). It refuses to run if
`homedir()` is not the sandbox, so it cannot write your real audit log. Exit 1 on any FAIL.

**host** (real OpenCode, real model, ~10s):

```bash
CANARY=ghp_$(head -c 200 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 36)
EV=$($S host <label> <file-name> "<file-content>" "<prompt>")
```

Writes `<file-content>` to `proj/<file-name>`, runs `opencode run --standalone --auto --format json
--print-logs -m opencode-go/deepseek-v4.1-flash#low "<prompt>" </dev/null`, and saves
`run.jsonl` (event stream), `run.stderr` (host + plugin logs), `audit.log` (this run only) and
`input-file.txt` under `$EV`. Override the model with `REDACTOR_VERIFY_MODEL`. Recipes with real
prompts and assertions are in `features/*.md`.

Hard-won handling rules:

- **stdin must be `/dev/null`.** With an open pipe on stdin, `opencode run` starts its server and then hangs
  forever with no output. The helper does this; do the same for any direct call.
- **Use fake canaries and a neutral prompt.** A prompt like "quote the GITHUB_TOKEN back to me exactly" makes
  the model refuse before it ever calls the tool. Ask it to `cat` the file and paste the output in a code block.
- The model may still refuse or skip the tool call. If `run.jsonl` has no tool part, that run proves nothing:
  rerun, do not count it as a pass.
- The audit log is shared by everything in a sandbox. `host` deletes it first so its evidence is its own;
  `hooks` appends to whatever is there.

## Evidence

Proof is saved to `/tmp/opencode-redactor-evidence/<run-id>/<label>/` (named by `host`/`hooks`, outside the
sandbox so cleanup cannot delete it). A host proof is only complete with all of:

1. **The action:** `input-file.txt` (the raw canary) and the prompt you sent.
2. **Nothing leaks:** `grep -c "$CANARY" $EV/run.jsonl $EV/run.stderr` is `0`, and the same for the session store:
   `grep -a -c "$CANARY" $RUN/data/opencode/opencode.db*` is `0` (check before `cleanup`, or `sqlite3` it).
3. **It was replaced, not dropped:** `grep -o 'REDACTED:<kind>#1:[0-9a-f]*' $EV/run.jsonl` finds a placeholder.
4. **The side effect:** `$EV/audit.log` has a line with the right `channel`, `action`, `tier`, `kind`, and no value.
5. **Plugin was loaded:** `run.stderr` contains `[redactor] active on 2.0.27`. Without it a clean stream proves nothing.

Standards: drive the real user path (prompt typed to `opencode run`, tool executed by the host), not the
plugin's internals, except in the explicitly model-free `hooks` drive. Use only fabricated credentials.
Check what is *not* redacted as well: the raw `data/opencode/shell/**/sh_*.out` file **does** contain the canary by
design (README: "the disk is not clean"). Do not report that as a leak; do report it if it ever *stops* being so
without a README change.

## Cleanup

```bash
$S cleanup
```

Kills only processes whose working directory is inside the sandbox (never by name; your own
`opencode serve --service` is untouched), deletes the sandbox including `auth.json`, and removes the
pointer file. The evidence directory is kept; its path is printed. If a run died halfway, run `cleanup`
before `new`; it is safe to repeat.

## Known gaps found while building this skill

The earlier "warn-only findings are never audited" gap is fixed; `hooks` now ALL PASS. The README install
also names the five runtime files to copy, so following it no longer puts tests and `corpus.ts` in the
plugins directory. Still open:

- Audit log directory (now documented in the README's "Audit log" section): the plugin writes to
  `homedir()/.local/share/opencode/` without creating it, and ignores `XDG_DATA_HOME`. `new` creates the
  directory; a user with a custom `XDG_DATA_HOME` and no `~/.local/share/opencode` would silently get no
  audit log (only a stderr line the host hides).
