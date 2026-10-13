# AGENTS.md

## What this is

An OpenCode v2 plugin that redacts credentials before they reach a model provider. The SDK peer dependency is pinned exactly to `@opencode/plugin` 2.0.27; host behaviours the code relies on were verified against that version only, so re-verify after any upgrade. No npm dependencies, by design (spec 27) — do not add any. Bun is the runtime and test runner.

## Commands

- `bun test` — everything; fast (~30 ms), no services, no network
- `bun test src/rules.test.ts` — one file; `bun test -t "<test name>"` — one test
- `bun run typecheck` — `tsc --noEmit` under `strict` + `noUncheckedIndexedAccess` + `exactOptionalPropertyTypes`; optional-field handling is where it bites

## Wiring

- `src/plugin.ts` is the host entrypoint (package `main`). It registers four hooks: `prompt` (user input), `context` (system prompt text parts only), `tool.execute.before` (observe only), `tool.execute.after` (tool output).
- `shape.ts` is the pinned data shape every module speaks in; `rules.ts` holds the detectors, denylist and prose/code classification; `redact.ts` resolves overlaps and applies replacements; `session.ts` holds per-conversation placeholder scopes.
- Only five files are runtime: `plugin.ts`, `redact.ts`, `rules.ts`, `session.ts`, `shape.ts`. `corpus.ts` and the `*.test.ts` files are not plugins — the host loads every file in `.opencode/plugins/` as one.

## The corpus is the spec

- `src/corpus.ts` is a written specification, not test data: fixtures are added before the detector exists and fail first (spec 24).
- `corpus.test.ts` pins exact fixture counts for both lists; adding or removing a fixture means deliberately updating those numbers, never absorbing the failure.
- A secret fixture's value must appear verbatim in its context; benign fixtures each carry a reason; labels are unique across both lists.
- A finding must cover the whole value. A partially redacted credential is worse than a missed one (spec 19).

## Adding or changing a detector

- A new provider is a new entry in `DETECTORS` in `rules.ts`, never a new branch anywhere else.
- Patterns use the `d` flag; when a rule captures, group 1 is the secret and the rest of the match is context.
- Tier A is anchored and redacts unconditionally, and must not set `entropy`. Tier B is keyword-plus-entropy, requires `entropy`, and redacts in prose but only warns in code. `appliesHere` is the single gate — never re-implement it.
- A fixed-length rule must end in a lookahead covering at least the charset of the run it bounds, or an over-long value prefix-matches and leaves its tail behind. The corpus tests append tails to every Tier A fixture to keep this true.
- Non-secret shapes go in `DENYLIST`. Suppression of documented example keys is by exact value, never by prefix — Stripe test keys authenticate against the real API.
- `PLACEHOLDER_SENTINEL` is reserved; `detect()` drops any match containing it, which is what keeps redaction idempotent.

## Safety rules that are easy to violate

- Never persist or log `Finding.value`. Only `redact()` output carries a real fingerprint; `detect()` deliberately leaves it unset so a caller cannot log what it must not.
- Never rewrite tool input (`execute.before` records `observed` only) and never edit `tools` in the system prompt. Both are settled decisions (spec 8, 9), not gaps.
- The host persists `state.content`, derived from `result.content` — that is why `walkStrings` rewrites the whole result in place. Mutating `result.output` alone leaves raw values in session history.
- Raw shell spill files under `~/.local/share/opencode/shell/` contain credentials by design; do not "fix" the disk (spec 28).

## Verifying the plugin wiring

Unit tests cover the detectors and the redaction core; they do not prove the plugin wired into a host. After changing anything in `src/`, drive the plugin through the skill at `.claude/skills/verify-opencode-redactor/`:

- `S=.claude/skills/verify-opencode-redactor/scripts/redactor-verify.sh`, then `$S new`, `$S doctor`, `$S hooks` (model-free, ~1 s), `$S host <label> <file> <content> <prompt>` (real host + model), `$S cleanup`.
- Never run bare `opencode ...` from this repo — it talks to the user's real background service on port 49374; every call needs `--standalone` and stdin from `/dev/null` (the script handles both).
- Do not drive the hooks by hand outside that sandbox: the plugin writes its audit log to your real `~/.local/share/opencode/`, and it does not create the directory.

## Docs conventions

Behavior changes ship with the doc changes in the same commit, and the commit message explains the failure mode being fixed. `docs/spec.md` items are numbered for citation — amend in place, never renumber. `GLOSSARY.md` is the domain vocabulary; use its terms. `README.md` states the guarantees and the known boundaries; keep it truthful when behaviour changes.
