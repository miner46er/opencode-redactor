#!/usr/bin/env bash
# Drives opencode-redactor inside a throwaway OpenCode sandbox.
#
#   redactor-verify.sh new               create a sandbox, print its path (also saved as the "current" run)
#   redactor-verify.sh doctor            read-only: is the current sandbox worth driving?
#   redactor-verify.sh host <label> <file> <content> <prompt>   real OpenCode + real model (see `host` below)
#   redactor-verify.sh hooks             model-free: fire the real plugin's hooks with fake events
#   redactor-verify.sh cleanup           stop what the sandbox started, delete scratch, keep evidence
#
# Everything OpenCode touches (data, config, state, cache, HOME) lives under the
# sandbox, and every opencode call passes --standalone, so the user's own
# background service, sessions and audit log are never read or written.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
POINTER=/tmp/verify-redactor-current
EVIDENCE_ROOT=/tmp/opencode-redactor-evidence
MODEL="${REDACTOR_VERIFY_MODEL:-opencode-go/deepseek-v4.1-flash#low}"

die() { echo "error: $*" >&2; exit 1; }

current() {
  [[ -f "$POINTER" ]] || die "no current run; run: $0 new"
  RUN="$(cat "$POINTER")"
  [[ -d "$RUN" ]] || die "current run $RUN is gone; run: $0 new"
  EVID="$EVIDENCE_ROOT/$(basename "$RUN")"
  mkdir -p "$EVID"
}

# Environment that confines OpenCode (and the plugin's homedir()) to the sandbox.
sandbox_env() {
  export HOME="$RUN/home" XDG_DATA_HOME="$RUN/data" XDG_CONFIG_HOME="$RUN/config" \
         XDG_STATE_HOME="$RUN/state" XDG_CACHE_HOME="$RUN/cache"
}

cmd_new() {
  command -v opencode >/dev/null || die "opencode not on PATH"
  command -v bun >/dev/null || die "bun not on PATH"
  local run; run="$(mktemp -d /tmp/verify-redactor.XXXXXX)"
  mkdir -p "$run"/{home,data,config,state,cache,proj/.opencode/plugins}
  # The plugin hardcodes ~/.local/share/opencode/redactor-audit.log and does not
  # create the directory. A real install always has it; the sandbox must too, or
  # every audit write fails silently on a stderr nobody sees.
  mkdir -p "$run/home/.local/share/opencode"
  # Link (not copy) the runtime files so the sandbox always runs the working tree.
  # OpenCode loads EVERY file in the directory as a plugin, so tests and the
  # fixture corpus are left out; they only add load-error noise.
  local f
  for f in "$REPO"/src/*.ts; do
    case "$f" in *.test.ts|*/corpus.ts) ;; *) ln -s "$f" "$run/proj/.opencode/plugins/" ;; esac
  done
  # Credentials: copied once, from the user's own store into a 0600 file that
  # lives only in the sandbox and is deleted by cleanup. Never printed.
  ( umask 077; opencode auth export > "$run/auth.json" 2>/dev/null ) || die "opencode auth export failed"
  echo "$run" > "$POINTER"
  RUN="$run"; sandbox_env
  ( cd "$run/proj" && opencode auth import --standalone "$run/auth.json" >/dev/null ) || die "auth import failed"
  echo "$run"
}

cmd_doctor() {
  current; sandbox_env
  local bad=0
  ck() { if eval "$2" >/dev/null 2>&1; then echo "ok    $1"; else echo "FAIL  $1"; bad=1; fi; }
  echo "run:      $RUN"
  echo "evidence: $EVID"
  echo "opencode: $(opencode --version 2>&1 | head -1)   (README requires v2.0.27)"
  ck "opencode is v2.x" "opencode --version | grep -q '^opencode v2\.'"
  ck "XDG data dir is inside sandbox" "(cd '$RUN/proj' && opencode debug paths | grep -q \"data .*$RUN\")"
  ck "plugin runtime files linked" "test -L '$RUN/proj/.opencode/plugins/plugin.ts'"
  ck "linked files point at this repo" "test \"\$(readlink -f '$RUN/proj/.opencode/plugins/plugin.ts')\" = '$REPO/src/plugin.ts'"
  ck "no test/corpus files in plugin dir" "! ls '$RUN/proj/.opencode/plugins' | grep -E 'test|corpus'"
  ck "credentials imported" "(cd '$RUN/proj' && opencode auth list --standalone | grep -q stored)"
  ck "audit dir exists in sandbox HOME" "test -d '$RUN/home/.local/share/opencode'"
  ck "unit tests pass (bun test)" "(cd '$REPO' && bun test)"
  local mine; mine="$(sandbox_pids | wc -l)"
  echo "info  sandbox-owned processes running: $mine"
  [[ $bad -eq 0 ]] || { echo "doctor: NOT healthy"; exit 1; }
  echo "doctor: healthy"
}

# PIDs whose working directory is inside the sandbox. We kill exactly these and
# nothing else, never by process name.
sandbox_pids() {
  local p cwd
  for p in /proc/[0-9]*; do
    cwd="$(readlink "$p/cwd" 2>/dev/null || true)"
    case "$cwd" in "$RUN"|"$RUN"/*) echo "${p#/proc/}" ;; esac
  done
}

# host <label> <file-name> <file-content> <prompt>
# Writes <file-content> to proj/<file-name>, asks the real model (through real
# OpenCode with the plugin loaded) to run `cat <file-name>` and quote it back,
# and saves the raw event stream. Evidence lands in $EVID/<label>/.
cmd_host() {
  current; sandbox_env
  local label="$1" name="$2" content="$3" prompt="$4" out
  out="$EVID/$label"; mkdir -p "$out"
  # Each host run gets its own audit evidence, not the hooks run's records.
  rm -f "$RUN/home/.local/share/opencode/redactor-audit.log"
  printf '%s' "$content" > "$RUN/proj/$name"
  printf '%s' "$content" > "$out/input-file.txt"
  # --print-logs puts the plugin's "[redactor] active" stderr line and plugin load
  # errors in run.stderr. stdin MUST be /dev/null: with an open pipe on stdin,
  # `opencode run` starts its server and then waits forever with no output. One
  # retry on an empty stream; a second empty stream is a real failure.
  local attempt
  for attempt in 1 2; do
    ( cd "$RUN/proj" && timeout 150 opencode run --standalone --auto --print-logs --format json \
        -m "$MODEL" "$prompt" < /dev/null ) > "$out/run.jsonl" 2> "$out/run.stderr" || true
    [[ -s "$out/run.jsonl" ]] && break
    echo "warn: attempt $attempt produced no output; retrying" >&2
  done
  [[ -s "$out/run.jsonl" ]] || die "opencode run produced no output twice (see $out/run.stderr)"
  cp -f "$RUN/home/.local/share/opencode/redactor-audit.log" "$out/audit.log" 2>/dev/null || : > "$out/audit.log"
  echo "$out"
}

cmd_hooks() {
  current
  sandbox_env
  ( cd "$REPO" && bun run "$REPO/.claude/skills/verify-opencode-redactor/scripts/drive-hooks.ts" "$RUN" "$EVID" )
}

cmd_cleanup() {
  current
  local p
  for p in $(sandbox_pids); do kill "$p" 2>/dev/null || true; done
  sleep 1
  for p in $(sandbox_pids); do kill -9 "$p" 2>/dev/null || true; done
  rm -rf "$RUN"
  rm -f "$POINTER"
  echo "removed sandbox $RUN; evidence kept at $EVID"
}

case "${1:-}" in
  new) cmd_new ;;
  doctor) cmd_doctor ;;
  host) shift; cmd_host "$@" ;;
  hooks) cmd_hooks ;;
  cleanup) cmd_cleanup ;;
  *) sed -n '2,12p' "$0"; exit 2 ;;
esac
