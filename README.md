<img src="assets/icon.svg" width="64" height="64" alt="">

# opencode-redactor

An OpenCode plugin that redacts credentials from your traffic before it reaches a model provider.

User input and tool output are scanned for API keys, tokens, private keys and
connection strings. Matches are replaced with stable typed placeholders. The
redacted text is what gets stored in session history, so scrolling back does
not reveal what was removed.

## Install

Copy `src/` into your project's `.opencode/plugins/` directory, or add this to
`opencode.json`:

```json
{ "plugin": ["opencode-redactor"] }
```

Requires OpenCode v2 (`@opencode/plugin` 2.0.27). v1 plugins do not run on v2
and this does not run on v1.

## What it does and does not protect you from

**Clean** means two different things and this plugin only guarantees one of them.

The **model boundary is clean.** Nothing the model can read contains a detected
credential. That covers user input, tool output, and the system prompt, and it
holds across the session store, the outgoing request, compaction, and subagents.

One field is deliberately not scanned: MCP tool descriptions. Rewriting a tool
description breaks the contract the model relies on to call it correctly, so a
secret pasted into an MCP server's description would still reach the provider.

The **disk is not clean.** OpenCode's `shell` tool writes full raw output to
`~/.local/share/opencode/shell/<scope>/sh_*.out` *before* any plugin hook runs.
For truncated output, session history contains a line pointing at that raw file.
This plugin does not rewrite those files. Doing so would mean writing to a path
this plugin does not own, keyed off a string inside data an MCP server may
partially control, which is a worse bug class than a plaintext file in a
user-private directory.

The session store itself is clean for anything the redactor sees, with one
host-side caveat below.

## Placeholders

```
[REDACTED:aws-access-key-id#1:3f2a9c1e7b04]
```

The same credential gets the same placeholder everywhere in a session, so the
model can still reason that two references point at one value. The trailing
fingerprint is an HMAC of the value under a random per-session key. It is
stable within a session and meaningless outside it, so an attacker reading your
session store cannot use it to confirm a guessed credential.

Redaction is idempotent. Applying it twice produces the same text as applying
it once, and a placeholder is never itself detected as a credential.

## Accuracy

Two tiers. **Tier A** is anchored provider formats (`AKIA...`, `ghp_...`, PEM
blocks). These redact unconditionally. **Tier B** is entropy plus a keyword, and
fires on unprefixed values: bare `.env` entries, quoted JSON or dict keys, and
`Authorization: Bearer`/`Basic` credentials. Tier B redacts in prose and
only warns in code, because source is high-entropy and a redactor that mangles a
minified bundle gets uninstalled.

Documented example keys (`AKIAIOSFODNN7EXAMPLE`, `sk_test_4eC39HqLyjWDarjtT1zdp7dc`)
are suppressed. So are UUIDs, git SHAs, hex digests, bcrypt hashes, SSH public
keys, bare base64 certificate bodies, plain URLs, variable references such as
`process.env.X`, and absolute file paths.

Pasted text and each tool output string are classified as code or prose on
their own. Config formats (`.env`, JSON, YAML) count as prose, because that is
where credentials live.

## What the model cannot do

Placeholders are dead. There is no vault and no restore path, so the model never
learns a credential's value. It cannot authenticate to anything, run a
credentialed request, or log in on your behalf. That is deliberate: the failure
mode being prevented is a credential leaving your machine inside a request the
model composed.

## Audit log

`~/.local/share/opencode/redactor-audit.log`, mode 600, one line per finding:

```
2026-01-01T00:00:00.000Z channel=prompt action=redacted tier=A kind=github-pat fp=3f2a9c1e7b04 offset=142
```

`channel` is `prompt`, `system`, `tool-output` or `tool-input`. `action` is
`redacted` when the text was changed, `warned` when a Tier B hit in source was
deliberately left alone, and `observed` when the text was scanned but not
modified.

Metadata only. Values are never written. Delete it freely.

## Known host behaviours

Mutating `tool.execute.after`'s `result.output` does **not** affect session
history. The host persists `state.content`, derived from `result.content`, and
the stored block has no `state.output` field. This plugin walks and rewrites the
entire result so that content is what changes.

Tool *input* is scanned and logged as `action=observed`, never rewritten, since
nothing on that path is changed.

A pasted file arriving as chat is classified before redaction, so the Tier B
gate applies to code in a prompt the same way it does in tool output.

A failed or slow scan fails open: the turn proceeds unscanned and a line goes to
stderr.

## License

MIT
