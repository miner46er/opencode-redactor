# opencode-redactor MVP spec

Derived from the design interview. Each item is a decision that was settled,
not an aspiration. Numbered for citation during review.

## Purpose

1. Redact credentials from OpenCode traffic before it reaches a model provider.
2. The redacted form is what is persisted, so scrolling back does not reveal
   what was removed.

## Threat model

3. The harm being prevented is a developer accidentally disclosing their own
   credential to a provider they already trust with their code, plus defense in
   depth. Not a hostile MCP server, not a compliance mandate.
4. Consequently an agent that cannot authenticate is acceptable. It cannot leak
   a credential through an authenticated request, which is the failure mode
   that actually burns people.

## Surfaces

5. Human-authored text is rewritten. Model-produced text is observed only.
6. User input is redacted before persistence.
7. Tool output is redacted before persistence.
8. Tool input is scanned and logged but NEVER rewritten. A secret there came
   from the model hallucinating one or from the user issuing a command
   deliberately, and rewriting either silently corrupts an intentional command.
9. System prompt is redacted. MCP tool descriptions are out of scope, because
   rewriting them breaks a contract with the model.

## Detection

10. Credentials only. No PII. PII detection has far worse precision and mangles
    source and prose constantly.
11. Tier A is anchored provider formats. These redact unconditionally.
12. Tier B is entropy plus keyword. Tier B redacts in prose and only WARNS in
    code, because source is high-entropy and a redactor that mangles a minified
    bundle gets uninstalled.
13. Suppression of documented examples is by EXACT VALUE, never by prefix.
    Stripe test keys authenticate against a real API, so a prefix rule would
    silently miss every one of them.
14. Non-secret shapes produce zero findings: UUIDs, git SHAs, hex digests,
    bcrypt hashes, SSH public keys, bare base64 certificate bodies, and
    semi-public identifiers such as Twilio Account SIDs.

## Placeholders and identity

15. Placeholders are dead. No vault, no restore path. The model never learns a
    value.
16. The same credential gets the same placeholder everywhere in a session, so
    the model can reason that two references are one value.
17. The fingerprint is a per-session HMAC under a random key, truncated to 12
    hex chars. Stable within a session, meaningless across sessions, so an
    attacker reading the session store cannot confirm a guessed credential.
18. Redaction is idempotent. Applying it twice equals applying it once. A
    placeholder is never itself detected.
19. A partially redacted credential is worse than a missed one, because it looks
    handled while a fragment survives. Over-long values are rejected outright
    rather than matched on a prefix.

## Failure posture

20. Fail open but loud. A scanner error lets the turn proceed unscanned and
    writes to stderr. Only a positive detection blocks.
21. Findings are always visible to the user. Never persist values. Audit records
    carry kind, surface, offset, fingerprint, and action only.

## Accuracy bar

22. Zero false positives on a corpus of realistic non-secrets.
23. 100 percent recall on anchored Tier A formats.
24. The corpus is written BEFORE the detector, so tests are a specification
    rather than a description of whatever the code happens to do.

## Delivery

25. OpenCode v2 only, SDK `@opencode/plugin` 2.0.27.
26. Single canonical redaction layer. A full-conversation backstop hook is
    opt-in debug only.
27. One dependency-free file set, shipped by copying into
    `.opencode/plugins/`.

## Known boundaries, documented not hidden

28. The model boundary is clean. The DISK is not. OpenCode's `shell` tool
    writes raw output to `~/.local/share/opencode/shell/` before any plugin
    hook runs. Redacting those files would mean writing to a path the plugin
    does not own, keyed off string content an MCP server may control.
29. Mutating `tool.execute.after`'s `result.output` does not affect persisted
    history. The host persists `state.content`, derived from `result.content`,
    and the stored block has no `state.output` field.
