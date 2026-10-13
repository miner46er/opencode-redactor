# Redaction

The domain of preventing machine credentials from reaching a language model. This context exists because the words people use for this work are consistently overloaded, and the overload causes real design errors.

## Language

**Surface**:
A channel through which text can enter or leave the agent's context. The code
type and the audit log call it a Channel: `prompt`, `system`, `tool-output`,
`tool-input`.
_Avoid_: input, source, stream

**Finding**:
A span of text a Detector classified as a credential, carrying a kind, a location, and a Fingerprint. A Finding is not the same as a secret. A false positive is still a Finding.
_Avoid_: match, hit, detection, secret

**Fingerprint**:
A stable identifier for one distinct credential value, used to give the same Placeholder to every occurrence of that value. Stable across turns within a session and never derived from an upstream engine's own identifier.
_Avoid_: id, hash, digest, key

**Detector**:
A rule or model that produces Findings from raw text.
_Avoid_: scanner, engine, filter, parser

**Redactor**:
The component that turns raw text into redacted text by applying Detectors.
_Avoid_: filter, scrubber, sanitizer

**Redaction**:
The replacement of a Finding's span with a Placeholder, applied to a Surface.
_Avoid_: masking, scrubbing, sanitizing, filtering, cleaning

**Placeholder**:
The text that substitutes for a redacted span. In this design a Placeholder is dead, meaning no recoverable value exists behind it anywhere.
_Avoid_: token, marker, stub, alias

**Pass**:
One agent turn's data as it crosses every Surface.
_Avoid_: turn, request, message, batch

**Provenance**:
Whether a span of text is on its way to the model or was produced by it. Text given to the model is rewritten; tool input, which the model writes, is only observed, and the model's replies are never scanned.
_Avoid_: source, origin, direction

**Backstop**:
A re-scan of text that the canonical redaction layer has already passed, run as a safety net when the primary layer missed or failed.
_Avoid_: fallback, secondary check, defense

**Clean**:
The state of a Surface, meaning nothing readable by the model. The state of the disk, meaning nothing readable by anyone. A redaction can be Clean in the first sense and not the second.
_Avoid_: safe, secure, sanitized, protected
