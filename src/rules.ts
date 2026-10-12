// Adding a provider is a new array entry, never a new branch.
import type { Detector, Finding, TextClass, Tier } from "./shape"

/**
 * Placeholders are built from this prefix. It is reserved: `#` and `:` are in
 * no provider charset, and a Tier B value run needs 16+ unbroken value chars,
 * so nothing inside a placeholder can satisfy a pattern. detect() also drops
 * any candidate whose match contains the sentinel, which is what makes
 * redaction idempotent even if a future pattern is widened too far.
 */
export const PLACEHOLDER_SENTINEL = "[REDACTED:"

/** gitleaks' default entropy floor for keyword-plus-entropy rules. */
const DEFAULT_ENTROPY_FLOOR = 3.5

/** Shortest value a Tier B rule may report; below this every token looks random. */
const MIN_TIER_B_VALUE_LENGTH = 16

/** A non-secret shape that must produce zero findings, and why. */
export interface DenyEntry {
  readonly reason: string
  readonly pattern: RegExp
}

/**
 * False-positive classes that make naive redactors unusable. These run against
 * each candidate's value regardless of detector, before entropy is considered.
 *
 * Suppression is by exact value wherever a shape is genuinely ambiguous, never
 * by prefix. Stripe test keys are the case that proves why: `sk_test_` is a real
 * credential against a real API, so a prefix rule would silently miss every one
 * of them, while only Stripe's published documentation placeholder is safe to
 * drop.
 */
export const DENYLIST: readonly DenyEntry[] = [
  {
    reason: "AWS's canonical example key is documentation, not a credential",
    pattern: /^AKIAIOSFODNN7EXAMPLE$/,
  },
  {
    reason: "AWS's canonical example secret, paired with the example key id above",
    pattern: /^wJalrXUtnFEMI\/K7MDENG\/bPxRfiCYEXAMPLEKEY$/,
  },
  {
    reason: "Stripe's published documentation placeholder, not a prefix-wide rule",
    pattern: /^sk_test_4eC39HqLyjWDarjtT1zdp7dc$/,
  },
  {
    reason: "jwt.io's default sample token, reproduced verbatim across thousands of tutorials",
    pattern:
      /^eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ\.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c$/,
  },
  {
    reason: "a UUID is an identifier, not a secret",
    pattern: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  },
  {
    reason: "40 lowercase hex chars are a git SHA or a digest, not a secret",
    pattern: /^[0-9a-f]{40}$/,
  },
  {
    reason: "64 lowercase hex chars are a digest, not a secret",
    pattern: /^[0-9a-f]{64}$/,
  },
  {
    reason: "a bcrypt hash is a stored verifier, not a replayable credential",
    pattern: /^\$2[aby]\$/,
  },
  {
    reason: "an SSH public key is public by definition",
    pattern:
      /^(?:ssh-rsa|ssh-ed25519|ecdsa-sha2-[a-z0-9-]+|ssh-dss)[ \t]|^AAAAB3NzaC1yc2E|^AAAAC3NzaC1lZDI1NTE5/,
  },
  {
    // Only URLs with no userinfo and no query: a password in userinfo is the
    // connection-string rule's job, and a query may carry a token of its own.
    reason: "a URL with no userinfo or query is an address, not a secret",
    pattern: /^[a-z][a-z0-9+.-]*:\/\/[^\s@?#]*$/i,
  },
  {
    // The lowercase head is what separates `process.env.X` from dotted
    // provider formats: a JWT starts "eyJ" and a SendGrid key starts "SG.".
    // A password shaped like this is missed rather than partly redacted,
    // which spec 19 ranks as the lesser harm.
    reason: "a dotted identifier is a reference to where a secret lives, such as process.env.X",
    pattern: /^[a-z_$][a-z0-9_$]*(?:\.[A-Za-z_$][\w$]*)+$/,
  },
  {
    // Anchored on a real root so a base64 secret that happens to start with "/"
    // is not mistaken for a path.
    reason: "an absolute filesystem path points at where a secret is stored",
    pattern: /^(?:\/(?:home|Users|etc|usr|var|run|opt|tmp|srv|mnt|root|private)|~)\/[\w.\/-]*$/,
  },
  {
    reason: "a certificate body (MII-prefixed DER) is public material",
    pattern: /^MII[A-Za-z0-9+/]{30,}={0,2}$/,
  },
]

/**
 * Provider-format rules first (Tier A, precision-first, high confidence), then
 * the keyword+entropy rule for unprefixed values (Tier B). Patterns use the
 * `d` flag so a capture group's offset is exact; the captured group is the
 * secret a placeholder replaces, the rest of the match is context.
 */
export const DETECTORS: readonly Detector[] = [
  {
    kind: "aws-access-key-id",
    tier: "A",
    pattern: /\b(?:A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}(?![A-Z0-9])/gd,
  },
  {
    kind: "aws-secret-access-key",
    tier: "A",
    // Not anchored to 40 chars: real AWS secrets vary in length, and a fixed
    // width leaves the tail of a longer secret exposed as a short unflagged run.
    pattern: /\baws[._ -]*(?:secret[._ -]*)?(?:access[._ -]*)?key[._ -]*[:=][._ -]*['"]?([A-Za-z0-9/+=]{40,})['"]?/gid,
  },
  {
    kind: "github-pat",
    tier: "A",
    pattern: /\bgh[pousr]_[A-Za-z0-9]{36}(?![A-Za-z0-9])/gd,
  },
  {
    kind: "slack-token",
    tier: "A",
    // \b cannot be the terminator here: it treats "-" as a boundary, so a
    // token with more hyphen groups than the pattern allows would match on a
    // prefix and leave the tail behind.
    pattern: /\bxox[bp]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9-])/gd,
  },
  {
    kind: "stripe-live-key",
    tier: "A",
    // "_" is in the negated class too: it is a word character, so \b would stop
    // at it and leave the rest of the key exposed.
    pattern: /\b(?:sk|rk)_live_[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])/gd,
  },
  {
    kind: "google-api-key",
    tier: "A",
    pattern: /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/gd,
  },
  {
    kind: "openai-api-key",
    tier: "A",
    pattern: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/gd,
  },
  {
    kind: "anthropic-api-key",
    tier: "A",
    pattern: /\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/gd,
  },
  {
    kind: "gitlab-pat",
    tier: "A",
    pattern: /\bglpat-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/gd,
  },
  {
    kind: "npm-token",
    tier: "A",
    pattern: /\bnpm_[A-Za-z0-9]{36}(?![A-Za-z0-9])/gd,
  },
  {
    kind: "sendgrid-api-key",
    tier: "A",
    pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/gd,
  },
  {
    // Only the SK auth token. An AC-prefixed Account SID is a semi-public
    // identifier that appears in every webhook config and support URL, so
    // treating it as a credential would fire on ordinary Twilio usage.
    kind: "twilio-api-key",
    tier: "A",
    pattern: /\bSK[0-9a-f]{32}(?![0-9a-fA-F])/gd,
  },
  {
    // Test-mode keys authenticate against Stripe's real API, so they redact.
    // Tier B because a bare `sk_test_` with no surrounding assignment is
    // weaker evidence than a live key in an explicit credential context.
    kind: "stripe-test-key",
    tier: "B",
    pattern: /\bsk_test_[A-Za-z0-9]{16,}(?![A-Za-z0-9])/gd,
  },
  {
    kind: "pem-private-key",
    tier: "A",
    pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/gd,
  },
  {
    kind: "jwt",
    tier: "A",
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_-])/gd,
  },
  {
    kind: "connection-string-password",
    tier: "A",
    // The password runs to the LAST "@" before the path. An unencoded "@" in a
    // password is common in practice, and stopping at the first one would
    // redact a prefix and leave the rest in the output.
    pattern: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|ftps?|smtps?|https?):\/\/[^\s:/@]{1,64}:([^\s/"'`<>]{3,128})@/gid,
  },
  {
    // The netrc grammar is the anchor: a password token only counts after a
    // machine (or default) entry, so ordinary prose about passwords never matches.
    kind: "netrc-password",
    tier: "A",
    pattern: /\b(?:machine\s+\S+|default)(?:\s+(?:login|account)\s+\S+)*\s+password\s+(\S+)/gd,
  },
  {
    kind: "generic-secret",
    tier: "B",
    entropy: DEFAULT_ENTROPY_FLOOR,
    // The key may be quoted (JSON, Python dicts) and the operator may be Go's
    // ":=" or Ruby's "=>". An unquoted value runs to whitespace or a shell
    // metacharacter, since a shell could not have read it past one; only a
    // trailing code delimiter is dropped, and it may not open with "[" so an
    // emitted placeholder can never be a value. Stopping at the first punctuation
    // instead would redact a prefix and leave the rest of the password behind.
    pattern:
      /\b[A-Za-z0-9_-]{0,40}(?:key|secret|token|password|passwd|credential)[A-Za-z0-9_-]{0,40}["']?[ \t]*(?::=|=>|[:=])[ \t]*(?:"([^"\s]{16,})"|'([^'\s]{16,})'|([^\s"'`;&|<>[][^\s"'`;&|<>]{14,}[^\s"'`;&|<>,)\]}]))/gid,
  },
  {
    // An Authorization scheme followed by its credential. Opaque bearer tokens
    // have no provider prefix, so this is entropy evidence like generic-secret.
    kind: "authorization-header",
    tier: "B",
    entropy: DEFAULT_ENTROPY_FLOOR,
    pattern: /\b(?:Bearer|Basic)[ \t]+([A-Za-z0-9._~+/-]{16,}=*)(?![A-Za-z0-9._~+/=-])/gid,
  },
]

/** Shannon entropy of a string in bits per character. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0
  const counts = new Map<string, number>()
  for (const char of s) counts.set(char, (counts.get(char) ?? 0) + 1)
  let entropy = 0
  for (const count of counts.values()) {
    const p = count / s.length
    entropy -= p * Math.log2(p)
  }
  return entropy
}

interface ValueSpan {
  readonly value: string
  readonly start: number
  readonly end: number
}

/** The captured group is the secret when a pattern captures; otherwise the whole match. */
function secretSpan(match: RegExpMatchArray): ValueSpan | null {
  const indices = match.indices
  if (indices && match.length > 1) {
    for (let group = 1; group < match.length; group++) {
      const span = indices[group]
      if (span) return { value: match[group] ?? "", start: span[0], end: span[1] }
    }
    return null
  }
  const start = match.index ?? 0
  return { value: match[0], start, end: start + match[0].length }
}

function passesTierBGate(value: string, floor: number): boolean {
  if (value.length < MIN_TIER_B_VALUE_LENGTH) return false
  if (/\s/.test(value)) return false
  return shannonEntropy(value) >= floor
}

function isDenied(value: string): boolean {
  return DENYLIST.some((entry) => entry.pattern.test(value))
}

/**
 * Returns spans only. It has no session, so it cannot fingerprint a value, and
 * it deliberately leaves `fingerprint` unset rather than stamping a provisional
 * one that a caller might persist. Only redact() output is safe to log.
 */

/**
 * The Tier B gate, in one place so it cannot drift: detect() skips a Tier B
 * rule on code, and redact() files that same case under `warned` rather than
 * `redacted`.
 *
 * Tier A is an anchored provider format and redacts everywhere. Tier B is
 * keyword-plus-entropy evidence: a credential in prose, but in source it is
 * usually a hash or an asset, so it is reported and left alone.
 */
export function appliesHere(tier: Tier, surface: TextClass): boolean {
  return tier === "A" || surface === "prose"
}

/**
 * A line that only source would contain. Config formats (.env, JSON, YAML) are
 * deliberately not code: they are where credentials live, and calling them code
 * would downgrade every Tier B hit in them to a warning. That is also why "#"
 * comments, braces on their own, and `export NAME=` shell lines do not count.
 */
const CODE_LINE =
  /=>|\bfunction\b|^\s*(?:const|let|var|import|from|def|class|fn|func|package|return|#include)\b|^\s*export\s+(?:default|const|let|var|function|class|async|type|interface|enum)\b|^\s*export\s*[{*]|^\s*(?:\/\/|\/\*)|^\s*\.\w+\(|;\s*$|\)\s*\{\s*$|<\/?[a-z][a-z0-9-]*[\s>/]/

/** `cat -n` and editor-style gutters, which would hide a line's first token. */
const LINE_NUMBER_GUTTER = /^\s*\d+(?:\t|\s*[|:]\s?)/

/**
 * Classifies text by the share of its non-blank lines that only source would
 * contain. Must be given the text itself: a JSON-encoded string is one line, so
 * any single code token anywhere in it would decide the whole class.
 */
export function textClassOf(text: string): TextClass {
  const lines = text
    .split("\n", 40)
    .map((line) => line.replace(LINE_NUMBER_GUTTER, ""))
    .filter((line) => line.trim().length > 0)
  if (lines.length === 0) return "prose"
  const code = lines.filter((line) => CODE_LINE.test(line)).length
  return code / lines.length > 0.3 ? "code" : "prose"
}

/**
 * Document order, then longest span first, then kind for a stable tie-break.
 * redact() re-sorts by overlap precedence, so this ordering only has to be
 * deterministic, not meaningful.
 */
export function byPosition(a: Finding, b: Finding): number {
  return a.start - b.start || b.end - a.end || compareKind(a, b)
}

/** Alphabetical, so two findings at the same span never sort unstably. */
export function compareKind(a: Finding, b: Finding): number {
  return a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0
}

export function detect(text: string, surface: TextClass): Finding[] {
  const findings: Finding[] = []
  for (const detector of DETECTORS) {
    if (!appliesHere(detector.tier, surface)) continue
    for (const match of text.matchAll(detector.pattern)) {
      const span = secretSpan(match)
      if (!span) continue
      if (match[0].includes(PLACEHOLDER_SENTINEL)) continue
      if (isDenied(span.value)) continue
      if (detector.tier === "B" && !passesTierBGate(span.value, detector.entropy ?? DEFAULT_ENTROPY_FLOOR)) {
        continue
      }
      findings.push({
        kind: detector.kind,
        start: span.start,
        end: span.end,
        value: span.value,
        tier: detector.tier,
      })
    }
  }
  findings.sort(byPosition)
  return findings
}
