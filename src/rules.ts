/**
 * The detector registry: one table row per provider format. Surface gating,
 * entropy gating, and tier routing all read the `tier` and `entropy` fields off
 * each row, so adding a provider is a new array entry, never a new branch.
 */
import type { Detector, Finding } from "./shape"

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
    pattern: /\bxox[bp]-(?:[0-9A-Za-z]{6,48}-){0,4}[0-9A-Za-z]{10,64}\b/gd,
  },
  {
    kind: "stripe-live-key",
    tier: "A",
    pattern: /\b(?:sk|rk)_live_[A-Za-z0-9]{24,99}\b/gd,
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
    pattern: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|ftps?|smtps?|https?):\/\/[^\s:/@]{1,64}:([^\s/@]{3,128})@/gid,
  },
  {
    kind: "generic-secret",
    tier: "B",
    entropy: DEFAULT_ENTROPY_FLOOR,
    pattern: /\b[A-Za-z0-9_-]{0,40}(?:key|secret|token|password|passwd|credential)[A-Za-z0-9_-]{0,40}[ \t]*[:=][ \t]*(?:"([^"\s]{16,})"|'([^'\s]{16,})'|([A-Za-z0-9+/=_\-]{16,}))/gid,
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
export function detect(text: string, surface: "prose" | "code"): Finding[] {
  const findings: Finding[] = []
  for (const detector of DETECTORS) {
    if (detector.tier === "B" && surface === "code") continue
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
  findings.sort(
    (a, b) => a.start - b.start || b.end - a.end || (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0),
  )
  return findings
}
