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
    // Slack and Discord webhook URLs are the exception: the credential is in
    // the path, so those hosts are carved out and the webhook rules redact the
    // whole URL instead of this rule dropping it.
    reason:
      "a URL with no userinfo or query is an address, not a secret, unless it is a chat webhook endpoint",
    pattern:
      /^(?!https?:\/\/(?:hooks\.slack\.com\/(?:services|workflows|triggers)\/|discord(?:app)?\.com\/api\/webhooks\/))[a-z][a-z0-9+.-]*:\/\/[^\s@?#]*$/i,
  },
  {
    // The lowercase head is what separates `process.env.X` from dotted
    // provider formats: a JWT starts "eyJ" and a SendGrid key starts "SG.".
    // A password shaped like this is missed rather than partly redacted,
    // which spec 19 ranks as the lesser harm. Vault service and batch tokens
    // (hvs./hvb.) are lowercase-headed dotted runs too, so the lookahead
    // carves them out rather than let the reference rule swallow a credential.
    reason: "a dotted identifier is a reference to where a secret lives, such as process.env.X",
    pattern: /^(?!hv[bs]\.)[a-z_$][a-z0-9_$]*(?:\.[A-Za-z_$][\w$]*)+$/,
  },
  {
    // Anchored on a real root so a base64 secret that happens to start with "/"
    // is not mistaken for a path.
    reason: "an absolute filesystem path points at where a secret is stored",
    pattern: /^(?:\/(?:home|Users|etc|usr|var|run|opt|tmp|srv|mnt|root|private)|~)\/[\w.\/-]*$/,
  },
  {
    // A PKCS#8 or PKCS#1 private key is MII-prefixed too: DER puts SEQUENCE
    // then INTEGER version 0, which lands "IBA" at characters 6-8 of the
    // base64. Certificates and public keys never carry it, so excluding "IBA"
    // keeps private keys while still dropping a certificate body.
    reason: "a certificate body (MII-prefixed DER) is public material; a private key body is not",
    pattern: /^MII[A-Za-z0-9+/]{3}(?!IBA)[A-Za-z0-9+/]{27,}={0,2}$/,
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
    pattern: /\b(?:A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}(?![A-Za-z0-9])/gd,
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
    // The letter set covers xoxa app, xoxb bot, xoxp user, xoxr refresh and
    // xoxs/xoxe workspace tokens. \b cannot be the terminator here: it treats
    // "-" as a boundary, so a token with more hyphen groups than the pattern
    // allows would match on a prefix and leave the tail behind.
    pattern: /\bxox[abprse]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9-])/gd,
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
    // "or-v1-" is excluded so OpenRouter keys are reported as their own kind
    // instead of being consumed here as an OpenAI key.
    pattern: /\bsk-(?!ant-|or-v1-)(?:proj-)?[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/gd,
  },
  {
    kind: "anthropic-api-key",
    tier: "A",
    pattern: /\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/gd,
  },
  {
    // The alternation covers every GitLab token family: glpat personal access,
    // glptt pipeline trigger, gldt deploy, glrt runner, glcbt CI build, gloas
    // and glsoat OAuth, glffct feature-flag client, glagent agent, glimt
    // incoming mail.
    kind: "gitlab-pat",
    tier: "A",
    pattern: /\bgl(?:pat|ptt|dt|rt|cbt|oas|soat|ffct|agent|imt)-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/gd,
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
    pattern: /\bSK[0-9a-f]{32}(?![A-Za-z0-9])/gd,
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
    // A fine-grained PAT keeps its own kind so a policy can treat it apart from
    // the classic gh[pousr]_ tokens; the negative lookahead rejects an
    // over-long alphanumeric tail instead of prefix-matching it.
    kind: "github-fine-grained-pat",
    tier: "A",
    pattern: /\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}(?![A-Za-z0-9])/gd,
  },
  {
    // The app-level token does not fit the xox[baprse] shape: it is
    // "xapp-<version>-<app id>-<id>-<secret>" with mixed case.
    kind: "slack-app-token",
    tier: "A",
    pattern: /\bxapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+(?![A-Za-z0-9-])/gd,
  },
  {
    // The credential is the whole URL, not only the trailing secret. The
    // generic "a URL is an address" deny entry carves these hosts out so it
    // cannot swallow a live webhook.
    kind: "slack-webhook",
    tier: "A",
    pattern:
      /\bhttps:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/T[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9]{20,}(?![A-Za-z0-9])/gd,
  },
  {
    // Same whole-URL reasoning as slack-webhook; the URL deny entry carves out
    // Discord's webhook path.
    kind: "discord-webhook",
    tier: "A",
    pattern: /\bhttps:\/\/(?:discord|discordapp)\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{60,}(?![A-Za-z0-9_-])/gd,
  },
  {
    kind: "telegram-bot-token",
    tier: "A",
    pattern: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}(?![A-Za-z0-9_-])/gd,
  },
  {
    kind: "huggingface-token",
    tier: "A",
    pattern: /\bhf_[A-Za-z]{34}(?![A-Za-z0-9])/gd,
  },
  {
    kind: "groq-api-key",
    tier: "A",
    pattern: /\bgsk_[A-Za-z0-9]{52}(?![A-Za-z0-9])/gd,
  },
  {
    kind: "replicate-api-token",
    tier: "A",
    pattern: /\br8_[A-Za-z0-9]{37}(?![A-Za-z0-9])/gd,
  },
  {
    kind: "xai-api-key",
    tier: "A",
    pattern: /\bxai-[A-Za-z0-9]{80}(?![A-Za-z0-9])/gd,
  },
  {
    kind: "perplexity-api-key",
    tier: "A",
    pattern: /\bpplx-[A-Za-z0-9]{48}(?![A-Za-z0-9])/gd,
  },
  {
    kind: "openrouter-api-key",
    tier: "A",
    pattern: /\bsk-or-v1-[a-f0-9]{64}(?![A-Za-z0-9])/gd,
  },
  {
    kind: "stripe-webhook-secret",
    tier: "A",
    pattern: /\bwhsec_[A-Za-z0-9]{32,}(?![A-Za-z0-9])/gd,
  },
  {
    // The captured group is the key; the connection string around it is context.
    // \b and the trailing lookahead keep a longer alphanumeric run from being
    // matched on its first 88 chars.
    kind: "azure-storage-account-key",
    tier: "A",
    pattern: /\bAccountKey=([A-Za-z0-9+/]{86}==)(?![A-Za-z0-9+/=])/gd,
  },
  {
    // The "~" in every client secret keeps it out of the dotted-identifier deny
    // entry, so only the lookbehind/lookahead are needed to stop a match inside
    // a longer mixed run.
    kind: "azure-ad-client-secret",
    tier: "A",
    pattern: /(?<![A-Za-z0-9_~.-])[A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.-]{31,34}(?![A-Za-z0-9_~.-])/gd,
  },
  {
    // Only the signature value is a credential; the "?sig="/"&sig=" markers are
    // context, so this one captures rather than matching the whole query.
    kind: "azure-sas-signature",
    tier: "A",
    pattern: /[?&]sig=([A-Za-z0-9%+/=]{40,})(?![A-Za-z0-9%+/=])/gid,
  },
  {
    // The provider prefix stays in the value so the 64-hex digest deny entry
    // cannot suppress it.
    kind: "digitalocean-token",
    tier: "A",
    pattern: /\bdo[por]_v1_[a-f0-9]{64}(?![A-Za-z0-9])/gd,
  },
  {
    // hvs./hvb. is a lowercase-headed dotted run, so the dotted-identifier deny
    // entry carves these prefixes out rather than swallow a live token.
    kind: "vault-token",
    tier: "A",
    pattern: /\bhv[sb]\.[A-Za-z0-9_-]{90,}(?![A-Za-z0-9_-])/gd,
  },
  {
    kind: "terraform-cloud-token",
    tier: "A",
    pattern: /\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,}(?![A-Za-z0-9_=-])/gd,
  },
  {
    kind: "databricks-token",
    tier: "A",
    // The terminator includes "-" so the optional "-<region>" suffix cannot be
    // backtracked away, which would leave "dapi<32 hex>" matched against the
    // front of a longer hyphenated token.
    pattern: /\bdapi[a-f0-9]{32}(?:-\d)?(?![A-Za-z0-9-])/gd,
  },
  {
    kind: "shopify-token",
    tier: "A",
    pattern: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}(?![A-Za-z0-9])/gd,
  },
  {
    kind: "pypi-token",
    tier: "A",
    pattern: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}(?![A-Za-z0-9_-])/gd,
  },
  {
    kind: "dockerhub-pat",
    tier: "A",
    pattern: /\bdckr_pat_[A-Za-z0-9_-]{27,}(?![A-Za-z0-9_-])/gd,
  },
  {
    kind: "postman-api-key",
    tier: "A",
    pattern: /\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}(?![A-Za-z0-9])/gd,
  },
  {
    kind: "linear-api-key",
    tier: "A",
    pattern: /\blin_api_[A-Za-z0-9]{40}(?![A-Za-z0-9])/gd,
  },
  {
    kind: "atlassian-api-token",
    tier: "A",
    pattern: /\bATATT3[A-Za-z0-9_=-]{180,}(?![A-Za-z0-9_=-])/gd,
  },
  {
    // Two token families share Grafana's "gl" namespace; one kind with an
    // alternation means a policy keyed on kind covers both.
    kind: "grafana-token",
    tier: "A",
    pattern: /\b(?:glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}|glc_[A-Za-z0-9+/]{32,}={0,2})(?![A-Za-z0-9+/=])/gd,
  },
  {
    kind: "sentry-token",
    tier: "A",
    pattern: /\bsntry[su]_[A-Za-z0-9+/=_-]{40,}(?![A-Za-z0-9+/=_-])/gd,
  },
  {
    // sbp_ is the account access token; sb_secret_ is the newer service key.
    kind: "supabase-token",
    tier: "A",
    pattern: /\b(?:sbp_[a-f0-9]{40}|sb_secret_[A-Za-z0-9_-]{30,})(?![A-Za-z0-9_-])/gd,
  },
  {
    kind: "newrelic-api-key",
    tier: "A",
    pattern: /\bNRAK-[A-Z0-9]{27}(?![A-Za-z0-9])/gd,
  },
  {
    kind: "square-token",
    tier: "A",
    pattern: /\b(?:sq0atp-[A-Za-z0-9_-]{22}|sq0csp-[A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])/gd,
  },
  {
    kind: "age-secret-key",
    tier: "A",
    // age uses bech32's alphabet. The lookahead is over all alphanumerics, not
    // that alphabet, so any longer run is rejected rather than prefix-matched.
    pattern: /\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}(?![A-Za-z0-9])/gd,
  },
  {
    kind: "firebase-fcm-server-key",
    tier: "A",
    pattern: /\bAAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{100,}(?![A-Za-z0-9_-])/gd,
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
