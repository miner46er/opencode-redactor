import { describe, expect, test } from "bun:test"

import { DENYLIST, DETECTORS, detect, shannonEntropy } from "./rules"
import { redact, resolveOverlaps } from "./redact"
import { createPlaceholderRegistry, createPlaceholderScope } from "./session"
import type { Finding } from "./shape"

const AWS_ACCESS_KEY = "AKIA1234567890ABCDEF"
const AWS_SECRET = "abcdEFGH1234/ijklMNOP5678+rstuVWXY90zAb1"
const GITHUB_BODY = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
const SLACK_TOKEN = "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx"
const SLACK_USER_TOKEN = "xoxp-123456789012-123456789012-abcdefghijklmnopqrstuvwx"
const STRIPE_LIVE = "sk_live_51MxYzAbCdEfGhIjKlMnOpQr"
const GOOGLE_API_KEY = "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
const OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
const ANTHROPIC_API_KEY = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_kQ"
const GITLAB_PAT = "glpat-AbCdEfGhIjKlMnOpQrSt"
const NPM_TOKEN = "npm_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
const SENDGRID_KEY = "SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
const TWILIO_ACCOUNT_SID = "AC0123456789abcdef0123456789abcdef"
const TWILIO_API_KEY = "SK0123456789abcdef0123456789abcdef"
const PEM_BLOCK = [
  "-----BEGIN RSA PRIVATE KEY-----",
  "MIIEowIBAAKCAQEA7f3a9c1e7b04d2a6f8e1c3b5a7d9e0f2",
  "-----END RSA PRIVATE KEY-----",
].join("\n")
const JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
const CONNECTION_STRING = "POSTGRES_URL=postgres://appuser:s3cr3tP4ssw0rd@db.internal:5432/prod"
const GENERIC_VALUE = "3f9a2b8c1d4e5f6a7b8c9d0e1f2a3b4c"

const TIER_A_CASES: ReadonlyArray<readonly [string, string]> = [
  ["aws-access-key-id", `AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY}`],
  ["aws-secret-access-key", `AWS_SECRET_ACCESS_KEY=${AWS_SECRET}`],
  ["github-pat", `GITHUB_TOKEN=ghp_${GITHUB_BODY}`],
  ["slack-token", `SLACK_BOT_TOKEN=${SLACK_TOKEN}`],
  ["stripe-live-key", `STRIPE_SECRET_KEY=${STRIPE_LIVE}`],
  ["google-api-key", `GOOGLE_MAPS_KEY=${GOOGLE_API_KEY}`],
  ["openai-api-key", `OPENAI_API_KEY=${OPENAI_API_KEY}`],
  ["anthropic-api-key", `ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}`],
  ["gitlab-pat", `GITLAB_TOKEN=${GITLAB_PAT}`],
  ["npm-token", `NPM_TOKEN=${NPM_TOKEN}`],
  ["sendgrid-api-key", `SENDGRID_API_KEY=${SENDGRID_KEY}`],
  ["twilio-api-key", `TWILIO_ACCOUNT_SID=${TWILIO_ACCOUNT_SID}\nTWILIO_API_KEY=${TWILIO_API_KEY}`],
  ["pem-private-key", PEM_BLOCK],
  ["jwt", `Authorization: Bearer ${JWT}`],
  ["connection-string-password", CONNECTION_STRING],
]

describe("registry shape", () => {
  // Tier and entropy are orthogonal. A Tier B detector may be anchored and so
  // carry no floor, and an absent floor still applies the default at match time.
  test("no Tier A detector declares an entropy floor", () => {
    for (const detector of DETECTORS) {
      if (detector.tier === "A") {
        expect(detector.entropy, detector.kind).toBeUndefined()
      }
    }
  })

  test("Tier B detectors exist and are a minority of the table", () => {
    const tierA = DETECTORS.filter((detector) => detector.tier === "A")
    const tierB = DETECTORS.filter((detector) => detector.tier === "B")
    expect(tierA.length).toBeGreaterThanOrEqual(15)
    expect(tierB.length).toBe(2)
    expect(tierB.length).toBeLessThan(tierA.length)
  })
})

describe("detect: Tier A", () => {
  for (const [kind, text] of TIER_A_CASES) {
    test(`${kind} detects in a realistic context, on both surfaces`, () => {
      for (const surface of ["prose", "code"] as const) {
        const findings = detect(text, surface)
        const finding = findings.find((candidate) => candidate.kind === kind)
        expect(findings.map((candidate) => candidate.kind), `${surface}: ${text}`).toContain(kind)
        expect(finding?.tier).toBe("A")
        if (finding) expect(text.slice(finding.start, finding.end)).toBe(finding.value)
      }
    })
  }

  test("github-pat detects all five classic prefixes", () => {
    for (const prefix of ["ghp", "gho", "ghu", "ghs", "ghr"]) {
      const text = `GITHUB_TOKEN=${prefix}_${GITHUB_BODY}`
      expect(detect(text, "code").map((finding) => finding.kind), text).toContain("github-pat")
    }
  })

  test("slack-token detects xoxp user tokens", () => {
    const text = `SLACK_USER_TOKEN=${SLACK_USER_TOKEN}`
    expect(detect(text, "code").map((finding) => finding.kind)).toContain("slack-token")
  })

  test("aws-secret-access-key only revalues the secret, not the variable name", () => {
    const text = `AWS_SECRET_ACCESS_KEY=${AWS_SECRET}`
    const finding = detect(text, "code").find((candidate) => candidate.kind === "aws-secret-access-key")
    expect(finding?.value).toBe(AWS_SECRET)
    expect(finding?.start).toBe(text.indexOf(AWS_SECRET))
  })
})

describe("detect: Tier B", () => {
  test("generic-secret fires on prose", () => {
    const text = `api_key = "${GENERIC_VALUE}"`
    const finding = detect(text, "prose").find((candidate) => candidate.kind === "generic-secret")
    expect(finding?.value).toBe(GENERIC_VALUE)
    expect(finding?.tier).toBe("B")
  })

  test("generic-secret fires on an unquoted assignment", () => {
    const text = `API_KEY=${GENERIC_VALUE}`
    const finding = detect(text, "prose").find((candidate) => candidate.kind === "generic-secret")
    expect(finding?.value).toBe(GENERIC_VALUE)
  })

  test("generic-secret is silent on code", () => {
    expect(detect(`api_key = "${GENERIC_VALUE}"`, "code")).toEqual([])
    expect(detect(`API_KEY=${GENERIC_VALUE}`, "code")).toEqual([])
  })

  test("generic-secret rejects short, low-entropy, and whitespace-broken values", () => {
    expect(detect(`api_key = "abc123"`, "prose")).toEqual([])
    expect(detect(`api_key = "aaaaaaaaaaaaaaaaaaaa"`, "prose")).toEqual([])
    expect(detect(`api_key = "aaa aaa aaa aaa aaa aaa"`, "prose")).toEqual([])
  })

  test("entropy is measured on the matched value, not the line around it", () => {
    const paddedValue = `${"x".repeat(24)}${GENERIC_VALUE}`
    const text = `api_key = "${paddedValue}"\ntoken = "${GENERIC_VALUE}"`
    const findings = detect(text, "prose").filter((candidate) => candidate.kind === "generic-secret")
    expect(findings.length).toBe(1)
    expect(findings[0]?.value).toBe(GENERIC_VALUE)
  })
})

describe("shannonEntropy", () => {
  test("a single repeated character carries no information", () => {
    expect(shannonEntropy("aaaaaaaa")).toBe(0)
  })

  test("a uniform 16-symbol hex string is four bits per character", () => {
    expect(shannonEntropy("0123456789abcdef".repeat(2))).toBeCloseTo(4.0, 10)
  })

  test("an empty string is zero", () => {
    expect(shannonEntropy("")).toBe(0)
  })

  test("a high-entropy token clears the 3.5 floor", () => {
    expect(shannonEntropy("aB3$z9Qw2!xY7pLk5")).toBeGreaterThan(3.5)
  })
})

describe("deny-list", () => {
  const DENY_INPUTS: readonly string[] = [
    `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`,
    // The example secret only surfaces via a keyworded assignment, so the
    // input has to supply the key name as well as the value.
    `aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`,
    `STRIPE_SECRET_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc`,
    // jwt.io's sample, carried in an Authorization header like a real leak.
    `authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`,
    `session_token = "550e8400-e29b-41d4-a716-446655440000"`,
    `secret_hash = "8f4e2b1a9c0d3e5f7a6b8c9d0e1f2a3b4c5d6e7f"`,
    `api_secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"`,
    `db_password = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6ukxiK"`,
    [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF7a1c2e3b4d5f60718293a4b5c6d7e8f9a0b1c2d3e4 user@host",
      'public_key = "AAAAB3NzaC1yc2EAAAADAQABAAABgQDf7a1c2e3b4d5f60718293a4b5c6d7e8f9012345678a9b0c1d2e3f4a5b6c7d8"',
    ].join("\n"),
    `tls_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy0f7n2x4v6b8d0"`,
  ]

  test("has one input case per entry", () => {
    expect(DENY_INPUTS.length).toBe(DENYLIST.length)
  })

  DENYLIST.forEach((entry, index) => {
    test(`suppresses: ${entry.reason}`, () => {
      const text = DENY_INPUTS[index] ?? ""
      const findings = detect(text, "prose")
      expect(
        findings.map((finding) => `${finding.kind}@${finding.start}=${finding.value}`),
        entry.reason,
      ).toEqual([])
    })
  })
})

describe("no partial coverage", () => {
  // A rule that matches a fixed width without a right-hand boundary leaves the
  // tail of a longer secret in the output. That is worse than a miss: it looks
  // like the redactor worked while a credential fragment survives. Each case
  // asserts the whole value is either covered or the candidate is rejected.
  const OVERLONG: readonly [string, string, string][] = [
    ["aws-secret-access-key", "AWS_SECRET_ACCESS_KEY", "aB3xK9mQ7pL2wR8tY5uI1oP4sD6fG0hJ2kL5nB7vC9xZ1"],
    ["github-pat", "GITHUB_TOKEN", `ghp_${"a".repeat(40)}`],
    ["npm-token", "NPM_TOKEN", `npm_${"b".repeat(40)}`],
    ["google-api-key", "GOOGLE_KEY", `AIza${"c".repeat(39)}`],
    ["aws-access-key-id", "AWS_KEY", `AKIA${"D".repeat(20)}`],
  ]

  for (const [kind, name, value] of OVERLONG) {
    test(`${kind} never leaves a tail of an over-long value`, () => {
      const text = `${name}=${value}`
      const finding = detect(text, "prose").find((candidate) => candidate.kind === kind)
      if (finding === undefined) return
      const covered = text.slice(finding.start, finding.end)
      expect(
        covered === value,
        `${kind} covered ${covered.length} of ${value.length} chars, leaving "${value.slice(covered.length)}" in the output`,
      ).toBe(true)
    })
  }

  test("a redacted over-long secret leaves nothing recognisable behind", () => {
    const session = createPlaceholderScope()
    const value = "aB3xK9mQ7pL2wR8tY5uI1oP4sD6fG0hJ2kL5nB7vC9xZ1"
    const result = redact(`AWS_SECRET_ACCESS_KEY=${value}`, "prose", session)
    expect(result.text.includes("C9xZ1"), "the trailing fragment of the secret survived redaction").toBe(false)
    expect(result.text).toContain("[REDACTED:aws-secret-access-key")
  })
})

describe("redact", () => {
  test("returns the input unchanged when nothing is found", () => {
    const session = createPlaceholderScope()
    const result = redact("nothing to see here", "prose", session)
    expect(result.text).toBe("nothing to see here")
    expect(result.redacted).toEqual([])
    expect(result.warned).toEqual([])
  })

  test("multiple findings apply right-to-left with valid offsets", () => {
    const session = createPlaceholderScope()
    const text = `aws=${AWS_ACCESS_KEY} gh=ghp_${GITHUB_BODY} end`
    const result = redact(text, "prose", session)

    expect(result.redacted.map((finding) => finding.kind)).toEqual(["aws-access-key-id", "github-pat"])
    expect(result.warned).toEqual([])
    for (const finding of result.redacted) {
      expect(text.slice(finding.start, finding.end)).toBe(finding.value)
    }

    const byKind = new Map(result.redacted.map((finding) => [finding.kind, finding]))
    const aws = byKind.get("aws-access-key-id")
    const github = byKind.get("github-pat")
    expect(result.text).toBe(
      `aws=[REDACTED:aws-access-key-id#1:${aws?.fingerprint}] gh=[REDACTED:github-pat#1:${github?.fingerprint}] end`,
    )
    expect(result.text.includes(AWS_ACCESS_KEY)).toBe(false)
    expect(result.text.includes(GITHUB_BODY)).toBe(false)
  })

  test("connection strings redact only the password, keeping the URI shape", () => {
    const session = createPlaceholderScope()
    const result = redact(CONNECTION_STRING, "prose", session)
    const fingerprint = result.redacted[0]?.fingerprint
    expect(result.redacted.map((finding) => finding.kind)).toEqual(["connection-string-password"])
    expect(result.text).toBe(
      `POSTGRES_URL=postgres://appuser:[REDACTED:connection-string-password#1:${fingerprint}]@db.internal:5432/prod`,
    )
  })

  test("a Tier A finding beats an overlapping Tier B finding", () => {
    const session = createPlaceholderScope()
    const text = `password = "${AWS_ACCESS_KEY}"`
    const result = redact(text, "prose", session)
    expect(result.redacted.map((finding) => finding.kind)).toEqual(["aws-access-key-id"])
    expect(result.warned).toEqual([])
    expect(result.text).toBe(
      `password = "[REDACTED:aws-access-key-id#1:${result.redacted[0]?.fingerprint}]"`,
    )
  })

  test("for equal tiers the longer span wins a nested overlap", () => {
    const session = createPlaceholderScope()
    const text = `token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig-${GOOGLE_API_KEY}`
    expect(detect(text, "prose").map((finding) => finding.kind)).toContain("google-api-key")
    const result = redact(text, "prose", session)
    expect(result.redacted.map((finding) => finding.kind)).toEqual(["jwt"])
    expect(result.text).toBe(`token=[REDACTED:jwt#1:${result.redacted[0]?.fingerprint}]`)
  })

  test("resolveOverlaps applies tier, then length, then lower start", () => {
    const make = (kind: string, tier: "A" | "B", start: number, end: number): Finding => ({
      kind,
      start,
      end,
      value: "x",
      tier,
      fingerprint: "000000000000",
    })
    const kinds = (input: readonly Finding[]) => resolveOverlaps(input).map((finding) => finding.kind)
    expect(kinds([make("tier-b", "B", 0, 30), make("tier-a", "A", 5, 15)])).toEqual(["tier-a"])
    expect(kinds([make("longer", "A", 0, 20), make("shorter", "A", 5, 10)])).toEqual(["longer"])
    expect(kinds([make("later", "A", 4, 12), make("earlier", "A", 0, 8)])).toEqual(["earlier"])
    expect(kinds([make("inverted", "A", 10, 5), make("empty", "A", 7, 7)])).toEqual([])
  })

  test("Tier B is warned, not redacted, on code", () => {
    const session = createPlaceholderScope()
    const text = `api_key = "${GENERIC_VALUE}"`
    const result = redact(text, "code", session)
    expect(result.text).toBe(text)
    expect(result.redacted).toEqual([])
    expect(result.warned.map((finding) => finding.kind)).toEqual(["generic-secret"])
    expect(result.warned[0]?.fingerprint).toMatch(/^[0-9a-f]{12}$/)
  })

  test("code redacts Tier A and warns Tier B in the same pass", () => {
    const session = createPlaceholderScope()
    const text = `AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY}\napi_key = "${GENERIC_VALUE}"`
    const result = redact(text, "code", session)
    expect(result.redacted.map((finding) => finding.kind)).toEqual(["aws-access-key-id"])
    expect(result.warned.map((finding) => finding.kind)).toEqual(["generic-secret"])
    expect(result.text.includes(AWS_ACCESS_KEY)).toBe(false)
    expect(result.text.includes(GENERIC_VALUE)).toBe(true)
  })

  test("prose redacts Tier A and Tier B together, with no warnings", () => {
    const session = createPlaceholderScope()
    const text = `AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY}\napi_key = "${GENERIC_VALUE}"`
    const result = redact(text, "prose", session)
    expect(result.warned).toEqual([])
    expect(result.redacted.map((finding) => finding.kind).sort()).toEqual([
      "aws-access-key-id",
      "generic-secret",
    ])
    expect(result.text.includes(AWS_ACCESS_KEY)).toBe(false)
    expect(result.text.includes(GENERIC_VALUE)).toBe(false)
  })

  test("the same value gets the same placeholder everywhere in one session", () => {
    const session = createPlaceholderScope()
    const text = `a=${AWS_ACCESS_KEY} b=${AWS_ACCESS_KEY}`
    const result = redact(text, "prose", session)
    expect(result.redacted.length).toBe(2)
    expect(result.redacted[0]?.fingerprint).toBe(result.redacted[1]?.fingerprint)
    const placeholder = `[REDACTED:aws-access-key-id#1:${result.redacted[0]?.fingerprint}]`
    expect(result.text).toBe(`a=${placeholder} b=${placeholder}`)
  })
})

describe("idempotency", () => {
  const IDEMPOTENCY_INPUTS: ReadonlyArray<readonly ["prose" | "code", string]> = [
    [
      "prose",
      [
        `AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY}`,
        `GITHUB_TOKEN=ghp_${GITHUB_BODY}`,
        `POSTGRES_URL=postgres://appuser:s3cr3tP4ssw0rd@db.internal:5432/prod`,
      ].join("\n"),
    ],
    ["prose", `api_key = "${GENERIC_VALUE}"\nAuthorization: Bearer ${JWT}`],
    ["prose", `password = "${AWS_SECRET}"`],
    ["code", `api_key = "${GENERIC_VALUE}"\nAWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY}`],
  ]

  IDEMPOTENCY_INPUTS.forEach(([surface, input], index) => {
    test(`redact(redact(x)) === redact(x) for input ${index} (${surface})`, () => {
      const session = createPlaceholderScope()
      const once = redact(input, surface, session)
      const twice = redact(once.text, surface, session)
      expect(twice.text).toBe(once.text)
      expect(twice.redacted).toEqual([])
      expect(once.text.includes(AWS_ACCESS_KEY)).toBe(false)
      expect(once.text.includes(AWS_SECRET)).toBe(false)
      // On code, Tier B is warned rather than replaced, so its value stays.
      expect(once.text.includes(GENERIC_VALUE)).toBe(surface === "code")
    })
  })

  test("no detector can match any emitted placeholder", () => {
    const session = createPlaceholderScope()
    const emitted = redact(`AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY}`, "prose", session).text
    const samples = DETECTORS.map((detector) => `[REDACTED:${detector.kind}#1:3f2a9c1e7b04]`)
    samples.push(emitted, "[REDACTED:generic-secret#12:abcdef012345]")
    for (const detector of DETECTORS) {
      for (const sample of samples) {
        const matches = [...sample.matchAll(detector.pattern)]
        expect(matches.length, `${detector.kind} matched ${sample}`).toBe(0)
      }
    }
  })
})

describe("session scope", () => {
  test("fingerprints are exactly 12 lowercase hex chars", () => {
    const session = createPlaceholderScope()
    const placeholder = session.placeholderFor("some-distinct-value-1234", "generic-secret")
    expect(placeholder.finding.fingerprint).toMatch(/^[0-9a-f]{12}$/)
  })

  test("two scopes fingerprint the same value differently", () => {
    const first = createPlaceholderScope()
    const second = createPlaceholderScope()
    const a = first.placeholderFor(AWS_SECRET, "generic-secret")
    const b = second.placeholderFor(AWS_SECRET, "generic-secret")
    expect(a.finding.fingerprint).not.toBe(b.finding.fingerprint)
    expect(a.finding.fingerprint).toMatch(/^[0-9a-f]{12}$/)
    expect(b.finding.fingerprint).toMatch(/^[0-9a-f]{12}$/)
  })

  test("counters are per kind and stable per value", () => {
    const session = createPlaceholderScope()
    const a = session.placeholderFor("value-aaaa-1234-5678", "generic-secret")
    const b = session.placeholderFor("value-bbbb-1234-5678", "generic-secret")
    const c = session.placeholderFor("value-cccc-1234-5678", "aws-access-key-id")
    expect(a.text).toBe(`[REDACTED:generic-secret#1:${a.finding.fingerprint}]`)
    expect(b.text).toBe(`[REDACTED:generic-secret#2:${b.finding.fingerprint}]`)
    expect(c.text).toBe(`[REDACTED:aws-access-key-id#1:${c.finding.fingerprint}]`)
    expect(session.placeholderFor("value-aaaa-1234-5678", "generic-secret").text).toBe(a.text)
  })

  test("findings exposes observed values in memory and reset clears them", () => {
    const session = createPlaceholderScope()
    session.placeholderFor("value-aaaa-1234-5678", "generic-secret")
    expect(session.findings().length).toBe(1)
    expect(session.findings()[0]?.value).toBe("value-aaaa-1234-5678")
    session.reset()
    expect(session.findings()).toEqual([])
  })

  test("reset rotates the key so fingerprints do not correlate across epochs", () => {
    const session = createPlaceholderScope()
    const before = session.placeholderFor(AWS_SECRET, "generic-secret").finding.fingerprint
    session.reset()
    const after = session.placeholderFor(AWS_SECRET, "generic-secret").finding.fingerprint
    expect(after).not.toBe(before)
  })
})

describe("conversation isolation", () => {
  // The host scopes a plugin instance to a directory, not a conversation. If one
  // scope were shared across conversations, the same credential would carry the
  // same fingerprint into two unrelated histories, and equality would become
  // correlatable between them.
  test("two conversations in one process fingerprint the same value differently", () => {
    const registry = createPlaceholderRegistry()
    const value = "AKIA7QWERTYUIOPASDFGH"
    const a = registry.for("ses_alpha").placeholderFor(value, "aws-access-key-id")
    const b = registry.for("ses_beta").placeholderFor(value, "aws-access-key-id")
    expect(a.finding.fingerprint).not.toBe(b.finding.fingerprint)
  })

  test("the same conversation reuses its scope and its fingerprint", () => {
    const registry = createPlaceholderRegistry()
    const value = "AKIA7QWERTYUIOPASDFGH"
    const first = registry.for("ses_alpha").placeholderFor(value, "aws-access-key-id")
    const second = registry.for("ses_alpha").placeholderFor(value, "aws-access-key-id")
    expect(second.text).toBe(first.text)
  })

  test("releasing a conversation drops its key so history cannot be rechecked", () => {
    const registry = createPlaceholderRegistry()
    const value = "AKIA7QWERTYUIOPASDFGH"
    const before = registry.for("ses_alpha").placeholderFor(value, "aws-access-key-id").finding.fingerprint
    registry.release("ses_alpha")
    const after = registry.for("ses_alpha").placeholderFor(value, "aws-access-key-id").finding.fingerprint
    expect(after).not.toBe(before)
  })
})
