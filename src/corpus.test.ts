import { describe, expect, it } from "bun:test"
import { BENIGN, SECRETS, type BenignFixture, type SecretFixture } from "./corpus"
import { detect } from "./rules"
import type { Finding } from "./shape"

type TestSurface = "prose" | "code"

const TIER_A = SECRETS.filter((fixture) => fixture.tier === "A")
const TIER_B = SECRETS.filter((fixture) => fixture.tier === "B")

function byKind(fixtures: readonly SecretFixture[]): ReadonlyMap<string, readonly SecretFixture[]> {
  const groups = new Map<string, SecretFixture[]>()
  for (const fixture of fixtures) {
    const group = groups.get(fixture.kind)
    if (group === undefined) {
      groups.set(fixture.kind, [fixture])
    } else {
      group.push(fixture)
    }
  }
  return groups
}

function kindsOf(findings: readonly Finding[]): string {
  return findings.length === 0 ? "no findings" : findings.map((finding) => finding.kind).join(", ")
}

/**
 * The finding must cover the fixture's value exactly. Matching the kind alone
 * would pass a detector that stops partway through the value, and a partially
 * redacted credential is worse than a missed one.
 */
function expectSecret(findings: readonly Finding[], fixture: SecretFixture, surface: TestSurface): void {
  const ofKind = findings.filter((finding) => finding.kind === fixture.kind)
  expect(
    ofKind.length > 0,
    `${fixture.label}: expected kind "${fixture.kind}" on surface "${surface}", got ${kindsOf(findings)}`,
  ).toBe(true)
  expect(
    ofKind.some((finding) => finding.value === fixture.value),
    `${fixture.label}: a "${fixture.kind}" finding must cover the whole value, not part of it`,
  ).toBe(true)
}

function expectNoFindings(fixture: BenignFixture, surface: TestSurface): void {
  const findings = detect(fixture.text, surface)
  expect(
    findings,
    `${fixture.label} produced ${kindsOf(findings)} on surface "${surface}".\n` +
      `Why this text is not a secret: ${fixture.reason}`,
  ).toEqual([])
}

describe("corpus integrity", () => {
  it("keeps the exact fixture counts", () => {
    expect(SECRETS, "an accidental deletion or addition must be reviewed, never silently absorbed").toHaveLength(73)
    expect(BENIGN, "an accidental deletion or addition must be reviewed, never silently absorbed").toHaveLength(34)
  })

  it("embeds every secret value verbatim in its context", () => {
    for (const fixture of SECRETS) {
      expect(
        fixture.context.includes(fixture.value),
        `${fixture.label}: context must contain the value verbatim`,
      ).toBe(true)
    }
  })

  it("never embeds a secret fixture value inside a benign fixture", () => {
    for (const benign of BENIGN) {
      for (const secret of SECRETS) {
        expect(
          benign.text.includes(secret.value),
          `${benign.label} unexpectedly contains the value of ${secret.label}`,
        ).toBe(false)
      }
    }
  })

  it("uses unique labels across both lists", () => {
    const labels = [...SECRETS, ...BENIGN].map((fixture) => fixture.label)
    expect(new Set(labels).size, "labels identify fixtures in failure output, so they must not collide").toBe(
      labels.length,
    )
  })

  it("carries a reason on every benign fixture", () => {
    for (const benign of BENIGN) {
      expect(benign.reason.length, `${benign.label} needs a reason explaining why it is benign`).toBeGreaterThan(20)
    }
  })
})

for (const [kind, fixtures] of byKind(TIER_A)) {
  describe(`tier A / ${kind}`, () => {
    for (const fixture of fixtures) {
      it(`${fixture.label} matches on prose`, () => {
        expectSecret(detect(fixture.context, "prose"), fixture, "prose")
      })

      it(`${fixture.label} matches on code`, () => {
        expectSecret(detect(fixture.context, "code"), fixture, "code")
      })
    }
  })
}

// A lookahead over a narrower charset than the run around it lets a longer
// alphanumeric run match on its prefix and leave the tail in the output. The
// PEM block is exempt: its END marker, not a charset, is what terminates it.
describe("tier A / no prefix match on an over-long run", () => {
  for (const fixture of TIER_A.filter((candidate) => candidate.kind !== "pem-private-key")) {
    it(`${fixture.label} is rejected or covered whole when an alphanumeric tail follows`, () => {
      for (const tail of ["9", "Z", "z"]) {
        const text = `${fixture.value}${tail}`
        const partial = detect(text, "prose").find(
          (finding) => finding.kind === fixture.kind && finding.start === 0 && finding.end < text.length,
        )
        expect(partial, `${fixture.kind} matched a prefix and left "${tail}" behind`).toBeUndefined()
      }
    })
  }
})

for (const [kind, fixtures] of byKind(TIER_B)) {
  describe(`tier B / ${kind}`, () => {
    for (const fixture of fixtures) {
      it(`${fixture.label} matches on prose`, () => {
        expectSecret(detect(fixture.context, "prose"), fixture, "prose")
      })
    }
  })
}

for (const benign of BENIGN) {
  describe(`benign / ${benign.label}`, () => {
    it("produces no findings on prose", () => {
      expectNoFindings(benign, "prose")
    })

    it("produces no findings on code", () => {
      expectNoFindings(benign, "code")
    })
  })
}
