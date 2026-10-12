// Expects src/rules.ts to export:
//   export function detect(text: string, surface: "prose" | "code"): Finding[]
// Tier A detectors match regardless of surface.
// Tier B detectors return a finding on "prose" and return [] on "code".

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

function expectKind(findings: readonly Finding[], kind: string, label: string, surface: TestSurface): void {
  expect(
    findings.some((finding) => finding.kind === kind),
    `${label}: expected kind "${kind}" on surface "${surface}", got ${kindsOf(findings)}`,
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
    expect(SECRETS, "an accidental deletion or addition must be reviewed, never silently absorbed").toHaveLength(22)
    expect(BENIGN, "an accidental deletion or addition must be reviewed, never silently absorbed").toHaveLength(26)
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
        expectKind(detect(fixture.context, "prose"), kind, fixture.label, "prose")
      })

      it(`${fixture.label} matches on code`, () => {
        expectKind(detect(fixture.context, "code"), kind, fixture.label, "code")
      })
    }
  })
}

for (const [kind, fixtures] of byKind(TIER_B)) {
  describe(`tier B / ${kind}`, () => {
    for (const fixture of fixtures) {
      it(`${fixture.label} matches on prose`, () => {
        expectKind(detect(fixture.context, "prose"), kind, fixture.label, "prose")
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
