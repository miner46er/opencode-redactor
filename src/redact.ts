import { appliesHere, byPosition, compareKind, detect } from "./rules"
import type { PlaceholderScope } from "./session"
import type { Finding, RedactedFinding, RedactionResult, TextClass } from "./shape"

/**
 * Findings can nest or overlap because provider formats sit inside assignments.
 * Precedence is higher tier, then longer span, then earlier start, so a Tier B
 * assignment never beats the Tier A credential nested inside it.
 */
export function resolveOverlaps(findings: readonly Finding[]): Finding[] {
  const ranked = findings
    .filter((finding) => finding.end > finding.start)
    .slice()
    .sort((a, b) => {
      if (a.tier !== b.tier) return a.tier === "A" ? -1 : 1
      const lengthDiff = b.end - b.start - (a.end - a.start)
      if (lengthDiff !== 0) return lengthDiff
      if (a.start !== b.start) return a.start - b.start
      return compareKind(a, b)
    })
  const accepted: Finding[] = []
  for (const candidate of ranked) {
    const collides = accepted.some((kept) => kept.start < candidate.end && candidate.start < kept.end)
    if (!collides) accepted.push(candidate)
  }
  accepted.sort(byPosition)
  return accepted
}

export function redact(
  text: string,
  surface: TextClass,
  session: PlaceholderScope,
): RedactionResult {
  // detect() withholds Tier B on code, but the result shape still has to report
  // those candidates as warnings, so scan as prose and route each finding by the
  // same gate detect() used.
  const findings = resolveOverlaps(detect(text, "prose"))
  const redacted: RedactedFinding[] = []
  const warned: RedactedFinding[] = []
  const replacements: Array<{ readonly start: number; readonly end: number; readonly text: string }> = []

  for (const finding of findings) {
    if (finding.start < 0 || finding.end > text.length) continue
    const placeholder = session.placeholderFor(finding.value, finding.kind)
    const applied: RedactedFinding = { ...placeholder.finding, start: finding.start, end: finding.end }
    if (!appliesHere(finding.tier, surface)) {
      warned.push(applied)
      continue
    }
    redacted.push(applied)
    replacements.push({ start: finding.start, end: finding.end, text: placeholder.text })
  }

  // Right-to-left keeps every earlier span's offsets valid while text grows.
  let out = text
  for (let i = replacements.length - 1; i >= 0; i--) {
    const span = replacements[i]
    if (!span) continue
    out = out.slice(0, span.start) + span.text + out.slice(span.end)
  }
  return { text: out, redacted, warned }
}
