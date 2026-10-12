import { createHmac, randomBytes } from "node:crypto"

import { DETECTORS, PLACEHOLDER_SENTINEL } from "./rules"
import type { Finding, Placeholder, RedactedFinding, Tier } from "./shape"

/**
 * Placeholder text is stable per value for the lifetime of one scope.
 *
 * One scope backs one conversation, never more. A scope's fingerprint key must
 * not be shared across conversations, or the same credential would produce the
 * same fingerprint in two unrelated histories and equality would become
 * correlatable between them.
 */
export interface PlaceholderScope {
  /**
   * The ONLY mutating entry point. Assigns (or returns the existing) stable
   * placeholder for a value, and records the observation in the ledger.
   */
  placeholderFor(value: string, kind: string): Placeholder<RedactedFinding>
  /**
   * The in-memory audit ledger of observed values that were given placeholders.
   * Finding objects carry `.value` because the pinned shape requires it; that
   * copy exists in memory only, and never persisting or logging it is the
   * caller's responsibility.
   */
  findings(): readonly Finding[]
  reset(): void
}

/** Hands out the one scope that owns a given conversation. */
export interface PlaceholderRegistry {
  for(sessionID: string): PlaceholderScope
  /** Drops a conversation's scope and its key. Called when a session ends. */
  release(sessionID: string): void
}

export function createPlaceholderScope(): PlaceholderScope {
  let key = randomBytes(32)
  const byFingerprint = new Map<string, Placeholder<RedactedFinding>>()
  const counters = new Map<string, number>()

  const fingerprintOf = (value: string): string =>
    createHmac("sha256", key).update(value, "utf8").digest("hex").slice(0, 12)

  const tierOf = (kind: string): Tier => DETECTORS.find((detector) => detector.kind === kind)?.tier ?? "B"

  return {
    placeholderFor(value, kind) {
      const fingerprint = fingerprintOf(value)
      const existing = byFingerprint.get(fingerprint)
      if (existing) return existing
      const n = (counters.get(kind) ?? 0) + 1
      counters.set(kind, n)
      // The ledger is not positional: placeholderFor receives no offsets, so
      // start/end span the recorded value itself. Real offsets live on the
      // findings redact() returns.
      const finding: RedactedFinding = {
        kind,
        start: 0,
        end: value.length,
        value,
        tier: tierOf(kind),
        fingerprint,
      }
      const placeholder: Placeholder<RedactedFinding> = {
        text: `${PLACEHOLDER_SENTINEL}${kind}#${n}:${fingerprint}]`,
        finding,
      }
      byFingerprint.set(fingerprint, placeholder)
      return placeholder
    },
    findings() {
      return [...byFingerprint.values()].map((placeholder) => placeholder.finding)
    },
    reset() {
      // A reset opens a new privacy epoch: rotating the key keeps fingerprints
      // from correlating across it, matching the guarantee separate scopes make
      // for each other.
      key = randomBytes(32)
      byFingerprint.clear()
      counters.clear()
    },
  }
}

export function createPlaceholderRegistry(): PlaceholderRegistry {
  const scopes = new Map<string, PlaceholderScope>()
  return {
    for(sessionID) {
      const existing = scopes.get(sessionID)
      if (existing) return existing
      const created = createPlaceholderScope()
      scopes.set(sessionID, created)
      return created
    },
    release(sessionID) {
      // Dropping the scope drops its key with it, so the credential it hashed
      // cannot be checked against this conversation's stored history later.
      scopes.delete(sessionID)
    },
  }
}
