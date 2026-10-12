/**
 * The pinned data shape. Every other module speaks in these terms.
 *
 * A Finding is a span a Detector classified as a credential. It is not
 * necessarily a secret. A false positive is still a Finding, and `tier`
 * is what tells the two apart.
 */

/**
 * Where text crosses the model boundary. A channel is a place data flows
 * through, independent of what the text turns out to be.
 */
export type Channel = "prompt" | "tool-output" | "tool-input"

/**
 * What the text is. Drives the Tier B gate: an entropy hit in prose is a
 * credential, and the same hit in source is usually a hash or an asset.
 */
export type TextClass = "prose" | "code"

/**
 * Tier A is an anchored provider format: AKIA..., ghp_..., PEM blocks.
 * Exact matches with no ambiguity, so they redact unconditionally.
 *
 * Tier B is entropy plus a keyword, which is what fires on unprefixed
 * values like bare .env entries. High false-positive rate on source
 * code, so it redacts in prose and only warns in code.
 */
export type Tier = "A" | "B"

export interface Finding {
  /** Stable detector identity, e.g. "aws-access-key-id". */
  readonly kind: string
  /** Inclusive start offset in the source string. */
  readonly start: number
  /** Exclusive end offset in the source string. */
  readonly end: number
  /** The matched text. Never persisted, never logged, never displayed. */
  readonly value: string
  readonly tier: Tier
  /**
   * Per-session HMAC of the value, truncated to 12 hex chars.
   * Equal values produce equal fingerprints within a session and
   * never across sessions.
   *
   * Absent on findings straight out of `detect()`, which has no session
   * to key against. Only `redact()` output carries a real fingerprint,
   * so only redact() output may be persisted or logged.
   */
  readonly fingerprint?: string
}

export interface Placeholder<T extends Finding = Finding> {
  readonly text: string
  readonly finding: T
}

export interface RedactionResult {
  /** The rewritten text. Identical to input when nothing was found. */
  readonly text: string
  /**
   * Findings that were actually replaced. Always session-fingerprinted, since
   * redact() is what applies the session key.
   */
  readonly redacted: readonly RedactedFinding[]
  /** Findings detected but deliberately left in place. Also fingerprinted. */
  readonly warned: readonly RedactedFinding[]
}

/** A Finding that has passed through a session scope and can be logged. */
export interface RedactedFinding extends Finding {
  readonly fingerprint: string
}

/** A single detector rule. Tier A entries must not use `entropy`. */
export interface Detector {
  readonly kind: string
  readonly tier: Tier
  readonly pattern: RegExp
  /**
   * Shannon entropy floor in bits per character. Applied after the
   * pattern matches. Required for Tier B, forbidden for Tier A.
   */
  readonly entropy?: number
}
