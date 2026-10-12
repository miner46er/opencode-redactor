import { Plugin } from "@opencode/plugin"
import { appendFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"
import { redact } from "./redact"
import { createPlaceholderRegistry } from "./session"
import type { Channel, RedactedFinding, RedactionResult, TextClass } from "./shape"

/**
 * Redacts credentials from OpenCode traffic before it reaches a model.
 *
 * Two surfaces are rewritten. User input is redacted at `prompt`, which the
 * host treats as canonical persisted input. Tool output is redacted at
 * `tool.execute.after`, where the persisted message block stores
 * `state.content` derived from `result.content`.
 *
 * `result.output` is mutated too, because it feeds the outgoing request, but
 * mutating it alone leaves the raw value in session history. See README.
 *
 * Tool input is scanned and reported but never rewritten. A secret in tool
 * input came from the model hallucinating one or from the user typing a
 * command directly, and rewriting either silently corrupts a command that
 * was deliberately issued.
 */

const AUDIT_LOG = join(homedir(), ".local", "share", "opencode", "redactor-audit.log")

interface AuditRecord {
  readonly channel: Channel
  readonly kind: string
  readonly tier: "A" | "B"
  readonly fingerprint: string
  readonly offset: number
  /** What actually happened to the text. "observed" means nothing was changed. */
  readonly action: "redacted" | "warned" | "observed"
}

/**
 * Metadata only. The value is never written, so this log is safe to keep and
 * impossible to mine for credentials.
 */
function audit(records: readonly AuditRecord[]): void {
  if (records.length === 0) return
  const lines = records
    .map(
      (r) =>
        `${new Date().toISOString()} channel=${r.channel} action=${r.action} tier=${r.tier} kind=${r.kind} fp=${r.fingerprint} offset=${r.offset}`,
    )
    .join("\n")
  try {
    appendFileSync(AUDIT_LOG, `${lines}\n`, { mode: 0o600 })
  } catch (error) {
    // An unwritable audit log must not block the session, but the findings it
    // was meant to record are then invisible, so say so rather than swallow it.
    process.stderr.write(`[redactor] could not write the audit log: ${String(error)}\n`)
  }
}

function record(
  channel: Channel,
  action: AuditRecord["action"],
  finding: RedactedFinding,
): AuditRecord {
  return {
    channel,
    action,
    kind: finding.kind,
    tier: finding.tier,
    fingerprint: finding.fingerprint,
    offset: finding.start,
  }
}

function toRecords(channel: Channel, result: RedactionResult): AuditRecord[] {
  return [
    ...result.redacted.map((f) => record(channel, "redacted", f)),
    ...result.warned.map((f) => record(channel, "warned", f)),
  ]
}

/**
 * Rewrites every string reachable from `value`, in place.
 *
 * The host persists `result.content` and derives the stored block from it, so
 * an in-place walk over the whole result is what makes redaction durable. A
 * depth cap stops a cyclic or pathologically deep object from hanging the hook.
 */
function walkStrings(value: unknown, apply: (s: string) => string, depth = 0): void {
  if (depth > 12 || value === null || typeof value !== "object") return
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    if (typeof entry === "string") {
      const next = apply(entry)
      if (next !== entry) (value as Record<string, unknown>)[key] = next
    } else if (entry !== null && typeof entry === "object") {
      walkStrings(entry, apply, depth + 1)
    }
  }
}

/** Tool output that looks like source is held to a stricter bar than prose. */
function isCodeish(text: string): boolean {
  const lines = text.split("\n", 40)
  let code = 0
  for (const line of lines) {
    if (/^\s*[.#/]|=>|function |const |let |var |import |export |def |class |<\/?[a-z]/i.test(line)) code++
  }
  return lines.length > 0 && code / lines.length > 0.3
}

export default Plugin.define({
  id: "opencode-redactor",
  async setup(ctx) {
    // The host scopes a plugin instance to a directory, not a conversation, so
    // the registry keys scopes by session ID. Sharing one scope across
    // conversations would give the same credential the same fingerprint in two
    // histories, which is the correlation the fingerprint exists to prevent.
    const registry = createPlaceholderRegistry()

    // Releasing on delete drops the conversation's fingerprint key, so a stored
    // history cannot be checked against this process later. The subscription is
    // an async iterable and is closed automatically when the plugin unloads.
    void (async () => {
      for await (const event of ctx.event.subscribe()) {
        if (event.type === "session.deleted") {
          registry.release(event.data.sessionID)
        }
      }
    })()

    await ctx.session.hook("prompt", (event) => {
      const text = event.prompt?.text
      if (typeof text !== "string" || text.length === 0) return
      try {
        // A pasted file is code even though it arrived as chat, and the Tier B
        // gate exists to keep source readable.
        const classification: TextClass = isCodeish(text) ? "code" : "prose"
        const result = redact(text, classification, registry.for(event.sessionID))
        if (result.text !== text) {
          event.prompt.text = result.text
          audit(toRecords("prompt", result))
        }
      } catch (error) {
        process.stderr.write(`[redactor] prompt pass failed, sending unscanned: ${String(error)}\n`)
      }
    })

    // The system prompt carries agent instructions, skills and MCP tool
    // descriptions, so a secret written into any of them would otherwise reach
    // the provider on every turn. Only the text parts are rewritten: `tools` is
    // deliberately left alone, since editing a tool description breaks the
    // contract the model relies on to call it. Messages need no pass here,
    // because history was already redacted before it was persisted.
    await ctx.session.hook("context", (event) => {
      try {
        const scope = registry.for(event.sessionID)
        for (const part of event.system) {
          if (typeof part.text !== "string" || part.text.length === 0) continue
          const result = redact(part.text, "prose", scope)
          if (result.text !== part.text) {
            // SystemPart.text is typed readonly, but the host builds the request
            // from this object after the hook returns. Verified against 2.0.27:
            // a canary written here is what the model then reads back.
            ;(part as { text: string }).text = result.text
            audit(toRecords("system", result))
          }
        }
      } catch (error) {
        process.stderr.write(`[redactor] system prompt pass failed, sending unscanned: ${String(error)}\n`)
      }
    })

    await ctx.tool.hook("execute.after", (event) => {
      if (event.status !== "completed" || !event.result) return
      try {
        const text: TextClass = isCodeish(JSON.stringify(event.result).slice(0, 4000)) ? "code" : "prose"
        const scope = registry.for(event.sessionID)
        const records: AuditRecord[] = []
        walkStrings(event.result, (value) => {
          if (value.length === 0) return value
          const result = redact(value, text, scope)
          if (result.text !== value) records.push(...toRecords("tool-output", result))
          return result.text
        })
        audit(records)
      } catch (error) {
        process.stderr.write(`[redactor] tool pass failed, sending unscanned: ${String(error)}\n`)
      }
    })

    await ctx.tool.hook("execute.before", (event) => {
      // Observed only. See the module comment for why input is never rewritten.
      try {
        const input = JSON.stringify(event.input ?? {})
        if (input.length === 0) return
        // Nothing is rewritten here, so every finding is recorded as observed.
        // Reporting these as redacted would make the log claim work that never
        // happened, which is worse than logging nothing.
        const result = redact(input, "prose", registry.for(event.sessionID))
        const observed = [...result.redacted, ...result.warned]
        if (observed.length > 0) {
          audit(observed.map((f) => record("tool-input", "observed", f)))
        }
      } catch (error) {
        process.stderr.write(`[redactor] tool input scan failed: ${String(error)}\n`)
      }
    })

    process.stderr.write(
      `[redactor] active on ${ctx.app?.version ?? "unknown"} at ${ctx.location?.directory ?? "."}\n`,
    )
  },
})
