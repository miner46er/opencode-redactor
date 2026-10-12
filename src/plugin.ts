import { Plugin } from "@opencode/plugin"
import { appendFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"
import { redact } from "./redact"
import { createPlaceholderRegistry } from "./session"
import type { RedactionResult, Surface } from "./shape"

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
  readonly surface: Surface
  readonly kind: string
  readonly tier: "A" | "B"
  readonly fingerprint: string
  readonly offset: number
  readonly action: "redacted" | "warned"
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
        `${new Date().toISOString()} surface=${r.surface} action=${r.action} tier=${r.tier} kind=${r.kind} fp=${r.fingerprint} offset=${r.offset}`,
    )
    .join("\n")
  try {
    appendFileSync(AUDIT_LOG, `${lines}\n`, { mode: 0o600 })
  } catch {
    // An unwritable audit log must not block the session.
  }
}

function toRecords(surface: Surface, result: RedactionResult): AuditRecord[] {
  const redacted = result.redacted.map(
    (f): AuditRecord => ({
      surface,
      kind: f.kind,
      tier: f.tier,
      fingerprint: f.fingerprint,
      offset: f.start,
      action: "redacted",
    }),
  )
  const warned = result.warned.map(
    (f): AuditRecord => ({
      surface,
      kind: f.kind,
      tier: f.tier,
      fingerprint: f.fingerprint,
      offset: f.start,
      action: "warned",
    }),
  )
  return [...redacted, ...warned]
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
        const result = redact(text, "prose", registry.for(event.sessionID))
        if (result.text !== text) {
          event.prompt.text = result.text
          audit(toRecords("prompt", result))
        }
      } catch (error) {
        process.stderr.write(`[redactor] prompt pass failed, sending unscanned: ${String(error)}\n`)
      }
    })

    await ctx.tool.hook("execute.after", (event) => {
      if (event.status !== "completed" || !event.result) return
      try {
        const surface: Surface = isCodeish(JSON.stringify(event.result).slice(0, 4000)) ? "code" : "prose"
        const scope = registry.for(event.sessionID)
        const records: AuditRecord[] = []
        walkStrings(event.result, (text) => {
          if (text.length === 0) return text
          const result = redact(text, surface, scope)
          if (result.text !== text) records.push(...toRecords(surface, result))
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
        const result = redact(input, "prose", registry.for(event.sessionID))
        if (result.warned.length > 0 || result.redacted.length > 0) {
          audit(toRecords("tool", result))
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
