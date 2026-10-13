// Model-free drive of the real plugin: loads src/plugin.ts, lets it register its
// hooks against a stand-in `ctx`, then fires the same events OpenCode fires and
// checks what the plugin did to them. Only the host is faked; every line of the
// plugin and detectors is the real working tree.
//
// usage: bun run drive-hooks.ts <sandbox-dir> <evidence-dir>
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"
import { randomBytes } from "node:crypto"

const [sandbox, evidence] = process.argv.slice(2)
if (!sandbox || !evidence) throw new Error("usage: drive-hooks.ts <sandbox-dir> <evidence-dir>")

// The plugin resolves its audit log from homedir() when imported. Bun ignores a
// HOME assigned at runtime, so redactor-verify.sh launches this with HOME already
// set. Refuse to continue otherwise: this run would write to the user's real log.
if (homedir() !== join(sandbox, "home")) {
  throw new Error(`homedir() is ${homedir()}, not the sandbox home; run via redactor-verify.sh hooks`)
}
const auditPath = join(sandbox, "home", ".local", "share", "opencode", "redactor-audit.log")
mkdirSync(join(sandbox, "home", ".local", "share", "opencode"), { recursive: true })

const out = join(evidence, "hooks")
mkdirSync(out, { recursive: true })

const alnum = (n: number) =>
  randomBytes(n * 2).toString("base64").replace(/[^A-Za-z0-9]/g, "").slice(0, n)
const PAT = `ghp_${alnum(36)}` // fabricated GitHub PAT shape (Tier A)
const ENV_SECRET = alnum(32) // fabricated value for a bare .env assignment (Tier B)

type Handler = (event: any) => unknown
const hooks = new Map<string, Handler>()
const plugin = (await import(join(process.cwd(), "src", "plugin.ts"))).default
await plugin.setup({
  event: { subscribe: async function* () {} },
  session: { hook: async (name: string, fn: Handler) => void hooks.set(`session.${name}`, fn) },
  tool: { hook: async (name: string, fn: Handler) => void hooks.set(`tool.${name}`, fn) },
  app: { version: "verify-harness" },
  location: { directory: sandbox },
})
const fire = async (name: string, event: any) => {
  const h = hooks.get(name)
  if (!h) throw new Error(`plugin never registered ${name}`)
  await h(event)
  return event
}

const log: string[] = []
let failed = 0
const check = (name: string, ok: boolean, detail = "") => {
  if (!ok) failed++
  log.push(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? `  -- ${detail}` : ""}`)
}
const PLACEHOLDER = /\[REDACTED:([a-z0-9-]+)#(\d+):([0-9a-f]{12})\]/

// prompt: Tier A credential in user input is rewritten before persistence.
const p1 = await fire("session.prompt", {
  sessionID: "s1",
  prompt: { text: `please use this token ${PAT} for the deploy` },
})
check("prompt: Tier A value removed", !p1.prompt.text.includes(PAT), p1.prompt.text)
check("prompt: typed placeholder inserted", /\[REDACTED:github-pat#1:[0-9a-f]{12}\]/.test(p1.prompt.text))
check("prompt: surrounding text preserved", p1.prompt.text.startsWith("please use this token ") && p1.prompt.text.endsWith(" for the deploy"))

// same credential twice in one session -> same placeholder; idempotent.
const p2 = await fire("session.prompt", { sessionID: "s1", prompt: { text: `again: ${PAT}` } })
const ph1 = p1.prompt.text.match(PLACEHOLDER)?.[0]
const ph2 = p2.prompt.text.match(PLACEHOLDER)?.[0]
check("session: same credential -> same placeholder", !!ph1 && ph1 === ph2, `${ph1} vs ${ph2}`)
const p3 = await fire("session.prompt", { sessionID: "s1", prompt: { text: p1.prompt.text } })
check("idempotent: redacting redacted text changes nothing", p3.prompt.text === p1.prompt.text)

// different session -> different fingerprint (no cross-history correlation).
const p4 = await fire("session.prompt", { sessionID: "s2", prompt: { text: `token ${PAT}` } })
const fp = (s: string) => s.match(PLACEHOLDER)?.[3]
check("session: other session gets a different fingerprint", !!fp(p4.prompt.text) && fp(p4.prompt.text) !== fp(p1.prompt.text))

// tool output: every string in the result is rewritten, nested ones included.
const tool = await fire("tool.execute.after", {
  sessionID: "s1",
  status: "completed",
  result: {
    output: `GITHUB_TOKEN=${PAT}\n`,
    content: [{ type: "text", text: `GITHUB_TOKEN=${PAT}\n` }],
    metadata: { deep: { raw: PAT } },
  },
})
const serialized = JSON.stringify(tool.result)
check("tool output: no raw credential anywhere in result", !serialized.includes(PAT), serialized)
check("tool output: result.content rewritten (what the host persists)", PLACEHOLDER.test(tool.result.content[0].text))

// Tier B: bare .env assignment redacts in prose; same text inside source only warns.
const envText = `NAME=demo\nDATABASE_PASSWORD=${ENV_SECRET}\n`
const t2 = await fire("tool.execute.after", { sessionID: "s1", status: "completed", result: { output: envText, content: [{ type: "text", text: envText }] } })
check("Tier B in .env prose: redacted", !t2.result.output.includes(ENV_SECRET), t2.result.output)
const codeText = ["import os", "def load():", `    password = "${ENV_SECRET}"`, "    return os.environ", "", "class A:", "    pass"].join("\n")
const t3 = await fire("tool.execute.after", { sessionID: "s1", status: "completed", result: { output: codeText, content: [{ type: "text", text: codeText }] } })
check("Tier B in source: left alone (warn only)", t3.result.output.includes(ENV_SECRET))

// system prompt text parts.
const sys = await fire("session.context", { sessionID: "s1", system: [{ text: `You may use ${PAT}` }, { text: "no secrets" }], tools: [] })
check("system prompt: credential removed", !sys.system[0].text.includes(PAT))
check("system prompt: clean part untouched", sys.system[1].text === "no secrets")

// tool input: observed in the audit log, never rewritten.
const before = { sessionID: "s1", input: { command: `curl -H "Authorization: token ${PAT}"` } }
await fire("tool.execute.before", before)
check("tool input: not rewritten", JSON.stringify(before.input).includes(PAT))

// failed tool call is ignored.
const failedTool = await fire("tool.execute.after", { sessionID: "s1", status: "failed", result: { output: PAT } })
check("failed tool call: untouched", failedTool.result.output === PAT)

// audit log: metadata only, mode 600, records every channel.
const audit = existsSync(auditPath) ? readFileSync(auditPath, "utf8") : ""
check("audit log exists", audit.length > 0, auditPath)
check("audit log: never contains a value", !audit.includes(PAT) && !audit.includes(ENV_SECRET))
for (const ch of ["prompt", "system", "tool-output", "tool-input"]) {
  check(`audit log: channel=${ch} recorded`, audit.includes(`channel=${ch} `))
}
check("audit log: tool-input recorded as observed", /channel=tool-input action=observed/.test(audit))
check("audit log: Tier B in source recorded as warned", /action=warned tier=B/.test(audit))
check("audit log: mode 600", existsSync(auditPath) && (statSync(auditPath).mode & 0o777) === 0o600)

writeFileSync(join(out, "result.txt"), log.join("\n") + "\n")
writeFileSync(join(out, "audit.log"), audit)
console.log(log.join("\n"))
console.log(`\n${failed === 0 ? "ALL PASS" : `${failed} FAILED`}  (evidence: ${out})`)
process.exit(failed === 0 ? 0 : 1)
