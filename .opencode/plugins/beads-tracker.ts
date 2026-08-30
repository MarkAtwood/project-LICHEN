// ponytail: records which bead each opencode session claimed, for beads-status TUI plugin
import { mkdir, readFile, rm, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { homedir } from "node:os"

function key(value: string) {
  return value.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 120)
}

const id = "lichen-beads-tracker"

const server = async (input: { directory: string }) => {
  const mapDir = join(homedir(), ".local", "share", "opencode", "beads-status")
  const fileFor = (sessionID: string) => join(mapDir, `${key(input.directory)}--${key(sessionID)}.json`)

  return {
    "tool.execute.before": async (hookInput: { tool: string; sessionID: string }, output: { args: any }) => {
      if (hookInput.tool !== "bash") return
      const command = typeof output.args?.command === "string" ? output.args.command : ""
      if (!/\bbd\s+/.test(command)) return

      const claims = [
        ...command.matchAll(/\bbd\s+update\s+(?:(\S+)[^\n;]*?--claim\b|--claim\s+(\S+))/g),
      ]
      const closes = [...command.matchAll(/\bbd\s+close\s+(\S+)/g)]
      if (!claims.length && !closes.length) return

      try {
        await mkdir(mapDir, { recursive: true })
        const file = fileFor(hookInput.sessionID)
        for (const close of closes) {
          try {
            const current = JSON.parse(await readFile(file, "utf8"))
            if (current?.bead === close[1]) await rm(file, { force: true })
          } catch {}
        }
        const last = claims.at(-1)
        if (last) {
          const bead = last[1] || last[2]
          await writeFile(file, JSON.stringify({ bead, at: Date.now() }), "utf8")
        }
      } catch {}
    },
  }
}

export default { id, server }
