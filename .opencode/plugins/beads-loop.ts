// ponytail: self-looping beads worker driver for an interactive TUI; gated by OPENCODE_BEADS_LOOP env
import type { TuiPlugin } from "@opencode-ai/plugin/tui"

const id = "lichen-beads-loop"

const ROUND_PROMPT = `Continue the beads worker loop (instructions: scripts/beads-worker-full.txt).
Claim the next ready bead, complete it fully (tests, 3x codereview with findings filed as new beads, close, commit), then stop and report.
Exactly one bead this round.`

const NEW_SESSION_EVERY = 6

const tui: TuiPlugin = async (api) => {
  const flag = process.env.OPENCODE_BEADS_LOOP
  if (!flag) return
  const worker = Number.parseInt(flag, 10) || 1
  const SETTLE_MS = 8000 + worker * 2000

  let armed = false
  let running = false
  let rounds = 0

  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

  async function readyCount(): Promise<number> {
    try {
      const proc = Bun.spawn(["bd", "ready", "--json"], {
        cwd: api.state.path.directory || process.cwd(),
        stdout: "pipe",
        stderr: "ignore",
      })
      const out = await new Response(proc.stdout).text()
      await proc.exited
      if (proc.exitCode !== 0) return 0
      const parsed: unknown = JSON.parse(out)
      return Array.isArray(parsed) ? parsed.length : 0
    } catch {
      return 0
    }
  }

  async function runRound() {
    rounds += 1
    if (rounds % NEW_SESSION_EVERY === 0) {
      await api.client.tui.executeCommand({ body: { command: "session.new" } })
      await sleep(1000)
    }
    await api.client.tui.appendPrompt({ body: { text: ROUND_PROMPT } })
    await api.client.tui.submitPrompt()
    armed = true
  }

  api.event.on("session.idle", async () => {
    if (!armed || running) return
    running = true
    armed = false
    try {
      await sleep(SETTLE_MS)
      const remaining = await readyCount()
      if (remaining === 0) {
        api.ui.toast({ title: "beads-loop", message: "ready queue drained — worker loop done", variant: "success" })
        return
      }
      await runRound()
    } catch (error) {
      api.ui.toast({
        title: "beads-loop",
        message: `round failed: ${error instanceof Error ? error.message : String(error)}`,
        variant: "error",
      })
    } finally {
      running = false
    }
  })

  setTimeout(() => {
    void (async () => {
      try {
        if ((await readyCount()) > 0) await runRound()
      } catch {}
    })()
  }, 3000 + worker * 1500)
}

export default { id, tui }
