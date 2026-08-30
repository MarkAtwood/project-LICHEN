// ponytail: self-looping beads worker driver for an interactive TUI; gated by OPENCODE_BEADS_LOOP env
// .tsx extension (no JSX) so the server plugin auto-scan (*.ts,*.js) skips it — TUI-only module
import type { TuiPlugin } from "@opencode-ai/plugin/tui"

const id = "lichen-beads-loop"

const ROUND_PROMPT = `Continue the beads worker loop (instructions: scripts/beads-worker-full.txt).
Claim the next ready bead, complete it fully (tests, 3x codereview with findings filed as new beads, close, commit), then stop and report.
Exactly one bead this round.`

const NEW_SESSION_EVERY = 6
const MIN_ROUND_INTERVAL_MS = 30_000

const tui: TuiPlugin = async (api) => {
  const flag = process.env.OPENCODE_BEADS_LOOP
  if (!flag) return
  const worker = Number.parseInt(flag, 10) || 1
  const SETTLE_MS = 8000 + worker * 2000

  let running = false
  let rounds = 0
  let lastRoundAt = 0

  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

  function report(message: string, variant: "info" | "success" | "error" = "info") {
    api.ui.toast({ title: "beads-loop", message, variant })
    void api.client.app
      .log({ body: { service: "beads-loop", level: variant === "error" ? "error" : "info", message } })
      .catch(() => {})
  }

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
    lastRoundAt = Date.now()
    report(`round ${rounds} submitted (worker ${worker})`)
  }

  async function maybeRound(trigger: string) {
    if (running) return
    if (Date.now() - lastRoundAt < MIN_ROUND_INTERVAL_MS) return
    running = true
    try {
      await sleep(SETTLE_MS)
      const remaining = await readyCount()
      if (remaining === 0) {
        report("ready queue drained — worker loop done", "success")
        return
      }
      await runRound()
    } catch (error) {
      report(`${trigger} failed: ${error instanceof Error ? error.message : String(error)}`, "error")
    } finally {
      running = false
    }
  }

  api.event.on("session.idle", () => {
    void maybeRound("idle")
  })

  report(`active (worker ${worker}, settle ${SETTLE_MS}ms)`)
  setTimeout(() => {
    void maybeRound("kickoff")
  }, 3000 + worker * 1500)
}

export default { id, tui }
