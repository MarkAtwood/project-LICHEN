// ponytail: self-looping beads worker driver for an interactive TUI; gated by OPENCODE_BEADS_LOOP env
// .tsx extension (no JSX) so the server plugin auto-scan (*.ts,*.js) skips it — TUI-only module
import type { TuiPlugin } from "@opencode-ai/plugin/tui"

const id = "lichen-beads-loop"

// Round prompt lives in a file the launcher copies fresh into each worktree:
// editing scripts/beads-worker-round.txt changes the next round with no restart.
const ROUND_PROMPT_FILE = "scripts/beads-worker-round.txt"
const ROUND_PROMPT_FALLBACK = `Continue the beads worker loop (instructions: scripts/beads-worker-full.txt).
Claim the next ready bead, complete it fully (tests, 3x codereview with findings filed as new beads, close, commit), then stop and report.
Exactly one bead this round.`

async function roundPrompt(cwd: string): Promise<string> {
  try {
    const text = await Bun.file(`${cwd}/${ROUND_PROMPT}`).text()
    if (text.trim()) return text
  } catch {}
  return ROUND_PROMPT
}

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

  // File-based debug trace: survives TUI restarts, readable without the TUI.
  const TRACE = `${process.env.HOME || ""}/Developer/fleet-debug.log`
  function trace(message: string) {
    try {
      Bun.appendSync(TRACE, `${new Date().toISOString()} worker${worker}: ${message}\n`)
    } catch {}
  }

  function report(message: string, variant: "info" | "success" | "error" = "info") {
    api.ui.toast({ title: "beads-loop", message, variant })
    void api.client.app
      .log({ service: "beads-loop", level: variant === "error" ? "error" : "info", message })
      .catch(() => {})
  }

  async function readyCount(): Promise<number> {
    try {
      const cwd = api.state.path.directory || process.cwd()
      const proc = Bun.spawn(["bd", "ready", "--json"], {
        cwd,
        stdout: "pipe",
        stderr: "pipe",
      })
      const out = await new Response(proc.stdout).text()
      const err = await new Response(proc.stderr).text()
      await proc.exited
      trace(`readyCount cwd=${cwd} exit=${proc.exitCode} err=${err.slice(0, 120).replace(/\n/g, " ")}`)
      if (proc.exitCode !== 0) return 0
      const parsed: unknown = JSON.parse(out)
      return Array.isArray(parsed) ? parsed.length : 0
    } catch (error) {
      trace(`readyCount threw: ${error instanceof Error ? error.message : String(error)}`)
      return 0
    }
  }

  async function runRound() {
    rounds += 1
    if (rounds % NEW_SESSION_EVERY === 0) {
      await api.client.tui.executeCommand({ command: "session.new" })
      await sleep(1000)
    }
    const prompt = await roundPrompt(api.state.path.directory || process.cwd())
    trace(`round ${rounds}: submitting ${prompt.length} chars`)
    await api.client.tui.appendPrompt({ text: prompt })
    await api.client.tui.submitPrompt()
    lastRoundAt = Date.now()
    report(`round ${rounds} submitted (worker ${worker})`)
  }

  async function maybeRound(trigger: string) {
    if (running) {
      trace(`${trigger}: skipped, already running`)
      return
    }
    if (Date.now() - lastRoundAt < MIN_ROUND_INTERVAL_MS) {
      trace(`${trigger}: skipped, min interval`)
      return
    }
    running = true
    try {
      await sleep(SETTLE_MS)
      const remaining = await readyCount()
      trace(`${trigger}: remaining=${remaining}`)
      if (remaining === 0) {
        report("ready queue drained — worker loop done", "success")
        return
      }
      await runRound()
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      trace(`${trigger} FAILED: ${message}`)
      report(`${trigger} failed: ${message}`, "error")
    } finally {
      running = false
    }
  }

  api.event.on("session.idle", () => {
    void maybeRound("idle")
  })

  report(`active (worker ${worker}, settle ${SETTLE_MS}ms)`)
  trace("plugin activated, kickoff scheduled")
  setTimeout(() => {
    void maybeRound("kickoff")
  }, 3000 + worker * 1500)
}

export default { id, tui }
