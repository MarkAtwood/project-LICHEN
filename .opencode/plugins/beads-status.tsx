/** @jsxImportSource @opentui/solid */
// ponytail: single-file TUI slot plugin; shows THIS session's claimed bead in the sidebar footer
import type { TuiPlugin } from "@opencode-ai/plugin/tui"
import { For, Show, createSignal, onCleanup } from "solid-js"

type Bead = {
  id: string
  title: string
  status?: string
  updated_at?: string
}

const POLL_MS = 4000
const MAP_TTL_MS = 24 * 60 * 60 * 1000
const MAX_SHOWN = 3

function key(value: string) {
  return value.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 120)
}

function truncated(text: string, max: number) {
  return text.length > max ? text.slice(0, max - 1) + "…" : text
}

const id = "lichen-beads-status"

const tui: TuiPlugin = async (api) => {
  const [beads, setBeads] = createSignal<Bead[]>([])

  async function poll() {
    try {
      const dir = api.state.path.directory || process.cwd()
      const proc = Bun.spawn(["bd", "list", "--status=in_progress", "--json"], {
        cwd: dir,
        stdout: "pipe",
        stderr: "ignore",
      })
      const out = await new Response(proc.stdout).text()
      await proc.exited
      if (proc.exitCode !== 0) {
        setBeads([])
        return
      }
      const parsed: unknown = JSON.parse(out)
      if (!Array.isArray(parsed)) {
        setBeads([])
        return
      }
      const open = parsed.filter(
        (item): item is Bead =>
          !!item && typeof item === "object" && (item as Bead).status === "in_progress" && !!(item as Bead).id,
      )
      setBeads(open)
    } catch {
      setBeads([])
    }
  }

  const timer = setInterval(poll, POLL_MS)
  api.lifecycle.onDispose(() => clearInterval(timer))
  void poll()

  async function sessionBead(sessionID: string): Promise<string | undefined> {
    if (!sessionID) return undefined
    try {
      const dir = api.state.path.directory || process.cwd()
      const file = `${key(dir)}--${key(sessionID)}.json`
      const home = process.env.HOME || process.env.USERPROFILE || ""
      const path = `${home}/.local/share/opencode/beads-status/${file}`
      const text = await Bun.file(path).text()
      const map: unknown = JSON.parse(text)
      if (!map || typeof map !== "object") return undefined
      const bead = (map as { bead?: unknown; at?: unknown }).bead
      const at = (map as { at?: unknown }).at
      if (typeof bead !== "string" || typeof at !== "number") return undefined
      if (Date.now() - at > MAP_TTL_MS) return undefined
      return bead
    } catch {
      return undefined
    }
  }

  api.slots.register({
    order: 500,
    slots: {
      sidebar_footer(_ctx, props) {
        const [mapped, setMapped] = createSignal<string | undefined>(undefined)
        const refreshMapped = async () => setMapped(await sessionBead(props.session_id))
        const mapTimer = setInterval(refreshMapped, POLL_MS)
        onCleanup(() => clearInterval(mapTimer))
        void refreshMapped()
        return (
          <Show when={beads().length > 0 && mapped()}>
            <box>
              <For each={beads().filter((bead) => mapped() === bead.id).slice(0, MAX_SHOWN)}>
                {(bead) => (
                  <box flexDirection="row" gap={0}>
                    <text flexShrink={0} style={{ fg: api.theme.current.warning }}>
                      [•]{" "}
                    </text>
                    <text flexShrink={0} style={{ fg: api.theme.current.text }}>
                      {truncated(bead.id, 28)}{" "}
                    </text>
                    <text flexGrow={1} wrapMode="word" style={{ fg: api.theme.current.textMuted }}>
                      {truncated(bead.title, 60)}
                    </text>
                  </box>
                )}
              </For>
            </box>
          </Show>
        )
      },
    },
  })
}

export default { id, tui }
