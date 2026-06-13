---
name: bd
description: Interface with the beads (bd) issue tracker for this repo. Use when the user wants to find, view, claim, create, update, or close issues, or sync the tracker. Wraps the ready→claim→work→close loop and the session-close sync. Invoke for any "what should I work on", "show me issue X", "file an issue", "close that", or "sync beads" request.
---

# Beads (bd) issue workflow

This repo tracks all work in **beads**. Issues live in a local Dolt DB; `.beads/issues.jsonl` is a passive export. Never hand-edit `issues.jsonl` — always go through `bd`.

## Preflight

If any `bd` call returns `command not found`, stop and tell the user to install it (see the install steps in the project README / CLAUDE.md). Do not fall back to editing `issues.jsonl` directly.

## The daily loop

1. **Find work** — `bd ready` (lists unblocked, open issues by priority). Use `bd list --status open` for the full backlog.
2. **Inspect** — `bd show <id>` before starting, to read description + dependencies.
3. **Claim** — `bd update <id> --claim` (sets status in_progress, assigns you).
4. **Do the work** — make the code change.
5. **Close** — `bd close <id> --reason "<what you did>"`. Always write a concrete close reason: the fix, the files touched, and how it was verified.

## Creating issues

`bd create "<title>" --type <bug|feature|task|chore> -p <0-3> -d "<description>"`

- Set a priority (`-p 0` highest). File follow-up issues for anything discovered mid-task rather than letting it slip.
- Link dependencies with `bd dep add <blocked-id> <blocker-id>`.

## Syncing (session close)

The tracker is git-native via `refs/dolt/data`. At the end of a work session, after closing/updating issues:

```bash
bd dolt push      # pushes issue DB changes to the remote (NOT auto-allowed — will prompt)
```

This is the outward-facing step, so it intentionally requires confirmation. Do it as part of the mandatory session-close workflow in CLAUDE.md (alongside `git push`).

## Persistent knowledge

Use `bd remember "<fact>"` for durable project knowledge — per CLAUDE.md, do NOT use MEMORY.md files for this project.

## Notes

- Run `bd prime` once per session for the full command reference (the SessionStart hook already does this).
- Read-only and common-mutation commands (`ready`, `show`, `list`, `create`, `update`, `close`, `dep add`, `remember`) are pre-allowed in `.claude/settings.local.json` and won't prompt. `bd dolt push` will prompt by design.
