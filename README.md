# frapast — interactive shell + UI upgrade

Drop-in files that give `frapast` a Claude-Code-style front end: a splash
banner on startup, a persistent `frapast ›` REPL with slash-commands,
arrow-key select menus, and live progress bars for scanning/proof
verification. Every existing command, flag, exit code, and JSON/YAML
output shape is unchanged — this only touches the human-facing terminal
output.

## Install

1. Copy these into your repo, preserving the paths:
   ```
   cli.py                    → overwrites your existing entrypoint
   scanner/ui/__init__.py    → new
   scanner/ui/theme.py       → new
   scanner/ui/banner.py      → new
   scanner/ui/progress.py    → new
   scanner/ui/menus.py       → new
   scanner/ui/results.py     → new
   scanner/ui/shell.py       → new
   ```
2. Add the new dependencies:
   ```
   pip install rich questionary prompt_toolkit pyfiglet
   ```
   - `rich` — you already used it optionally; it's now load-bearing for
     all human-formatted output (tables, banner, progress bars).
   - `questionary` / `prompt_toolkit` — power the arrow-key menus and the
     REPL's history + tab-completion. Both degrade gracefully to plain
     `input()` prompts if not installed, so nothing hard-crashes without
     them — you just lose the fancier interaction.
   - `pyfiglet` — renders the "FRAPAST" logo. Falls back to a hand-drawn
     ASCII banner if missing.

## What you get

- **`frapast`** with no arguments (in a real terminal) now opens the
  interactive shell instead of printing `--help`: a gradient logo panel,
  a "workspace" line, and a quick-start tip list, then a `frapast ›`
  prompt with command history (`~/.frapast_history`) and tab-completion.
  Piped/non-tty invocations (`frapast | cat`, CI, etc.) still get the old
  plain `--help` output — the shell never tries to read from a non-tty.
- **Shell commands**: `/scan <path>`, `/prove`, `/report`, `/fp-report`,
  `/help`, `/clear`, `/exit`. Typing a bare path (`.`, `../erpnext`) is
  shorthand for `/scan`. `/prove` with no flags re-uses the candidates
  from your last `/scan` in that session.
- **`frapast scan <path>`** (the existing one-shot command) is unchanged
  in behavior, but the old `[1]/[2]/[3]/[4]/[N]` text menu for choosing a
  proof-verification scope is now a real arrow-key select
  (`scanner/ui/menus.select_proof_scope`), and the raw `\r`-based
  "Scanning... [n/total]" progress line is now a proper spinner + bar
  (written to stderr, so `--format json | jq ...` piping is untouched).
- **Results table** (`scanner/ui/results.render_results`) adds a
  severity color legend and a one-line summary
  (`3 candidates · 1 critical · 1 high · 1 low`) instead of just a count.
- **`frapast shell [path]`** — explicit alias to launch the interactive
  shell with a repo pre-loaded, for discoverability from `--help`.
- Bonus fix: the `report` subcommand was defined in argparse and
  `render_track_record` was already imported, but `main()` never actually
  dispatched to it — it silently fell through to `--help`. That's wired
  up now (`frapast report` and the shell's `/report`).

## Notes on the rewrite

- `_scan_repo_with_severity`'s progress reporting moved from a manual
  `sys.stderr.write("\r...")` loop to `scanner.ui.progress.scan_progress`,
  but keeps the exact same `show_progress: bool` signature, so `scan()`
  and `scan_multi()` (your public API) are unaffected.
- The duplicated `_get_score` helper (previously defined once inline in
  `main()` and once in `_render_human_summary`) is now the single
  `scanner.ui.results.candidate_score`.
- All new color/style names live in `scanner/ui/theme.py`. If you add
  more `rich` markup elsewhere, note that Rich's theme only resolves a
  markup tag when the *entire* tag matches a registered key — `[bold
  accent]` won't pick up the `accent` color, so compound looks (e.g.
  "bold + accent") are registered as their own key (see `heading`,
  `tagline` in `theme.py`) rather than composed inline.

I built and exercised this against stubbed versions of your `scanner.*`
modules (matching the imports/signatures already in `cli.py`) in a real
pty via `pexpect` — banner render, `/scan`, `/prove` with the arrow-key
menu, `/report`, `/fp-report`, unknown-command handling, and `/exit` all
verified end-to-end. I don't have your actual repo, so I couldn't run it
against your real rule/proof engine — worth a quick smoke test on your
side before you rely on it.
