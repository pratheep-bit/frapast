"""scanner/ui/flow.py — Clean linear flow controller for frapast.

This module owns the UX pipeline:
  Step 1 — Scan         (caller does this and passes candidates in)
  Step 2 — Ask count    (ask_proof_count)
  Step 3 — Prove        (run_proof_pipeline)
  Step 4 — Summary      (show_proof_summary)
  Step 5 — Post-menu    (post_proof_menu)

Design rules:
- No argparse, no sys.argv — pure UX logic.
- All I/O goes through Rich console or plain input().
- Every function is independently testable.
- The web server calls the same functions via a thin adapter.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from scanner.ui.theme import console


# ---------------------------------------------------------------------------
# Proof summary dataclass
# ---------------------------------------------------------------------------


@dataclass
class ProofSummary:
    total: int = 0
    proven: int = 0
    refuted: int = 0
    skipped: int = 0
    errors: int = 0
    proven_findings: list[dict] = field(default_factory=list)

    @property
    def proven_pct(self) -> float:
        return (self.proven / self.total * 100) if self.total else 0.0


# ---------------------------------------------------------------------------
# Step 2 — Ask how many to prove
# ---------------------------------------------------------------------------


def ask_proof_count(total: int) -> int | str:
    """Prompt the user to choose how many candidates to prove.

    Returns:
        int  — exact count (e.g. 10, 20)
        "all" — prove everything
        "skip" — user wants to skip proof entirely
    """
    console.print()
    console.print(
        f"[bold cyan]How many of the [white]{total}[/white] findings do you want to prove?[/bold cyan]\n"
        "  Enter a number (e.g. [bold]10[/bold], [bold]20[/bold], [bold]50[/bold]),\n"
        "  [bold]all[/bold] to prove everything, or [bold]skip[/bold] to quit proof.\n"
    )
    try:
        raw = input("  Prove count ❯ ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[muted]skipped.[/muted]")
        return "skip"

    if not raw or raw in ("s", "skip", "n", "no", "q"):
        return "skip"
    if raw in ("a", "all"):
        return "all"
    if raw.isdigit():
        n = int(raw)
        if n <= 0:
            return "skip"
        return min(n, total)
    # Fallback — treat any non-numeric as skip
    console.print(f"[muted]'{raw}' not recognised — skipping proof.[/muted]")
    return "skip"


# ---------------------------------------------------------------------------
# Step 3 — Run the proof pipeline
# ---------------------------------------------------------------------------


def run_proof_pipeline(
    candidates: list[dict],
    count: int | str,
    repo: Path,
    repo_id: str,
    *,
    bench_url: str = "",
    bench_user: str = "",
    bench_password: str = "",
    bench_site: str = "",
    findings_dir: Path | None = None,
) -> ProofSummary:
    """Select a slice of candidates, run Tier 1 + Tier 2 proof, return summary.

    Args:
        candidates:  Full sorted candidate list (highest severity first).
        count:       int = prove that many, "all" = prove all, "skip" = noop.
        repo:        Repo root path.
        repo_id:     Repo identifier string.
        bench_url:   Optional Tier 2 bench URL.
        ...          Other bench params forwarded to ProofOrchestrator.
        findings_dir: If set, writes results to ledger YAML.

    Returns:
        ProofSummary with counts and the list of proven findings.
    """
    from dataclasses import replace as dc_replace
    from scanner.proof.models import ProofStatus
    from scanner.proof.orchestrator import ProofOrchestrator
    from scanner.ui.results import candidate_score
    from scanner.cli import _finding_id, _candidate_repo_id
    from scanner.ledger_io import update_ledger_after_proof
    from scanner import ui

    summary = ProofSummary()

    if count == "skip" or not candidates:
        return summary

    sorted_cands = sorted(candidates, key=candidate_score, reverse=True)
    if isinstance(count, int):
        slice_ = sorted_cands[:count]
    else:
        slice_ = sorted_cands

    summary.total = len(slice_)

    orchestrator = ProofOrchestrator(
        workspace_root=repo,
        bench_url=bench_url,
        bench_user=bench_user,
        bench_password=bench_password,
        bench_site_name=bench_site,
    )

    from scanner.ledger_io import update_ledger_after_proof, index_ledger_entries
    ledger_index = index_ledger_entries(findings_dir) if findings_dir is not None else None

    with ui.proof_progress(len(slice_), "Proving findings") as advance:
        for c in slice_:
            rule_id = c.get("rule_id", "")
            func = c.get("function", "")
            loc_hash = str(c.get("code_location_hash", ""))
            crid = _candidate_repo_id(c, repo_id)
            fid = _finding_id(c, crid)
            c["id"] = fid

            res = orchestrator.prove_candidate(fid, candidate_data=c)
            if loc_hash:
                res = dc_replace(res, code_location_hash=loc_hash)

            c["proof_status"] = getattr(res.status, "value", str(res.status))
            c["proof_error"] = res.error_message
            advance(f"{rule_id} in {func}")

            if findings_dir is not None:
                update_ledger_after_proof(findings_dir, res, _index=ledger_index)

            if res.status == ProofStatus.PASSED:
                c["proof_tier"] = res.proof_tier
                c["status"] = "proven"
                summary.proven += 1
                summary.proven_findings.append(c)
            elif res.status in (ProofStatus.FAILED,):
                summary.refuted += 1
            elif res.status == ProofStatus.SKIPPED:
                summary.skipped += 1
            elif res.status == ProofStatus.ERROR:
                summary.errors += 1

    return summary


# ---------------------------------------------------------------------------
# Step 4 — Show proof summary
# ---------------------------------------------------------------------------


def show_proof_summary(summary: ProofSummary) -> None:
    """Render a compact, colourful proof result panel."""
    from rich.panel import Panel
    from rich.text import Text

    if summary.total == 0:
        console.print("[muted]No findings were verified.[/muted]\n")
        return

    lines: list[str] = []
    lines.append(f"[bold]Findings verified:[/bold] [white]{summary.total}[/white]")

    if summary.proven:
        lines.append(f"  ✅ [bold green]PROVEN[/bold green]   {summary.proven}  ({summary.proven_pct:.0f}%)")
    if summary.refuted:
        lines.append(f"  ❌ [bold red]REFUTED[/bold red]  {summary.refuted}")
    if summary.skipped:
        lines.append(f"  ⏭  [muted]SKIPPED  {summary.skipped} (bench offline or no strategy)[/muted]")
    if summary.errors:
        lines.append(f"  ⚠️  [bold yellow]ERRORS[/bold yellow]   {summary.errors}")

    if summary.proven_findings:
        lines.append("")
        lines.append("[bold]Top proven findings:[/bold]")
        for i, c in enumerate(summary.proven_findings[:5], 1):
            tier = c.get("proof_tier", "?")
            lines.append(
                f"  [bold yellow]#{i}[/bold yellow] [{c.get('rule_id','')}] "
                f"[cyan]{c.get('file','')}:{c.get('line','')}[/cyan]  "
                f"[dim](Tier {tier})[/dim]"
            )
        if len(summary.proven_findings) > 5:
            lines.append(f"  [muted]… and {len(summary.proven_findings) - 5} more[/muted]")

    panel = Panel(
        "\n".join(lines),
        title="[bold]Proof Results[/bold]",
        border_style="green" if summary.proven else "yellow",
        padding=(1, 2),
    )
    console.print()
    console.print(panel)
    console.print()


# ---------------------------------------------------------------------------
# Step 5 — Post-proof menu
# ---------------------------------------------------------------------------


def post_proof_menu(
    repo: Path,
    candidates: list[dict],
    summary: ProofSummary,
    *,
    web_available: bool = False,
) -> str:
    """Show the post-proof action menu and return the chosen action key.

    Returns one of:
        "export_json" | "view_bug" | "report" | "open_web" | "rescan" | "exit"
    """
    has_proven = bool(summary.proven_findings)
    options: list[tuple[str, str]] = [
        ("v", "View code snippet for a specific bug  (e.g. b1, b3)"),
        ("j", "Export all findings to JSON file"),
        ("r", "View precision track-record report"),
    ]
    if web_available:
        options.append(("w", "Open Web UI in browser  (localhost:7777)"))
    if has_proven:
        options.append(("p", "Show proven-only findings"))
    options.append(("q", "Exit"))

    console.print("[bold cyan]What would you like to do next?[/bold cyan]\n")
    for key, desc in options:
        console.print(f"  [[bold]{key}[/bold]] {desc}")
    console.print()

    try:
        raw = input("  Choice ❯ ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return "exit"

    mapping = {key: key for key, _ in options}
    mapping.update({
        "view": "v", "bug": "v", "b": "v",
        "json": "j", "export": "j",
        "report": "r", "rep": "r",
        "web": "w", "ui": "w", "open": "w",
        "proven": "p", "proof": "p",
        "exit": "q", "quit": "q", "e": "q",
    })

    action_key = mapping.get(raw, raw)

    if action_key == "v":
        _handle_view_bug(repo, candidates)
        return post_proof_menu(repo, candidates, summary, web_available=web_available)

    if action_key == "j":
        _handle_export_json(repo, candidates)
        return post_proof_menu(repo, candidates, summary, web_available=web_available)

    if action_key == "r":
        _handle_report()
        return post_proof_menu(repo, candidates, summary, web_available=web_available)

    if action_key == "p" and has_proven:
        from scanner import ui
        ui.render_results(repo, summary.proven_findings, 0, 0.0, limit=50)
        return post_proof_menu(repo, candidates, summary, web_available=web_available)

    if action_key == "w" and web_available:
        return "open_web"

    return "exit"


# ---------------------------------------------------------------------------
# Inline handlers used by post_proof_menu
# ---------------------------------------------------------------------------


def _handle_view_bug(repo: Path, candidates: list[dict]) -> None:
    from scanner.ui.results import render_code_snippet, candidate_score
    sorted_cands = sorted(candidates, key=candidate_score, reverse=True)
    console.print(f"[muted]Enter bug number (1 – {len(sorted_cands)}), or press Enter to cancel:[/muted]")
    try:
        raw = input("  Bug # ❯ ").strip().lstrip("bBvV")
    except (KeyboardInterrupt, EOFError):
        return
    if raw.isdigit():
        idx = int(raw)
        if 1 <= idx <= len(sorted_cands):
            render_code_snippet(repo, sorted_cands[idx - 1], bug_id=idx)
        else:
            console.print(f"[muted]No bug #{idx}.[/muted]")


def _handle_export_json(repo: Path, candidates: list[dict]) -> None:
    out = repo / "frapast_findings.json"
    out.write_text(
        json.dumps({"candidates": candidates}, indent=2, default=str),
        encoding="utf-8",
    )
    console.print(f"[success]✓ Saved {len(candidates)} findings → {out}[/success]\n")


def _handle_report() -> None:
    try:
        from rich.markdown import Markdown
        from scanner.reporting.engine import render_track_record
        console.print(Markdown(render_track_record("findings")))
    except Exception as exc:
        console.print(f"[muted]Report unavailable: {exc}[/muted]")


# ---------------------------------------------------------------------------
# Full unified pipeline (called by cli.py entry point)
# ---------------------------------------------------------------------------


def run_full_pipeline(
    repo: Path,
    repo_id: str = "local",
    *,
    bench_url: str = "",
    bench_user: str = "",
    bench_password: str = "",
    bench_site: str = "",
    limit: int = 20,
    write_ledger: bool = False,
    ledger_dir: str = "findings",
    launch_web: bool = False,
) -> int:
    """The single unified entry point that runs the full pipeline.

    Steps:
      1. Scan repo
      2. Show findings table
      3. Ask proof count
      4. Run Tier 1 + Tier 2 proof
      5. Show summary
      6. Post-proof menu (or launch web server)

    Returns exit code (0 = success, 1 = findings found).
    """
    from scanner.cli import _scan_repo_with_severity, _write_candidates
    from scanner import ui

    # ── Step 1: Scan ──────────────────────────────────────────────────────
    console.print(f"\n[bold]🔍 Scanning[/bold] [cyan]{repo}[/cyan]…\n")
    candidates, num_files, elapsed = _scan_repo_with_severity(
        repo,
        fp_log_path=None,
        repo_id=repo_id,
        include_severity=True,
        show_progress=True,
    )

    if not candidates:
        console.print("[success]✓ No security findings detected.[/success]")
        return 0

    if write_ledger:
        _write_candidates(candidates, Path(ledger_dir), repo_id)

    # ── Step 2: Show findings table ────────────────────────────────────────
    ui.render_results(repo, candidates, num_files, elapsed, limit=limit)

    # ── Step 3: Ask proof count ────────────────────────────────────────────
    if launch_web:
        # Web mode: immediately launch the server instead of asking
        _launch_web_server(repo, candidates, bench_url, bench_user, bench_password, bench_site)
        return 1 if candidates else 0

    count = ask_proof_count(len(candidates))
    if count == "skip":
        console.print("[muted]Proof skipped. Goodbye.[/muted]\n")
        return 1

    # ── Step 4: Run proof ──────────────────────────────────────────────────
    findings_dir = Path(ledger_dir) if write_ledger else None
    summary = run_proof_pipeline(
        candidates,
        count,
        repo,
        repo_id,
        bench_url=bench_url,
        bench_user=bench_user,
        bench_password=bench_password,
        bench_site=bench_site,
        findings_dir=findings_dir,
    )

    # ── Step 5: Show summary ───────────────────────────────────────────────
    show_proof_summary(summary)

    # ── Step 6: Post-proof menu ────────────────────────────────────────────
    if sys.stdout.isatty():
        action = post_proof_menu(repo, candidates, summary, web_available=True)
        if action == "open_web":
            _launch_web_server(repo, candidates, bench_url, bench_user, bench_password, bench_site)

    return 1 if candidates else 0


def _launch_web_server(
    repo: Path,
    candidates: list[dict],
    bench_url: str,
    bench_user: str,
    bench_password: str,
    bench_site: str,
) -> None:
    """Start the web server and open the browser."""
    try:
        from scanner.web.server import start_server
        start_server(
            repo=repo,
            candidates=candidates,
            bench_url=bench_url,
            bench_user=bench_user,
            bench_password=bench_password,
            bench_site=bench_site,
        )
    except ImportError:
        console.print("[muted]Web server not available.[/muted]")


import sys  # noqa: E402  (needed by run_full_pipeline)
