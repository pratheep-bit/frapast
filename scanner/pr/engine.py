import subprocess
import json
import shutil
import tempfile
from pathlib import Path
from scanner.rules import Candidate

def route_candidate(candidate: Candidate) -> str:
    """Returns 'pr', 'issue', or 'log_only' based on confidence."""
    if candidate.fix_confidence in ("high", "medium"):
        return "pr"
    if candidate.fix_confidence == "low":
        return "issue"
    return "log_only"

def create_pr(candidate: Candidate, repo_path: Path, fixed_code: str, dry_run: bool = False) -> bool:
    branch_name = f"auto-fix-{candidate.taxonomy_id.lower()}-{candidate.code_location_hash[:8]}"
    title = f"fix: resolve {candidate.taxonomy_id} in {candidate.file}"
    body = f"Automated fix for {candidate.taxonomy_id}\n\nEvidence: {candidate.evidence}\n\nHash: {candidate.code_location_hash}"

    if not dry_run and _duplicate_exists(repo_path, branch_name, candidate):
        print(f"Existing PR/issue coverage found for {branch_name}, skipping")
        return False

    if dry_run:
        _print_dry_run_diff(repo_path, candidate, fixed_code, branch_name)
        return True

    worktree_dir = Path(tempfile.mkdtemp(prefix="pr-worktree-"))
    try:
        subprocess.run(["git", "worktree", "add", "-b", branch_name, str(worktree_dir), "HEAD"],
                        cwd=str(repo_path), check=True)
        (worktree_dir / candidate.file).write_text(fixed_code)
        subprocess.run(["git", "add", candidate.file], cwd=str(worktree_dir), check=True)
        subprocess.run(["git", "commit", "-m", title], cwd=str(worktree_dir), check=True)
        subprocess.run(["git", "push", "-u", "origin", branch_name], cwd=str(worktree_dir), check=True)
        subprocess.run(["gh", "pr", "create", "--title", title, "--body", body, "--draft"],
                        cwd=str(worktree_dir), check=True)
        return True
    except Exception as e:
        print(f"Failed to create PR: {e}")
        # Fix #6: must remove worktree before git will let us delete the branch
        if worktree_dir.exists():
            subprocess.run(["git", "worktree", "remove", "--force", str(worktree_dir)], cwd=str(repo_path), capture_output=True)
        subprocess.run(["git", "branch", "-D", branch_name], cwd=str(repo_path), capture_output=True)
        subprocess.run(["git", "push", "origin", "--delete", branch_name], cwd=str(repo_path), capture_output=True)
        return False
    finally:
        if worktree_dir.exists():
            subprocess.run(["git", "worktree", "remove", "--force", str(worktree_dir)], cwd=str(repo_path), capture_output=True)


def run_pr_batch(fixable: list[tuple[Candidate, str]], repo_path: Path, live: bool, max_prs: int = 1) -> int:
    """Create PRs for validated (candidate, fixed_code) pairs, stopping once
    `max_prs` PRs have actually been created. Returns the number created.

    Regression guard: only a successful create_pr() call increments the
    counter. The previous inline version in cli.py incremented on every
    attempt regardless of outcome, so a single duplicate-PR or git/gh
    failure on the very first candidate would silently end the run having
    created zero PRs, without ever trying the remaining, perfectly good
    candidates.
    """
    created = 0
    for candidate, fixed_code in fixable:
        ok = create_pr(candidate, repo_path, fixed_code, dry_run=not live)
        if not ok:
            print(f"Skipped PR for {candidate.rule_id} in {candidate.file} (duplicate or failure) — trying next candidate.")
            continue
        created += 1
        if created >= max_prs:
            print(f"Reached max PRs per run ({max_prs}). Review and merge this one before running again.")
            break
    return created


def _duplicate_exists(repo_path: Path, branch_name: str, candidate: Candidate) -> bool:
    try:
        for state in ("open", "closed", "merged"):
            res = subprocess.run(
                ["gh", "pr", "list", "--state", state, "--search", f"in:body \"{candidate.code_location_hash}\"", "--json", "url"],
                cwd=str(repo_path), capture_output=True, text=True, check=True,
            )
            if json.loads(res.stdout):
                return True
        res = subprocess.run(
            ["gh", "issue", "list", "--state", "all", "--search", f"in:body \"{candidate.code_location_hash}\"", "--json", "url"],
            cwd=str(repo_path), capture_output=True, text=True, check=True,
        )
        return bool(json.loads(res.stdout))
    except Exception:
        # Unknown gh state (auth expired, rate limited) — fail closed, don't proceed as if clear.
        return True

def _print_dry_run_diff(repo_path: Path, candidate: Candidate, fixed_code: str, branch_name: str) -> None:
    import difflib
    original = (repo_path / candidate.file).read_text().splitlines(keepends=True)
    fixed = fixed_code.splitlines(keepends=True)
    diff = difflib.unified_diff(original, fixed, fromfile=f"a/{candidate.file}", tofile=f"b/{candidate.file}")
    print(f"[Dry Run] Would create branch {branch_name}:")
    print("".join(diff))
