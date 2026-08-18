"""Native Frappe Bench CLI plugin integration.

Enables commands:
    bench frapast audit [app_name]
    bench frapast fix [app_name] [--apply]
    bench frapast prove [app_name] [--site SITE]
    bench frapast check
"""
from __future__ import annotations

import sys

import click


@click.group(name="frapast")
def commands():
    """frapAST security, performance & compatibility audit commands."""
    pass


@commands.command("audit")
@click.argument("app_name", required=False, default=".")
@click.option("--format", "-f", type=click.Choice(["human", "json", "yaml", "sarif"]), default="human", help="Output format")
@click.option("--limit", "-l", type=int, default=20, help="Maximum findings to show in human output")
@click.option("--sarif", type=str, default="", help="Export SARIF 2.1.0 report to file path")
def bench_audit(app_name: str, format: str, limit: int, sarif: str):
    """Run static security & performance scan on a Frappe custom app."""
    from scanner.cli import main

    args = ["scan", app_name, "--format", format, "--limit", str(limit)]
    if sarif:
        args.extend(["--sarif", sarif])
    sys.exit(main(args))


@commands.command("fix")
@click.argument("app_name", required=False, default=".")
@click.option("--apply", is_flag=True, default=False, help="Write code patches directly to disk")
@click.option("--rule", default="", help="Filter fixes to a specific rule ID (e.g. FR-HOOK-001)")
@click.option("--format", "-f", type=click.Choice(["human", "json", "yaml"]), default="human", help="Output format")
def bench_fix(app_name: str, apply: bool, rule: str, format: str):
    """Synthesize and apply automated AST code patches."""
    from scanner.cli import main

    args = ["fix", app_name, "--format", format]
    if apply:
        args.append("--apply")
    if rule:
        args.extend(["--rule", rule])
    sys.exit(main(args))


@commands.command("prove")
@click.argument("app_name", required=False, default=".")
@click.option("--site", "-s", default="", help="Frappe site name for multi-tenant routing")
@click.option("--bench-url", default="", help="Frappe bench URL (default auto-detected)")
@click.option("--user", "-u", default="Administrator", help="Frappe admin user")
@click.option("--password", "-p", default="", help="Frappe admin password")
def bench_prove(app_name: str, site: str, bench_url: str, user: str, password: str):
    """Run Two-Tier active proof verification against the local bench."""
    from scanner.cli import main

    args = ["prove", app_name]
    if site:
        args.extend(["--bench-site", site])
    if bench_url:
        args.extend(["--bench-url", bench_url])
    if user:
        args.extend(["--bench-user", user])
    if password:
        args.extend(["--bench-password", password])
    sys.exit(main(args))


@commands.command("check")
@click.option("--site", "-s", default="", help="Frappe site name to check")
def bench_check(site: str):
    """Diagnose bench ports, site routing, and authentication."""
    from scanner.cli import main

    args = ["bench-check"]
    if site:
        args.extend(["--bench-site", site])
    sys.exit(main(args))
