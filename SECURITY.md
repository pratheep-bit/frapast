# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
| < 0.1   | No        |

## Scope

This security policy applies strictly to vulnerabilities in the **frapAST engine itself**, including:

- The local web dashboard server (`scanner/web/server.py`) — e.g. path traversal, origin validation bypass, command execution.
- The runtime proof orchestrator and reproducer synthesis pipeline (`scanner/proof/`) — e.g. shell argument injection or unescaped parameter execution.
- The AST symbol indexer and rule execution pipeline (`scanner/python/`, `scanner/rules/`).
- The CLI entrypoint and output formatters (`scanner/cli.py`, `scanner/reporting/`).

### Out of Scope
- Security vulnerabilities detected by frapAST in third-party Frappe/ERPNext applications or custom apps (these must be reported to their respective application maintainers).
- Denial of service via pathological or malformed local files provided as scan targets.
- Issues in optional dependencies not used by the core scan path.

## Reporting a Vulnerability

If you discover a security vulnerability in frapAST, please report it privately:

1. **GitHub Security Advisory (Preferred)**: Open a private advisory at [https://github.com/pratheep-bit/frapast/security/advisories/new](https://github.com/pratheep-bit/frapast/security/advisories/new).
2. **Direct Email**: If GitHub Security Advisories cannot be used, email the maintainer directly at **`pratheeps2024@gmail.com`** with the subject `[frapAST Security Vulnerability Report]`.

## What to Include

Please provide:
1. A description of the vulnerability and its potential impact.
2. Step-by-step reproduction instructions or a minimal proof-of-concept.
3. The specific version or commit hash where the issue was observed.
4. Any potential mitigations or suggested fixes.

## Response & Maintenance Expectations

As an open-source project maintained by a lean team:
- **Initial Acknowledgment**: Best-effort within 3 business days.
- **Triage & Assessment**: Within 7 to 10 business days.
- **Fix & Disclosure**: Critical vulnerabilities will be prioritized for a patch release as soon as practical, followed by a coordinated public release notice crediting the reporter.
