# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |
| < 1.0   | No        |

## Scope

This policy covers security vulnerabilities in the frapAST scanner engine itself,
including but not limited to:

- The web dashboard server (`scanner/web/server.py`)
- The proof orchestration and reproducer synthesis pipeline (`scanner/proof/`)
- The Python AST indexing and rule engine (`scanner/python/`, `scanner/rules/`)
- The CLI entrypoint and output formatters (`scanner/cli.py`, `scanner/reporting/`)

Vulnerabilities in Frappe or ERPNext applications that frapAST detects are not in scope
here; those should be reported directly to the Frappe project.

## Reporting a Vulnerability

If you discover a security vulnerability in frapAST, please report it privately so it
can be assessed and patched before public disclosure.

**Preferred channel**: Open a
[GitHub Security Advisory](https://github.com/pratheep-bit/frapast/security/advisories/new)
on the repository. This keeps the report private and creates a tracked advisory.

**Alternative**: If you are unable to use GitHub's private advisory feature, send a
detailed description to the email address listed in `pyproject.toml` (`authors`).

## What to Include

A useful vulnerability report should contain:

1. A clear description of the issue and its potential impact.
2. Reproduction steps or a proof-of-concept (code or command sequence).
3. The version or commit hash of frapAST where the issue was observed.
4. Your preferred disclosure timeline.

## Response Timeline

| Milestone                           | Target            |
|-------------------------------------|-------------------|
| Acknowledgment of the report        | Within 48 hours   |
| Initial triage and severity rating  | Within 5 business days |
| Patch release for Critical/High     | Within 14 days    |
| Patch release for Medium/Low        | Within 30 days    |
| Coordinated public disclosure       | After patch ships |

## Disclosure Policy

We follow a coordinated vulnerability disclosure model. We will credit reporters by name
or handle in the release notes and security advisory unless you prefer to remain
anonymous. We ask that you do not publicly disclose details of the vulnerability until a
patch has been released or until 90 days have elapsed from the initial report, whichever
comes first.

## Out of Scope

The following are explicitly out of scope for this security policy:

- Findings frapAST reports in third-party Frappe/ERPNext applications (report those to
  the respective application authors).
- Denial-of-service via extremely large or pathological Python files (best-effort
  mitigation only).
- Issues in optional dependencies not used by the core scan path.
