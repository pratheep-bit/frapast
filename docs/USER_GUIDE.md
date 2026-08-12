# frapAST Security Engine — User Guide and Technical Documentation

frapAST is an enterprise-grade static application security testing (SAST) and active proof verification (DAST) platform engineered specifically for the Frappe Framework and ERPNext ecosystem.

---

## Installation

### Standard Installation

Install frapAST via `pip`:

```bash
pip install frapast
```

### Installation from Source

For local development or source compilation:

```bash
git clone https://github.com/pratheep-bit/frapast.git
cd frapast
pip install -e .
```

---

## Web Dashboard Interface

Launch the interactive web dashboard by running the entry-point executable with no subcommands:

```bash
frapast
```

The application initializes a local HTTP server listening on `http://localhost:7777` and opens your default browser.

### Key Dashboard Capabilities

- **Directory Chooser**: Select any target repository path starting from the `/Users` root directory or choose from pre-configured shortcut locations (`~/Documents/erpnext`, `~/frappe-bench/apps`).
- **Multidimensional Severity Metrics**: Real-time aggregation of findings classified into Critical, High, Medium, and Low severity tiers based on privilege required, blast radius, and impact class.
- **Row-Selection Proof Verification**: Select candidate vulnerabilities directly within the results grid and execute targeted active reproducers against a local bench instance.
- **Server-Sent Event (SSE) Live Stream**: Stream real-time verification logs and execution events directly to the dashboard console.
- **Track Record Reporting**: Generate markdown compliance track-record reports for security auditing.
- **SARIF & JSON Data Exports**: Export scan results in OASIS SARIF (`.sarif`) format for GitHub Code Scanning and enterprise CI/CD integration.

---

## Command Line Interface (CLI)

### Static Security Analysis

Execute static vulnerability detection across a target application:

```bash
frapast scan /path/to/erpnext --severity
```

#### CLI Command Flags

- `--severity`: Calculates 5-dimension composite severity scores for all candidates.
- `--format json|sarif|yaml|human`: Output format specification (default: `human`).
- `--limit N`: Maximum number of findings displayed in terminal output (default: 20).

### Active Proof Verification

Verify static candidate findings against a running local Frappe bench instance (`http://localhost:8005`):

```bash
frapast prove /path/to/erpnext --count 10 --bench-port 8005
```

### Bench Diagnostics

Run automated network and authentication health checks against your target Frappe bench environment:

```bash
frapast bench-check --bench-url http://localhost:8005 --bench-user Administrator --bench-password admin
```

### Interactive Security REPL Shell

Launch an interactive security REPL environment supporting auto-completion and context inspection:

```bash
frapast shell /path/to/erpnext
```

---

## System Configuration (`frapast.yaml`)

Configure multi-repository targets, ledger storage paths, and false-positive logs using a root-level `frapast.yaml` configuration file:

```yaml
repos:
  - id: erpnext
    path: ./apps/erpnext
    enabled: true

findings_dir: ./findings
fp_log: ./findings/fp-log.yaml
```
