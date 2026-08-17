# 🛡️ The `frapast` Ideology

> **The Manifesto for the World's Best Frappe & ERPNext Security Engine**

`frapast` was created to solve a fundamental problem in the Frappe ecosystem: **Custom apps quietly accumulate security, performance, and upgrade risks that generic scanners completely miss, while cloud SaaS scanners charge steep per-scan fees without proving their findings.**

Our mission is to build the most intelligent, fast, 100% precise, and privacy-first security & compatibility engine for Frappe and ERPNext in the world.

---

## 🏛️ The 5 Pillars of Our Ideology

```text
               ┌─────────────────────────────────────────────────────────┐
               │                  The frapast Vision                     │
               └────────────────────────────┬────────────────────────────┘
                                            │
    ┌───────────────────┬───────────────────┼───────────────────┬───────────────────┐
    │                   │                   │                   │                   │
┌───┴───────────┐   ┌───┴───────────┐   ┌───┴───────────┐   ┌───┴───────────┐   ┌───┴───────────┐
│ 1. Privacy &  │   │ 2. Dual-Engine│   │ 3. Frappe-    │   │ 4. Shift-Left │   │ 5. Action Over│
│ Local-First   │   │ Precision     │   │ Native        │   │ REPL Workflow │   │ Alarmism      │
└───────────────┘   └───────────────┘   └───────────────┘   └───────────────┘   └───────────────┘
```

---

### Pillar 1: Local-First & Zero Cloud Lock-In 🔒
- **Principle**: Your source code is your intellectual property. It should never leave your machine or be uploaded to third-party cloud servers.
- **Ideology**: Security tools should be **100% local, open-source, and free forever**. `frapast` runs entirely on your workstation or inside your private CI runners. No accounts, no credit cards, no SaaS subscriptions, and zero code bytes leaving disk.

---

### Pillar 2: Dual-Engine Precision (Static Recall + Runtime Truth) 🎯
- **Principle**: A scanner that floods developers with false positives is a broken scanner.
- **Ideology**: We believe in **2-Tier Verification**:
  1. **Tier 1 (Static AST)**: High-speed structural analysis across 5,000+ files in seconds to ensure 100% code coverage.
  2. **Tier 2 (Dynamic Proof)**: Automated synthesis of HTTP RPC reproducers and dataflow execution checks.
  - If a candidate finding cannot be statically or dynamically proven, it does not belong in your production alert queue. **Goal: 0% False Positives.**

---

### Pillar 3: Framework-Native Intelligence ⚡
- **Principle**: Generic linters (Bandit, SonarQube, Flake8) fail in Frappe because they treat Frappe code like generic Python.
- **Ideology**: `frapast` is built ground-up for Frappe idioms:
  - Deep awareness of `@frappe.whitelist(allow_guest=True)` permission boundaries.
  - Understanding `ignore_permissions=True` taint reachability across call graphs.
  - Disambiguating safe PyPika `frappe.qb` queries from raw SQL injections.
  - Tracking custom DocType lifecycles, `hooks.py` event handlers, and multi-tenancy boundaries.

---

### Pillar 4: Shift-Left REPL & CI Workflow 💻
- **Principle**: Security shouldn't be discovered at 2:00 AM on deployment day.
- **Ideology**: Security auditing must be an enjoyable, native part of a developer's daily workflow:
  - **Interactive REPL (`frapast shell`)**: Instant terminal inspection with arrow-key menus (`questionary`) and red-highlighted code snippets (`v 1` / `b1`).
  - **GitHub Security & PR Integration**: Exporting OASIS **SARIF v2.1.0** so vulnerabilities appear as native inline PR comments during code reviews.
  - **Git Diff Scanning**: `frapast scan . --diff main` to audit only modified code in Pull Requests.

---

### Pillar 5: Action Over Alarmism (Auto-Fix & PR Synthesis) 🛠️
- **Principle**: Telling a developer "line 42 is broken" without giving the solution is only half a job.
- **Ideology**: Every finding in `frapast` must provide:
  1. A plain-English explanation written like a senior Frappe core reviewer.
  2. The exact line-precise code snippet.
  3. The **Frappe-native replacement pattern** to fix it.
  4. Automated fix synthesis (`frapast fix --apply`) and 1-click GitHub PR creation (`frapast pr`).

---

## The Path to Ecosystem Leadership

By adhering strictly to this ideology, frapAST provides:

```text
[Cloud SaaS Scanners]                   [Generic Linters]                  [frapAST Engine]
  - Paid paywalls                         - Ignores Frappe idioms            - 100% Free & Open Source
  - Cloud source code uploads             - High false positive rate         - 100% Local & Private
  - Static-only guesses                   - No proof engine                  - 2-Tier Runtime Proof Engine
  - Proprietary web dashboards            - Generic suggestions              - SARIF + Bench CLI + Autofix
```

---

*"Security is not a tax paid to third-party cloud vendors. It is a craftsmanship standard built directly into your workflow."*
