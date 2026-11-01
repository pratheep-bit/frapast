"""Tests for FR-SECRET-002: Hardcoded plaintext credentials, keys, and committed configuration secrets.

Coverage:
  1. Python source file scanning — true positives (sensitive variable assignments, pattern matches)
  2. Python source file scanning — true negatives (placeholders, env references, short values)
  3. site_config.json / common_site_config.json — true positives and true negatives
  4. .env* file scanning — true positives, true negatives, excluded template files
"""
from __future__ import annotations

import json
from pathlib import Path

from scanner.callgraph import build_call_graph
from scanner.hooks import build_hook_index
from scanner.python import build_python_index
from scanner.rules import clear_rule_caches, execute_rules
from scanner.schema import build_schema_index
from scanner.shared import SourceFile


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _scan(tmp_path: Path, *, python_files: dict[str, str] | None = None, extra_files: dict[str, str] | None = None) -> list:
    """Build a minimal app layout under tmp_path, scan it, and return all FR-SECRET-002 candidates."""
    app_dir = tmp_path / "myapp"
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "__init__.py").write_text("")

    sources: list[SourceFile] = [SourceFile(path=app_dir / "__init__.py", root=tmp_path)]

    for rel, code in (python_files or {}).items():
        fpath = app_dir / rel
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(code, encoding="utf-8")
        sources.append(SourceFile(path=fpath, root=tmp_path))

    for rel, content in (extra_files or {}).items():
        fpath = tmp_path / rel
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(content, encoding="utf-8")

    clear_rule_caches()
    py_idx = build_python_index(sources)
    cg = build_call_graph(py_idx)
    schema = build_schema_index([])
    hooks = build_hook_index([])
    candidates = execute_rules(schema, hooks, py_idx, call_graph=cg)
    return [c for c in candidates if c.rule_id == "FR-SECRET-002"]


# ===========================================================================
# 1. Python source file — true positives
# ===========================================================================

class TestPythonSourceTruePositives:
    """FR-SECRET-002 must fire when plaintext secrets are assigned in Python source."""

    def test_api_secret_assignment(self, tmp_path):
        """Direct assignment to 'api_secret' with a realistic credential value triggers the rule."""
        code = 'api_secret = "Xk9mPqRs7vBn2wH4jL6nT8cE"'
        findings = _scan(tmp_path, python_files={"api.py": code})
        assert len(findings) >= 1
        assert any("api_secret" in f.function or "api_secret" in f.evidence for f in findings)

    def test_secret_key_assignment(self, tmp_path):
        """Assignment to 'secret_key' with a non-trivial value triggers the rule."""
        code = 'secret_key = "sUperS3cr3tK3y!@#xyz"'
        findings = _scan(tmp_path, python_files={"settings.py": code})
        assert len(findings) >= 1

    def test_db_password_assignment(self, tmp_path):
        """Assignment to 'db_password' with a realistic value triggers the rule."""
        code = 'db_password = "Prod_DB_P@ssw0rd99"'
        findings = _scan(tmp_path, python_files={"config.py": code})
        assert len(findings) >= 1

    def test_password_substring_match(self, tmp_path):
        """Variables whose name contains 'password' (e.g. 'admin_password') are also detected."""
        code = 'admin_password = "L3tM3In!Secr3t"'
        findings = _scan(tmp_path, python_files={"utils.py": code})
        assert len(findings) >= 1

    def test_pem_private_key_pattern(self, tmp_path):
        """A string constant containing a PEM private key header triggers the high-confidence pattern."""
        code = (
            'private_key = ('
            '"-----BEGIN RSA PRIVATE KEY-----\\n'
            'MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PAtEsHAGC7TVMY\\n'
            '-----END RSA PRIVATE KEY-----"'
            ')'
        )
        findings = _scan(tmp_path, python_files={"crypto.py": code})
        assert len(findings) >= 1

    def test_aws_access_key_pattern(self, tmp_path):
        """A string matching the AWS access key pattern (AKIA...) triggers the pattern detector."""
        code = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        findings = _scan(tmp_path, python_files={"aws_client.py": code})
        assert len(findings) >= 1

    def test_github_token_pattern(self, tmp_path):
        """A string matching the GitHub personal access token prefix triggers the pattern detector.

        The GitHub PAT regex requires exactly 36 alphanumeric characters after the 'ghp_' prefix.
        """
        # 36 alphanumeric chars: 26 letters + 10 digits = 36
        code = 'GH_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"'
        findings = _scan(tmp_path, python_files={"github_client.py": code})
        assert len(findings) >= 1

    def test_evidence_contains_masked_value(self, tmp_path):
        """The finding evidence must include a masked representation of the value (not the raw secret)."""
        code = 'api_secret = "SuperSecretValue99"'
        findings = _scan(tmp_path, python_files={"api.py": code})
        assert len(findings) >= 1
        ev = findings[0].evidence
        # Must NOT expose the full plain-text secret
        assert "SuperSecretValue99" not in ev
        # Must contain a masked hint (e.g. "Su...99")
        assert "..." in ev or "***" in ev


# ===========================================================================
# 2. Python source file — true negatives
# ===========================================================================

class TestPythonSourceTrueNegatives:
    """FR-SECRET-002 must NOT fire for safe, dynamic, or placeholder values."""

    def test_placeholder_value_not_flagged(self, tmp_path):
        """Safe placeholder strings must not trigger the rule."""
        code = 'api_secret = "your_secret_here"'
        findings = _scan(tmp_path, python_files={"api.py": code})
        assert len(findings) == 0

    def test_empty_string_not_flagged(self, tmp_path):
        """An empty string assigned to a sensitive variable must not be flagged."""
        code = 'api_secret = ""'
        findings = _scan(tmp_path, python_files={"api.py": code})
        assert len(findings) == 0

    def test_env_var_reference_not_flagged(self, tmp_path):
        """Reading a secret from the environment at runtime must not be flagged."""
        code = (
            "import os\n"
            'api_secret = os.environ.get("API_SECRET")\n'
        )
        findings = _scan(tmp_path, python_files={"api.py": code})
        assert len(findings) == 0

    def test_frappe_conf_reference_not_flagged(self, tmp_path):
        """Reading from frappe.conf at runtime must not be flagged."""
        code = (
            "import frappe\n"
            "api_secret = frappe.conf.api_secret\n"
        )
        findings = _scan(tmp_path, python_files={"api.py": code})
        assert len(findings) == 0

    def test_very_short_value_not_flagged(self, tmp_path):
        """Values shorter than the minimum length threshold must not be flagged."""
        code = 'secret_key = "ab"'
        findings = _scan(tmp_path, python_files={"api.py": code})
        assert len(findings) == 0

    def test_template_placeholder_not_flagged(self, tmp_path):
        """Values resembling template variables (e.g. <your_key>) must not be flagged."""
        code = 'api_secret = "<your_api_secret>"'
        findings = _scan(tmp_path, python_files={"api.py": code})
        assert len(findings) == 0


# ===========================================================================
# 3. site_config.json / common_site_config.json — true positives
# ===========================================================================

class TestConfigFileTruePositives:
    """FR-SECRET-002 must detect committed plaintext secrets in Frappe config JSON files."""

    def test_site_config_db_password(self, tmp_path):
        """site_config.json with a real db_password must be flagged."""
        cfg = {"db_password": "Pr0d_DB_Pass!123", "db_name": "mysite_db"}
        findings = _scan(tmp_path, extra_files={"site_config.json": json.dumps(cfg, indent=2)})
        assert len(findings) >= 1
        assert any("db_password" in f.evidence for f in findings)

    def test_common_site_config_encryption_key(self, tmp_path):
        """common_site_config.json with a committed encryption_key must be flagged."""
        cfg = {"encryption_key": "sUp3rEncryptK3y!9x7vBn2w", "developer_mode": 1}
        findings = _scan(tmp_path, extra_files={"common_site_config.json": json.dumps(cfg, indent=2)})
        assert len(findings) >= 1
        assert any("encryption_key" in f.evidence for f in findings)

    def test_site_config_admin_password(self, tmp_path):
        """site_config.json with a committed admin_password must be flagged."""
        cfg = {"admin_password": "G00dAdm1nP@ss", "db_name": "site1"}
        findings = _scan(tmp_path, extra_files={"site_config.json": json.dumps(cfg, indent=2)})
        assert len(findings) >= 1

    def test_config_file_evidence_contains_masked_value(self, tmp_path):
        """The finding evidence for a config file secret must include a masked value."""
        cfg = {"db_password": "Pr0d_DB_Pass!123"}
        findings = _scan(tmp_path, extra_files={"site_config.json": json.dumps(cfg, indent=2)})
        assert len(findings) >= 1
        ev = findings[0].evidence
        assert "Pr0d_DB_Pass!123" not in ev
        assert "..." in ev or "***" in ev

    def test_config_file_finding_references_filename(self, tmp_path):
        """The finding must reference the config file path in evidence."""
        cfg = {"db_password": "Pr0d_DB_Pass!123"}
        findings = _scan(tmp_path, extra_files={"site_config.json": json.dumps(cfg, indent=2)})
        assert len(findings) >= 1
        assert any("site_config.json" in f.evidence or "site_config.json" in f.file for f in findings)


# ===========================================================================
# 4. site_config.json — true negatives
# ===========================================================================

class TestConfigFileTrueNegatives:
    """FR-SECRET-002 must NOT fire for safe or placeholder config values."""

    def test_empty_db_password_not_flagged(self, tmp_path):
        """An empty db_password in site_config.json must not be flagged."""
        cfg = {"db_password": "", "db_name": "mysite"}
        findings = _scan(tmp_path, extra_files={"site_config.json": json.dumps(cfg, indent=2)})
        assert len(findings) == 0

    def test_template_placeholder_config_not_flagged(self, tmp_path):
        """Angle-bracket template values like <your_password> must not be flagged."""
        cfg = {"db_password": "<your_password>"}
        findings = _scan(tmp_path, extra_files={"site_config.json": json.dumps(cfg, indent=2)})
        assert len(findings) == 0

    def test_env_var_reference_in_config_not_flagged(self, tmp_path):
        """Values starting with '$' (shell env var references) must not be flagged."""
        cfg = {"db_password": "$DB_PASSWORD"}
        findings = _scan(tmp_path, extra_files={"site_config.json": json.dumps(cfg, indent=2)})
        assert len(findings) == 0

    def test_mustache_template_config_not_flagged(self, tmp_path):
        """Double-brace template values like {{ db_password }} must not be flagged."""
        cfg = {"db_password": "{{ db_password }}"}
        findings = _scan(tmp_path, extra_files={"site_config.json": json.dumps(cfg, indent=2)})
        assert len(findings) == 0

    def test_known_safe_placeholder_not_flagged(self, tmp_path):
        """Recognized safe placeholder strings (e.g. 'changeme') must not be flagged."""
        cfg = {"db_password": "changeme"}
        findings = _scan(tmp_path, extra_files={"site_config.json": json.dumps(cfg, indent=2)})
        assert len(findings) == 0

    def test_non_secret_config_keys_not_flagged(self, tmp_path):
        """Non-sensitive config keys (db_name, developer_mode) must not trigger the rule."""
        cfg = {"db_name": "mysite_db", "developer_mode": 0, "http_port": 8000}
        findings = _scan(tmp_path, extra_files={"site_config.json": json.dumps(cfg, indent=2)})
        assert len(findings) == 0

    def test_integer_value_not_flagged(self, tmp_path):
        """Non-string values (integers) must not be flagged even for sensitive key names."""
        cfg = {"db_password": 0}
        findings = _scan(tmp_path, extra_files={"site_config.json": json.dumps(cfg, indent=2)})
        assert len(findings) == 0


# ===========================================================================
# 5. .env* file scanning — true positives
# ===========================================================================

class TestEnvFileTruePositives:
    """FR-SECRET-002 must detect committed secrets in .env files."""

    def test_env_db_password(self, tmp_path):
        """A .env file with DB_PASSWORD set to a real credential must be flagged."""
        env_content = "DB_NAME=mysite\nDB_PASSWORD=Pr0d_DB_Pass!123\n"
        findings = _scan(tmp_path, extra_files={".env": env_content})
        assert len(findings) >= 1
        assert any("DB_PASSWORD" in f.evidence for f in findings)

    def test_env_secret_key(self, tmp_path):
        """A .env file with SECRET_KEY set to a real token must be flagged."""
        env_content = "SECRET_KEY=Xk9mPqRs7vBn2wH4jL6nT8cE\n"
        findings = _scan(tmp_path, extra_files={".env": env_content})
        assert len(findings) >= 1

    def test_env_api_token(self, tmp_path):
        """A .env file with API_TOKEN set to a real credential must be flagged."""
        env_content = "API_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ01234\n"
        findings = _scan(tmp_path, extra_files={".env": env_content})
        assert len(findings) >= 1

    def test_env_private_key_variable(self, tmp_path):
        """A .env file with PRIVATE_KEY set to a value must be flagged."""
        env_content = "PRIVATE_KEY=sUperS3cr3tK3y!@#xyz1234\n"
        findings = _scan(tmp_path, extra_files={".env": env_content})
        assert len(findings) >= 1


# ===========================================================================
# 6. .env* file scanning — true negatives
# ===========================================================================

class TestEnvFileTrueNegatives:
    """FR-SECRET-002 must NOT fire for template or safe .env files."""

    def test_env_example_file_excluded(self, tmp_path):
        """.env.example files are template files and must be excluded from scanning."""
        env_content = "DB_PASSWORD=changeme\nSECRET_KEY=your_secret_key_here\n"
        findings = _scan(tmp_path, extra_files={".env.example": env_content})
        assert len(findings) == 0

    def test_env_sample_file_excluded(self, tmp_path):
        """.env.sample files must be excluded from scanning."""
        env_content = "DB_PASSWORD=changeme\n"
        findings = _scan(tmp_path, extra_files={".env.sample": env_content})
        assert len(findings) == 0

    def test_env_template_file_excluded(self, tmp_path):
        """.env.template files must be excluded from scanning."""
        env_content = "SECRET_KEY=replace_this\n"
        findings = _scan(tmp_path, extra_files={".env.template": env_content})
        assert len(findings) == 0

    def test_env_test_file_excluded(self, tmp_path):
        """.env.test files must be excluded from scanning."""
        env_content = "DB_PASSWORD=testpassword\n"
        findings = _scan(tmp_path, extra_files={".env.test": env_content})
        assert len(findings) == 0

    def test_env_comments_not_flagged(self, tmp_path):
        """Comment lines in .env files must not be flagged."""
        env_content = "# DB_PASSWORD=RealPassword123\nDB_NAME=mysite\n"
        findings = _scan(tmp_path, extra_files={".env": env_content})
        assert len(findings) == 0

    def test_env_non_secret_variable_not_flagged(self, tmp_path):
        """Variables without secret-indicating names must not be flagged."""
        env_content = "APP_NAME=myapp\nDEBUG=false\nPORT=8000\n"
        findings = _scan(tmp_path, extra_files={".env": env_content})
        assert len(findings) == 0

    def test_env_public_key_variable_not_flagged(self, tmp_path):
        """Variables ending with _PUBLIC must not be flagged (public keys are not secrets)."""
        env_content = "STRIPE_KEY_PUBLIC=pk_test_abcdef123456\n"
        findings = _scan(tmp_path, extra_files={".env": env_content})
        assert len(findings) == 0
