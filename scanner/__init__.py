"""Frappe Security Scanner — Static Analysis Engine."""
from scanner.cli import scan, scan_multi
from scanner.config import ScanConfig, RepoConfig, load_config
from scanner.logger import logger
from scanner.rules import Candidate, execute_rules, clear_rule_caches

__version__ = "0.1.0"

__all__ = [
	"Candidate",
	"RepoConfig",
	"ScanConfig",
	"clear_rule_caches",
	"execute_rules",
	"load_config",
	"logger",
	"scan",
	"scan_multi",
]

