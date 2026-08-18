"""Frappe Security Scanner — Static Analysis Engine."""
from scanner.cli import scan, scan_multi
from scanner.config import RepoConfig, ScanConfig, load_config
from scanner.logger import logger
from scanner.rules import Candidate, clear_rule_caches, execute_rules

__version__ = "1.2.0"

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

