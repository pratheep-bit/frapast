"""Frappe Security Scanner — Static Analysis with Runtime Proof."""
from scanner.cli import scan, scan_multi
from scanner.config import ScanConfig, RepoConfig, load_config
from scanner.fix import synthesize_fix
from scanner.logger import logger
from scanner.proof.orchestrator import ProofOrchestrator
from scanner.rules import Candidate, execute_rules, clear_rule_caches

__version__ = "1.2.0"

__all__ = [
	"Candidate",
	"ProofOrchestrator",
	"RepoConfig",
	"ScanConfig",
	"clear_rule_caches",
	"execute_rules",
	"load_config",
	"logger",
	"scan",
	"scan_multi",
	"synthesize_fix",
]
