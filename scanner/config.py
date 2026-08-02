from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class RepoConfig:
	"""Configuration for a single repository to scan."""

	path: str
	id: str
	enabled: bool = True


@dataclass
class ScanConfig:
	"""Multi-repo scan configuration."""

	repos: list[RepoConfig] = field(default_factory=list)
	findings_dir: str = "findings"
	fp_log: str = "findings/fp-log.yaml"
	output_format: str = "yaml"  # yaml | json | markdown
	timeout_seconds: int = 300
	max_retries: int = 3


def load_config(path: str | Path) -> ScanConfig:
	"""Load scan configuration from a YAML file."""
	config_path = Path(path)
	if not config_path.exists():
		raise FileNotFoundError(f"Config file not found: {config_path}")
	data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
	if not isinstance(data, dict):
		raise ValueError(f"Invalid config: expected dict, got {type(data).__name__}")
	repos = []
	seen_ids = set()
	for repo_data in data.get("repos", []):
		if isinstance(repo_data, dict):
			repo_id = repo_data.get("id")
			if not repo_id:
				raise ValueError(f"Config error: 'id' is required for repo '{repo_data.get('path')}'")
			if repo_id in seen_ids:
				raise ValueError(f"Config error: Duplicate repo 'id' found: {repo_id}")
			seen_ids.add(repo_id)
			repos.append(
				RepoConfig(
					path=repo_data["path"],
					id=repo_id,
					enabled=repo_data.get("enabled", True),
				)
			)
	return ScanConfig(
		repos=repos,
		findings_dir=data.get("findings_dir", "findings"),
		fp_log=data.get("fp_log", "findings/fp-log.yaml"),
		output_format=data.get("output_format", "yaml"),
		timeout_seconds=int(data.get("timeout_seconds", 300)),
		max_retries=int(data.get("max_retries", 3)),
	)


def default_config(repo_path: str, repo_id: str = "local") -> ScanConfig:
	"""Create a default single-repo config."""
	return ScanConfig(
		repos=[RepoConfig(path=repo_path, id=repo_id)],
	)
