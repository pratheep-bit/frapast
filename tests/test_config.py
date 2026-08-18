"""Unit tests for scanner scan configuration loader."""

import unittest

from scanner.config import RepoConfig, ScanConfig


class TestConfigLoader(unittest.TestCase):
	def test_default_scan_config(self):
		config = ScanConfig()
		self.assertEqual(config.findings_dir, "findings")
		self.assertEqual(config.fp_log, "findings/fp-log.yaml")
		self.assertEqual(config.output_format, "yaml")
		self.assertEqual(config.timeout_seconds, 300)
		self.assertEqual(config.max_retries, 3)

	def test_repo_config_creation(self):
		repo = RepoConfig(path="/tmp/test_repo", id="test-app", enabled=True)
		self.assertEqual(repo.id, "test-app")
		self.assertEqual(repo.path, "/tmp/test_repo")
		self.assertTrue(repo.enabled)


if __name__ == "__main__":
	unittest.main()
