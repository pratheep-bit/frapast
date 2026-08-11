"""Unit test suite for server.py security controls, path resolution, and CORS."""
import json
import unittest
from pathlib import Path, PureWindowsPath
from unittest.mock import patch, MagicMock

from scanner.web.server import _resolve_file_path, PORT, _Handler


class TestServerSecurity(unittest.TestCase):
	def test_resolve_file_path_blocks_absolute_paths(self):
		repo = Path("/tmp/fake_repo")
		# Test POSIX absolute path
		self.assertIsNone(_resolve_file_path(repo, "/etc/passwd"))
		# Test Windows absolute path (verify PureWindowsPath recognises it as absolute)
		win_abs = "C:\\Windows\\System32\\cmd.exe"
		self.assertTrue(PureWindowsPath(win_abs).is_absolute())
		self.assertIsNone(_resolve_file_path(repo, win_abs))

	def test_resolve_file_path_blocks_path_traversal(self):
		repo = Path("/tmp/fake_repo")
		self.assertIsNone(_resolve_file_path(repo, "../../etc/passwd"))
		self.assertIsNone(_resolve_file_path(repo, "../../../secret.txt"))

	def test_trusted_origin_check(self):
		handler = MagicMock(spec=_Handler)
		handler.headers = {"Origin": f"http://localhost:{PORT}"}
		self.assertTrue(_Handler._is_trusted_origin(handler))

		handler.headers = {"Origin": "http://evil.com"}
		self.assertFalse(_Handler._is_trusted_origin(handler))

		# Same-origin navigations have no Origin header
		handler.headers = {}
		self.assertTrue(_Handler._is_trusted_origin(handler))


if __name__ == "__main__":
	unittest.main()
