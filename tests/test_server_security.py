"""Unit test suite for server.py security controls, path resolution, and CORS."""
import unittest
from pathlib import Path, PureWindowsPath
from unittest.mock import MagicMock

from scanner.web.server import PORT, _Handler, _resolve_file_path


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

	def test_browse_path_traversal_containment(self):
		handler = MagicMock(spec=_Handler)
		handler.rfile = MagicMock()
		handler.wfile = MagicMock()
		handler.headers = {}

		# Test directory path traversal attempting to escape to /etc
		handler.path = "/api/browse?path=../../../../etc"
		handler.command = "GET"

		_Handler._serve_browse(handler, {"path": ["../../../../etc"]})
		self.assertTrue(handler._serve_json.called)
		args = handler._serve_json.call_args[0][0]
		# Must be clamped to user home / allowed root, NOT /etc or /private/etc
		self.assertNotIn("etc", [p for p in Path(args.get("current_path", "")).parts if p == "etc"])
		self.assertTrue(args.get("current_path", "").startswith(str(Path.home())))

	def test_bench_password_not_persisted_in_db(self):
		"""Verify save_bench_config does not store plaintext password in SQLite."""
		import tempfile
		from scanner.web import db

		with tempfile.TemporaryDirectory() as td:
			db.init(Path(td))
			db.save_bench_config({
				"bench_url": "http://localhost:8000",
				"bench_user": "Administrator",
				"bench_password": "supersecretpassword",
				"bench_site": "dev.local",
			})

			loaded = db.load_bench_config()
			self.assertEqual(loaded["bench_url"], "http://localhost:8000")
			self.assertEqual(loaded["bench_user"], "Administrator")
			self.assertEqual(loaded["bench_site"], "dev.local")
			# Password must NOT be persisted in SQLite
			self.assertEqual(loaded["bench_password"], "")

			# Directly verify raw sqlite rows
			conn = db._connect()
			row = conn.execute("SELECT value FROM bench_config WHERE key = 'bench_password'").fetchone()
			self.assertIsNone(row)

	def test_serve_report_renders_from_sqlite_and_invalidates_cache(self):
		"""Verify _serve_report generates markdown from SQLite findings and cache invalidation works."""
		import tempfile
		from scanner.web import db, server

		with tempfile.TemporaryDirectory() as td:
			db.init(Path(td))
			scan_id = "test-scan-123"
			db.create_scan(scan_id, "/tmp/demo_repo")
			db.upsert_findings(scan_id, [
				{
					"id": "FR-PERM-001-demo",
					"rule_id": "FR-PERM-001",
					"file": "api.py",
					"line": 10,
					"function": "get_data",
					"status": "proven",
				},
				{
					"id": "FR-SQLI-001-demo",
					"rule_id": "FR-SQLI-001",
					"file": "query.py",
					"line": 25,
					"function": "run_sql",
					"status": "candidate",
				},
			])
			db.finish_scan(scan_id, "done")

			handler = MagicMock(spec=server._Handler)
			server._Handler.invalidate_report_cache()
			server._Handler._serve_report(handler)

			self.assertTrue(handler._serve_json.called)
			args = handler._serve_json.call_args[0][0]
			report_text = args.get("report", "")

			self.assertIn("Security Track-Record Report for demo_repo", report_text)
			self.assertIn("| proven | 1 |", report_text)
			self.assertIn("| candidate | 1 |", report_text)
			self.assertIn("FR-PERM-001", report_text)
			self.assertIn("FR-SQLI-001", report_text)


if __name__ == "__main__":
	unittest.main()


