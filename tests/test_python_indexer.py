"""Unit tests for the Python AST symbol indexer (scanner/python/engine.py)."""
import tempfile
import unittest
from pathlib import Path

from scanner.python.engine import build_python_index
from scanner.shared import SourceFile


class TestPythonIndexer(unittest.TestCase):
	def setUp(self):
		self.tmp_dir = tempfile.TemporaryDirectory()
		self.root = Path(self.tmp_dir.name)

	def tearDown(self):
		self.tmp_dir.cleanup()

	def test_relative_import_resolution(self):
		file_path = self.root / "app" / "controllers.py"
		file_path.parent.mkdir(parents=True, exist_ok=True)
		file_path.write_text(
			"from .models import ItemModel\n"
			"from ..utils import helper\n"
			"def run():\n"
			"    x = ItemModel()\n"
		)
		source = SourceFile(path=file_path, root=self.root)
		index = build_python_index([source])

		self.assertEqual(len(index.imports), 2)
		imp_map = {imp.local_name: imp.module for imp in index.imports}
		self.assertEqual(imp_map.get("ItemModel"), ".models")
		self.assertEqual(imp_map.get("helper"), "..utils")

	def test_parse_error_recording(self):
		bad_file = self.root / "bad.py"
		bad_file.write_text("def broken_syntax(:\n    pass\n")
		source = SourceFile(path=bad_file, root=self.root)
		index = build_python_index([source])

		self.assertEqual(len(index.parse_errors), 1)
		self.assertEqual(index.parse_errors[0].file, "bad.py")
		self.assertIn("invalid syntax", index.parse_errors[0].message)

	def test_unused_import_collection(self):
		file_path = self.root / "unused.py"
		file_path.write_text(
			"import os\n"
			"import sys\n"
			"def main():\n"
			"    print(sys.version)\n"
		)
		source = SourceFile(path=file_path, root=self.root)
		index = build_python_index([source])

		unused_names = {u.local_name for u in index.unused_imports}
		self.assertIn("os", unused_names)
		self.assertNotIn("sys", unused_names)


if __name__ == "__main__":
	unittest.main()
