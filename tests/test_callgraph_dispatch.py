"""Task 1 acceptance test: string-dispatch and dynamic-method callgraph edges."""
from textwrap import dedent

from scanner.callgraph.builder import build_call_graph
from scanner.hooks import build_hook_index, discover_hooks_files
from scanner.python import build_python_index, discover_python_files


def test_string_dispatch_creates_reachable_edge(tmp_path):
	f = tmp_path / "myapp" / "internal.py"
	f.parent.mkdir(parents=True)
	f.write_text(dedent("""\
		import frappe

		@frappe.whitelist()
		def public_endpoint():
		    frappe.call("myapp.internal.do_dangerous_thing")

		def do_dangerous_thing():
		    frappe.db.sql("SELECT * FROM `tabUser` WHERE name = '%s'" % frappe.form_dict.get("name"))
	"""))

	files = discover_python_files(tmp_path)
	python_index = build_python_index(files)
	graph = build_call_graph(python_index)

	whitelisted_ids = {fn.symbol_id for fn in python_index.whitelisted_endpoints}
	reachable = graph.reachable_from_set(whitelisted_ids)

	dangerous_fn = next(fn for fn in python_index.functions if fn.function == "do_dangerous_thing")
	assert dangerous_fn.id in reachable, (
		"FAIL: string-dispatch call via frappe.call() was not resolved as a "
		"reachability edge. This means FR-SQLI rules that depend on "
		"reachability will silently MISS this vulnerability."
	)


def test_dynamic_method_call_creates_reachable_edge(tmp_path):
	f = tmp_path / "myapp" / "api.py"
	f.parent.mkdir(parents=True)
	f.write_text(dedent("""\
		import frappe

		@frappe.whitelist()
		def update_doc(doctype, name):
		    doc = frappe.get_doc(doctype, name)
		    frappe.get_doc("Employee", name).dangerous_action()

		def dangerous_action():
		    pass
	"""))

	files = discover_python_files(tmp_path)
	python_index = build_python_index(files)
	graph = build_call_graph(python_index)

	# Verify the dynamic_method_calls were extracted
	assert any(r.method_name == "dangerous_action" for r in python_index.dynamic_method_calls), (
		"FAIL: frappe.get_doc().dangerous_action() was not extracted as a DynamicMethodCallRecord"
	)

	# Verify reachability
	whitelisted_ids = {fn.symbol_id for fn in python_index.whitelisted_endpoints}
	reachable = graph.reachable_from_set(whitelisted_ids)

	dangerous_fn = next(fn for fn in python_index.functions if fn.function == "dangerous_action")
	assert dangerous_fn.id in reachable, (
		"FAIL: dynamic method call via frappe.get_doc().method() was not resolved as a "
		"reachability edge."
	)


def test_hook_dispatch_creates_reachable_edge(tmp_path):
	# Create a hooks.py-like fixture and a Python file
	hooks_dir = tmp_path / "app_one"
	hooks_dir.mkdir(parents=True)
	(hooks_dir / "hooks.py").write_text(dedent("""\
		doc_events = {
		    "Attendance": {
		        "on_submit": ["app_one.handlers.on_submit_attendance"]
		    }
		}
	"""))
	(hooks_dir / "handlers.py").write_text(dedent("""\
		import frappe

		def on_submit_attendance(doc, method):
		    frappe.db.sql("SELECT * FROM tabAttendance WHERE name = '%s'" % doc.name)
	"""))

	hooks_files = discover_hooks_files(tmp_path)
	hook_index = build_hook_index(hooks_files)

	python_files = discover_python_files(tmp_path)
	python_index = build_python_index(python_files)

	graph = build_call_graph(python_index, hook_index)

	# The hook dispatch should create an edge from __framework_hook_root__
	# to the handler function
	assert "__framework_hook_root__" in graph.edges, (
		"FAIL: hook dispatch did not create edges from __framework_hook_root__"
	)


def test_string_dispatch_records_are_extracted(tmp_path):
	f = tmp_path / "test_module.py"
	f.write_text(dedent("""\
		import frappe

		def caller():
		    frappe.call("some.module.target_func")
		    frappe.enqueue("some.module.background_job")
	"""))

	files = discover_python_files(tmp_path)
	python_index = build_python_index(files)

	assert len(python_index.string_dispatch_calls) == 2, (
		f"Expected 2 string dispatch records, got {len(python_index.string_dispatch_calls)}"
	)
	paths = {r.target_dotted_path for r in python_index.string_dispatch_calls}
	assert "some.module.target_func" in paths
	assert "some.module.background_job" in paths
