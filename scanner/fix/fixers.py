import re

try:
    import libcst as cst
    from libcst import matchers as m
    from libcst.metadata import PositionProvider
    _cst_base = cst.CSTTransformer
except ImportError:
    cst = None
    m = None
    PositionProvider = None
    _cst_base = object


class MutableDefaultArgFixer(_cst_base):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, target_line: int, target_arg: str):
        self.target_line = target_line
        self.target_arg = target_arg
        self.patched = False

    def leave_FunctionDef(self, original_node, updated_node):
        pos = self.get_metadata(PositionProvider, original_node)
        if pos.start.line != self.target_line:
            return updated_node

        def _is_mutable(node):
            return isinstance(node, (cst.List, cst.Dict, cst.Set))

        new_params, injected = [], []
        for param in updated_node.params.params:
            if param.name.value == self.target_arg and param.default and _is_mutable(param.default):
                mutable_val = param.default
                new_params.append(param.with_changes(default=cst.Name("None")))
                injected.append(self._build_guard(param.name.value, mutable_val))
                self.patched = True
            else:
                new_params.append(param)

        new_kwonly = []
        for param in updated_node.params.kwonly_params:
            if param.name.value == self.target_arg and param.default and _is_mutable(param.default):
                mutable_val = param.default
                new_kwonly.append(param.with_changes(default=cst.Name("None")))
                injected.append(self._build_guard(param.name.value, mutable_val))
                self.patched = True
            else:
                new_kwonly.append(param)

        if not injected:
            return updated_node

        new_params_obj = updated_node.params.with_changes(params=new_params, kwonly_params=new_kwonly)
        body_stmts = list(updated_node.body.body)
        insert_idx = 0
        if body_stmts and isinstance(body_stmts[0], cst.SimpleStatementLine):
            first = body_stmts[0].body[0]
            if isinstance(first, cst.Expr) and isinstance(first.value, cst.SimpleString):
                insert_idx = 1
        new_body = [*body_stmts[:insert_idx], *injected, *body_stmts[insert_idx:]]
        return updated_node.with_changes(
            params=new_params_obj,
            body=updated_node.body.with_changes(body=new_body),
        )

    @staticmethod
    def _build_guard(name: str, mutable_val: cst.BaseExpression) -> cst.If:
        return cst.If(
            test=cst.Comparison(
                left=cst.Name(name),
                comparisons=[cst.ComparisonTarget(operator=cst.Is(), comparator=cst.Name("None"))],
            ),
            body=cst.IndentedBlock(body=[
                cst.SimpleStatementLine(body=[
                    cst.Assign(targets=[cst.AssignTarget(target=cst.Name(name))], value=mutable_val)
                ])
            ]),
        )


class HardcodedStringI18nFixer(_cst_base):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, target_line: int):
        self.target_line = target_line
        self.patched = False

    def leave_Call(self, original_node, updated_node):
        pos = self.get_metadata(PositionProvider, original_node)
        if pos.start.line != self.target_line:
            return updated_node
        if not (
            m.matches(updated_node.func, m.Attribute(value=m.Name("frappe"), attr=m.Name("msgprint")))
            or m.matches(updated_node.func, m.Attribute(value=m.Name("frappe"), attr=m.Name("throw")))
        ):
            return updated_node

        message_idx, message_arg = self._find_message_arg(updated_node)
        if message_arg is None or not m.matches(message_arg.value, m.SimpleString()):
            return updated_node

        wrapped = cst.Call(
            func=cst.Attribute(value=cst.Name("frappe"), attr=cst.Name("_")),
            args=[cst.Arg(value=message_arg.value)],
        )
        new_args = list(updated_node.args)
        new_args[message_idx] = message_arg.with_changes(value=wrapped)
        self.patched = True
        return updated_node.with_changes(args=new_args)

    @staticmethod
    def _find_message_arg(call: cst.Call):
        for i, arg in enumerate(call.args):
            if arg.keyword is not None and arg.keyword.value == "msg":
                return i, arg
        for i, arg in enumerate(call.args):
            if arg.keyword is None:
                return i, arg
        return None, None


class IgnorePermissionsGuardFixer(_cst_base):
    """FR-PERM-002: ignore_permissions=True reachable within one hop of a
    whitelisted endpoint, without an indexed permission guard.

    The scanner's callgraph index already knows *which* doctype/permission
    type applies at the flagged call site -- that can't be recovered from
    the AST alone (the doctype is frequently a variable, e.g. `self.doctype`
    or a value threaded in from an outer scope). So this fixer takes the
    resolved doctype expression and permission type as constructor args
    (mirroring how MutableDefaultArgFixer is handed `target_arg`) and does a
    purely mechanical insertion: an explicit `frappe.has_permission(...)`
    check immediately before the statement that performs the privileged
    operation.

    Deliberately does NOT strip `ignore_permissions=True` itself -- that
    flag is frequently load-bearing for the operation to succeed once the
    caller's own authorization has been verified explicitly. Removing it
    would risk silently changing behavior; adding the missing guard closes
    the actual gap the rule flags.

    Known limitation: only patches calls that appear as their own
    SimpleStatementLine (a bare expression, assignment, or return
    statement). A flagged call nested inside another expression (e.g. as
    part of an `if` test) is left untouched and `patched` stays False, so
    the caller can fall back to a manual-review path.
    """

    METADATA_DEPENDENCIES = (PositionProvider,)

    _IGNORE_PERMISSIONS_TRUE = m.Arg(
        keyword=m.Name("ignore_permissions"),
        value=m.Name("True"),
    ) if m else None

    def __init__(self, target_line: int, doctype_expr: str, ptype: str = "write"):
        self.target_line = target_line
        self.doctype_expr = doctype_expr
        self.ptype = ptype
        self.patched = False

    def leave_SimpleStatementLine(self, original_node, updated_node):
        pos = self.get_metadata(PositionProvider, original_node)
        if pos.start.line != self.target_line:
            return updated_node
        if not m.findall(updated_node, self._IGNORE_PERMISSIONS_TRUE):
            return updated_node

        self.patched = True
        guard = self._build_guard()
        return cst.FlattenSentinel([guard, updated_node])

    def _build_guard(self) -> cst.If:
        doctype_node = cst.parse_expression(self.doctype_expr)
        condition = cst.UnaryOperation(
            operator=cst.Not(),
            expression=cst.Call(
                func=cst.Attribute(value=cst.Name("frappe"), attr=cst.Name("has_permission")),
                args=[
                    cst.Arg(value=doctype_node),
                    cst.Arg(
                        keyword=cst.Name("ptype"),
                        value=cst.SimpleString(f'"{self.ptype}"'),
                        equal=cst.AssignEqual(
                            whitespace_before=cst.SimpleWhitespace(""),
                            whitespace_after=cst.SimpleWhitespace(""),
                        ),
                    ),
                ],
            ),
        )
        throw_stmt = cst.SimpleStatementLine(body=[
            cst.Expr(value=cst.Call(
                func=cst.Attribute(value=cst.Name("frappe"), attr=cst.Name("throw")),
                args=[
                    cst.Arg(value=cst.Call(
                        func=cst.Attribute(value=cst.Name("frappe"), attr=cst.Name("_")),
                        args=[cst.Arg(value=cst.SimpleString('"Not permitted"'))],
                    )),
                    cst.Arg(value=cst.Attribute(value=cst.Name("frappe"), attr=cst.Name("PermissionError"))),
                ],
            ))
        ])
        return cst.If(test=condition, body=cst.IndentedBlock(body=[throw_stmt]))


class SqlDocstatusFilterFixer(_cst_base):
    """FR-SQLI-002: raw SQL references a submittable DocType table without a
    docstatus filter, so draft/cancelled rows leak into results that should
    only reflect submitted (and, per the proof recipe, correctly excluded
    cancelled) records.

    Operates on the literal query text passed to `frappe.db.sql(...)`. The
    caller supplies the exact filter expression to inject (e.g.
    "docstatus < 2" or "att.docstatus = 1") because only the scanner's
    schema index knows the right table alias/qualification to use at this
    call site -- this fixer just splices it in mechanically:

    - If the query already has a WHERE clause, the filter is AND-ed in
      right after WHERE.
    - Else if it has GROUP BY / ORDER BY / LIMIT, a WHERE clause is
      inserted just before the first of those.
    - Else the WHERE clause is appended at the end (respecting a trailing
      semicolon, if present).

    Known limitations: only patches a literal `SimpleString` query
    argument (plain or triple-quoted). Queries built via f-strings,
    `.format()`, or string concatenation are left untouched (`patched`
    stays False) since splicing SQL into those safely requires knowing
    which fragment holds the WHERE/FROM clause, which this fixer can't
    infer from a single call site. Also skips (no-ops) if the word
    "docstatus" already appears anywhere in the query, to avoid stacking a
    second, possibly conflicting filter on top of an existing one the
    scanner's heuristics may have missed.
    """

    METADATA_DEPENDENCIES = (PositionProvider,)

    _WHERE_RE = re.compile(r"\bWHERE\b", re.IGNORECASE)
    _CLAUSE_RE = re.compile(r"\b(GROUP\s+BY|ORDER\s+BY|LIMIT)\b", re.IGNORECASE)
    _DOCSTATUS_RE = re.compile(r"\bdocstatus\b", re.IGNORECASE)

    def __init__(self, target_line: int, docstatus_filter: str = "docstatus < 2"):
        self.target_line = target_line
        self.docstatus_filter = docstatus_filter
        self.patched = False

    def leave_Call(self, original_node, updated_node):
        pos = self.get_metadata(PositionProvider, original_node)
        if pos.start.line != self.target_line:
            return updated_node
        if not m.matches(
            updated_node.func,
            m.Attribute(value=m.Attribute(value=m.Name("frappe"), attr=m.Name("db")), attr=m.Name("sql")),
        ):
            return updated_node

        query_idx, query_arg = self._find_query_arg(updated_node)
        if query_arg is None or not m.matches(query_arg.value, m.SimpleString()):
            return updated_node

        new_string = self._patch_string(cst.ensure_type(query_arg.value, cst.SimpleString))
        if new_string is None:
            return updated_node

        new_args = list(updated_node.args)
        new_args[query_idx] = query_arg.with_changes(value=new_string)
        self.patched = True
        return updated_node.with_changes(args=new_args)

    @staticmethod
    def _find_query_arg(call: cst.Call):
        for i, arg in enumerate(call.args):
            if arg.keyword is not None and arg.keyword.value == "query":
                return i, arg
        for i, arg in enumerate(call.args):
            if arg.keyword is None:
                return i, arg
        return None, None

    def _patch_string(self, node: cst.SimpleString):
        raw = node.value
        prefix_match = re.match(r"^[a-zA-Z]*", raw)
        prefix = prefix_match.group(0)
        rest = raw[len(prefix):]
        quote = rest[:3] if rest[:3] in ('"""', "'''") else rest[:1]
        if not quote or not rest.endswith(quote) or len(rest) < 2 * len(quote):
            return None
        inner = rest[len(quote):-len(quote)]
        if self._DOCSTATUS_RE.search(inner):
            return None
        new_inner = self._inject_docstatus(inner)
        return node.with_changes(value=f"{prefix}{quote}{new_inner}{quote}")

    def _inject_docstatus(self, sql: str) -> str:
        where_match = self._WHERE_RE.search(sql)
        if where_match:
            insert_at = where_match.end()
            return f"{sql[:insert_at]} ({self.docstatus_filter}) AND{sql[insert_at:]}"

        clause_match = self._CLAUSE_RE.search(sql)
        if clause_match:
            insert_at = clause_match.start()
            return f"{sql[:insert_at]}WHERE {self.docstatus_filter} {sql[insert_at:]}"

        stripped = sql.rstrip()
        trailing_ws = sql[len(stripped):]
        if stripped.endswith(";"):
            stripped = f"{stripped[:-1]} WHERE {self.docstatus_filter};"
        else:
            stripped = f"{stripped} WHERE {self.docstatus_filter}"
        return stripped + trailing_ws


class DbSetValueHooksFixer(_cst_base):
    """FR-SQLI-003: frappe.db.set_value bypasses controller validate /
    before_save hooks.

    `frappe.db.set_value(doctype, docname, fieldname, value)` writes
    straight to the database, so any validation, derived-field
    recalculation, or side effects a DocType's controller normally runs on
    save never fire. The mechanical fix is the standard Frappe pattern of
    loading the document and saving it through the ORM instead:

        doc = frappe.get_doc(doctype, docname)
        doc.set(fieldname, value)          # or doc.update({...}) for the
        doc.save(ignore_permissions=True)  # dict-fieldname bulk-update form

    `ignore_permissions=True` is added to `.save()` deliberately: unlike
    `.insert()`, `frappe.db.set_value` never ran a permission check either,
    so this keeps the fix scoped to *only* restoring the hooks (the
    separate FR-PERM-002 fixer is what adds a real permission check, where
    one belongs).

    Known limitations, all conservative (leaves `patched=False` rather than
    guessing): only handles the call as its own statement; only handles
    exactly 3 positional args (dict-fieldname bulk form) or exactly 4
    (single fieldname/value form), matching frappe.db.set_value's actual
    signature; and bails if any keyword arguments (e.g. `update_modified=`)
    are present, since mapping those onto `.save()` semantics correctly
    needs a human to confirm intent.
    """

    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, target_line: int, doc_var: str = "_doc"):
        self.target_line = target_line
        self.doc_var = doc_var
        self.patched = False

    def leave_SimpleStatementLine(self, original_node, updated_node):
        pos = self.get_metadata(PositionProvider, original_node)
        if pos.start.line != self.target_line:
            return updated_node
        if len(updated_node.body) != 1 or not isinstance(updated_node.body[0], cst.Expr):
            return updated_node

        call = updated_node.body[0].value
        if not isinstance(call, cst.Call):
            return updated_node
        if not m.matches(
            call.func,
            m.Attribute(value=m.Attribute(value=m.Name("frappe"), attr=m.Name("db")), attr=m.Name("set_value")),
        ):
            return updated_node
        if any(arg.keyword is not None for arg in call.args):
            return updated_node

        positional = list(call.args)
        if len(positional) not in (3, 4):
            return updated_node

        doctype_expr = positional[0].value
        docname_expr = positional[1].value

        assign_doc = cst.SimpleStatementLine(body=[
            cst.Assign(
                targets=[cst.AssignTarget(target=cst.Name(self.doc_var))],
                value=cst.Call(
                    func=cst.Attribute(value=cst.Name("frappe"), attr=cst.Name("get_doc")),
                    args=[cst.Arg(value=doctype_expr), cst.Arg(value=docname_expr)],
                ),
            )
        ])

        if len(positional) == 4:
            fieldname_expr = positional[2].value
            value_expr = positional[3].value
            update_stmt = cst.SimpleStatementLine(body=[
                cst.Expr(value=cst.Call(
                    func=cst.Attribute(value=cst.Name(self.doc_var), attr=cst.Name("set")),
                    args=[cst.Arg(value=fieldname_expr), cst.Arg(value=value_expr)],
                ))
            ])
        else:
            fielddict_expr = positional[2].value
            update_stmt = cst.SimpleStatementLine(body=[
                cst.Expr(value=cst.Call(
                    func=cst.Attribute(value=cst.Name(self.doc_var), attr=cst.Name("update")),
                    args=[cst.Arg(value=fielddict_expr)],
                ))
            ])

        save_stmt = cst.SimpleStatementLine(body=[
            cst.Expr(value=cst.Call(
                func=cst.Attribute(value=cst.Name(self.doc_var), attr=cst.Name("save")),
                args=[cst.Arg(
                    keyword=cst.Name("ignore_permissions"),
                    value=cst.Name("True"),
                    equal=cst.AssignEqual(
                        whitespace_before=cst.SimpleWhitespace(""),
                        whitespace_after=cst.SimpleWhitespace(""),
                    ),
                )],
            ))
        ])

        self.patched = True
        return cst.FlattenSentinel([assign_doc, update_stmt, save_stmt])


class QbDynamicIdentifierFixer(_cst_base):
    """FR-SQLI-004: frappe.qb uses a dynamic, non-literal table/column name.

    This is the one rule in this set that a pure AST rewrite genuinely
    cannot "fix" in the sense of making the underlying code correct:
    placeholders (`%s`, bound params) only parameterize *values*, never
    identifiers, so a dynamic table/column name is only as safe as whatever
    allow-list validates it -- and that allow-list is a product decision,
    not something derivable from the call site's syntax. required_indexes
    for this rule is [python, callgraph], notably *not* schema, so the
    scanner has no resolved set of legitimate identifiers to offer either.

    So rather than fabricate a call to a real-sounding-but-unverified
    Frappe internal, this fixer wraps the dynamic expression in a call to a
    small helper this codebase owns (`assert_safe_identifier`, see
    scanner/fix/security.py) and fails closed: if the caller doesn't supply
    `allowed_values`, the emitted allow-list is empty, so the guarded code
    raises at runtime on every call until a developer fills in the real set
    of permitted tables/columns for that call site. That's a deliberate
    choice -- better a loud runtime error during testing than a silent
    injection left in place.

    Note this fixer only rewrites the flagged argument expression; it does
    not add the corresponding import. Pair it with
    `libcst.codemod.visitors.AddImportsVisitor.add_needed_import(context,
    "scanner.fix.security", "assert_safe_identifier")` (or an equivalent
    import-management pass) when wiring this into a codemod pipeline.
    """

    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, target_line: int, target_arg_index: int = 0, allowed_values=None):
        self.target_line = target_line
        self.target_arg_index = target_arg_index
        self.allowed_values = list(allowed_values or [])
        self.patched = False

    def leave_Call(self, original_node, updated_node):
        pos = self.get_metadata(PositionProvider, original_node)
        if pos.start.line != self.target_line:
            return updated_node
        if not self._is_qb_call(updated_node.func):
            return updated_node
        if self.target_arg_index >= len(updated_node.args):
            return updated_node

        target_arg = updated_node.args[self.target_arg_index]
        # A literal string isn't what this rule flags -- only patch when the
        # identifier expression is genuinely dynamic (a name, attribute
        # access, f-string, call, etc.).
        if m.matches(target_arg.value, m.SimpleString()):
            return updated_node
        # Idempotency: don't wrap an already-wrapped expression again.
        if m.matches(target_arg.value, m.Call(func=m.Name("assert_safe_identifier"))):
            return updated_node

        if self.allowed_values:
            allowed_node = cst.Set(elements=[
                cst.Element(value=cst.SimpleString(f'"{v}"')) for v in self.allowed_values
            ])
        else:
            allowed_node = cst.Call(func=cst.Name("frozenset"), args=[])

        wrapped = cst.Call(
            func=cst.Name("assert_safe_identifier"),
            args=[
                cst.Arg(value=target_arg.value),
                cst.Arg(
                    keyword=cst.Name("allowed"),
                    value=allowed_node,
                    equal=cst.AssignEqual(
                        whitespace_before=cst.SimpleWhitespace(""),
                        whitespace_after=cst.SimpleWhitespace(""),
                    ),
                ),
            ],
        )
        new_args = list(updated_node.args)
        new_args[self.target_arg_index] = target_arg.with_changes(value=wrapped)
        self.patched = True
        return updated_node.with_changes(args=new_args)

    @staticmethod
    def _is_qb_call(func) -> bool:
        # Matches frappe.qb.from_(...), frappe.qb.into(...), etc., and the
        # common `from frappe import qb` -> qb.from_(...) import style.
        return bool(
            m.matches(
                func,
                m.Attribute(value=m.Attribute(value=m.Name("frappe"), attr=m.Name("qb")), attr=m.DoNotCare()),
            )
            or m.matches(func, m.Attribute(value=m.Name("qb"), attr=m.DoNotCare()))
        )


class PermissionCheckGuardFixer(_cst_base):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, target_line: int, row_level_doctypes: frozenset[str] = frozenset()):
        self.target_line = target_line
        self.patched = False
        # DocTypes known to have row-level permission rules (if_owner,
        # permission_query_conditions, has_permission hooks).  Passed in
        # from the fix engine which has access to schema/hooks indexes.
        self._row_level_doctypes = row_level_doctypes

    def leave_FunctionDef(self, original_node, updated_node):
        pos = self.get_metadata(PositionProvider, original_node)
        if pos.start.line != self.target_line:
            return updated_node

        # Collect function parameter names for record-id tracking
        func_params = self._extract_func_params(updated_node)

        visitor = _DocTypeInferVisitor(func_params=func_params)
        updated_node.visit(visitor)

        if len(visitor.doctypes) != 1:
            # Abstain: 0 or multiple conflicting DocTypes
            return updated_node

        if visitor.is_self_scoped or visitor.is_allow_guest:
            # Abstain: ORM lookup is keyed off frappe.session.user or endpoint allows guests.
            return updated_node

        target_doctype = next(iter(visitor.doctypes))

        # Decide guard shape based on access pattern
        if visitor.record_id_param:
            # Single-record lookup with a caller-supplied identifier.
            # Use row-level check: frappe.has_permission(dt, 'read', doc=X, throw=True)
            param = visitor.record_id_param
            guard_code = f"frappe.has_permission('{target_doctype}', 'read', doc={param}, throw=True)\n"
        elif target_doctype in self._row_level_doctypes and not visitor.is_list_query:
            # DocType has row-level rules but we can't confidently map
            # the record identifier — abstain rather than emit a
            # class-level check that would miss row-level enforcement.
            return updated_node
        else:
            # List query, singleton, or no row-level rules — class-level check is correct.
            guard_code = f"frappe.has_permission('{target_doctype}', 'read', throw=True)\n"

        guard_stmt = cst.parse_statement(guard_code)
        body_stmts = list(updated_node.body.body)
        insert_idx = 0
        if body_stmts and isinstance(body_stmts[0], cst.SimpleStatementLine):
            first = body_stmts[0].body[0]
            if isinstance(first, cst.Expr) and isinstance(first.value, cst.SimpleString):
                insert_idx = 1
        new_body = [*body_stmts[:insert_idx], guard_stmt, *body_stmts[insert_idx:]]
        self.patched = True
        return updated_node.with_changes(body=updated_node.body.with_changes(body=new_body))

    @staticmethod
    def _extract_func_params(node: cst.FunctionDef) -> frozenset[str]:
        """Extract parameter names from a FunctionDef, excluding 'self'."""
        params: set[str] = set()
        if node.params:
            for p in node.params.params:
                if isinstance(p.name, cst.Name) and p.name.value != "self":
                    params.add(p.name.value)
            if node.params.star_kwarg and isinstance(node.params.star_kwarg.name, cst.Name):
                params.add(node.params.star_kwarg.name.value)
            for p in node.params.kwonly_params:
                if isinstance(p.name, cst.Name):
                    params.add(p.name.value)
        return frozenset(params)


class _DocTypeInferVisitor(cst.CSTVisitor):
    """Walk a function body to infer which DocTypes it touches, whether
    the ORM lookups are scoped to ``frappe.session.user`` (self-scoped),
    and whether any single-record lookup uses a caller-supplied parameter
    as the record identifier (requiring ``doc=`` row-level check)."""

    _SESSION_USER_ALIASES = frozenset({
        "current_user", "session_user", "logged_in_user", "user",
    })

    # ORM functions that fetch a single record by identifier
    _SINGLE_RECORD_FUNCS = frozenset({
        "frappe.get_doc", "frappe.get_value",
        "frappe.db.get_value",
    })

    # ORM functions that return lists (class-level permission check is correct)
    _LIST_FUNCS = frozenset({
        "frappe.get_all", "frappe.get_list",
        "frappe.db.get_all", "frappe.db.get_list",
    })

    # ORM functions that access singletons
    _SINGLETON_FUNCS = frozenset({
        "frappe.db.get_single_value",
    })

    def __init__(self, func_params: frozenset[str] = frozenset()):
        self.doctypes: set[str] = set()
        self.is_self_scoped: bool = False
        self.is_list_query: bool = False
        self.is_allow_guest: bool = False
        # If a single-record ORM call uses a function param as the record
        # identifier, store that param name here for doc= emission.
        self.record_id_param: str | None = None
        self._func_params = func_params
        self._session_user_vars: set[str] = set()

    def visit_Decorator(self, node: cst.Decorator):
        if isinstance(node.decorator, cst.Call):
            for arg in node.decorator.args:
                if (
                    isinstance(arg.keyword, cst.Name)
                    and arg.keyword.value == "allow_guest"
                    and isinstance(arg.value, cst.Name)
                    and arg.value.value == "True"
                ):
                    self.is_allow_guest = True

    # ── Assignment tracking ──────────────────────────────────────────
    def visit_Assign(self, node: cst.Assign):
        """Detect ``current_user = frappe.session.user`` style aliases."""
        if not isinstance(node.value, cst.Attribute):
            return
        if self._is_session_user_expr(node.value):
            for target in node.targets:
                if isinstance(target.target, cst.Name):
                    self._session_user_vars.add(target.target.value)

    def visit_AnnAssign(self, node: cst.AnnAssign):
        if node.value and isinstance(node.value, cst.Attribute):
            if self._is_session_user_expr(node.value):
                if isinstance(node.target, cst.Name):
                    self._session_user_vars.add(node.target.value)

    # ── ORM call inspection ──────────────────────────────────────────
    def visit_Call(self, node: cst.Call):
        func_name = self._resolve_func_name(node.func)

        all_orm = self._SINGLE_RECORD_FUNCS | self._LIST_FUNCS | self._SINGLETON_FUNCS | {
            "frappe.qb.DocType", "DocType",
        }
        if func_name not in all_orm or not node.args:
            return

        # Extract doctype from first positional arg
        arg0 = node.args[0].value
        if isinstance(arg0, cst.SimpleString):
            val = arg0.value.strip("\"'")
            if val:
                self.doctypes.add(val)

        # Classify access pattern
        if func_name in self._LIST_FUNCS:
            self.is_list_query = True

        if func_name in self._SINGLE_RECORD_FUNCS and len(node.args) >= 2:
            # Check if 2nd positional arg is a function parameter (caller-controlled)
            arg1 = node.args[1].value
            if isinstance(arg1, cst.Name) and arg1.value in self._func_params:
                self.record_id_param = arg1.value

        # Check whether any argument traces back to frappe.session.user
        if self._args_reference_session_user(node.args):
            self.is_self_scoped = True

    # ── Also detect direct frappe.session.user references ────────────
    def visit_Attribute(self, node: cst.Attribute):
        """Flag if frappe.session.user appears anywhere in the function body."""
        if self._is_session_user_expr(node):
            self.is_self_scoped = True

    # ── Helpers ──────────────────────────────────────────────────────
    @staticmethod
    def _resolve_func_name(func) -> str:
        if isinstance(func, cst.Attribute):
            if isinstance(func.value, cst.Attribute) and isinstance(func.value.value, cst.Name):
                return f"{func.value.value.value}.{func.value.attr.value}.{func.attr.value}"
            elif isinstance(func.value, cst.Name):
                return f"{func.value.value}.{func.attr.value}"
        elif isinstance(func, cst.Name):
            return func.value
        return ""

    @staticmethod
    def _is_session_user_expr(node: cst.Attribute) -> bool:
        """Return True for ``frappe.session.user``."""
        return (
            isinstance(node, cst.Attribute)
            and node.attr.value == "user"
            and isinstance(node.value, cst.Attribute)
            and node.value.attr.value == "session"
            and isinstance(node.value.value, cst.Name)
            and node.value.value.value == "frappe"
        )

    def _args_reference_session_user(self, args) -> bool:
        """Check if any ORM call argument references frappe.session.user
        or a local variable known to alias it."""
        for arg in args:
            val = arg.value
            if isinstance(val, cst.Attribute) and self._is_session_user_expr(val):
                return True
            if isinstance(val, cst.Name) and val.value in self._session_user_vars:
                return True
            if isinstance(val, cst.Dict):
                for el in val.elements:
                    if isinstance(el, cst.DictElement):
                        if isinstance(el.value, cst.Attribute) and self._is_session_user_expr(el.value):
                            return True
                        if isinstance(el.value, cst.Name) and el.value.value in self._session_user_vars:
                            return True
        return False


class WkflDocstatusGuardFixer(_cst_base):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, target_line: int):
        self.target_line = target_line
        self.patched = False

    def leave_FunctionDef(self, original_node, updated_node):
        pos = self.get_metadata(PositionProvider, original_node)
        if pos.start.line != self.target_line:
            return updated_node

        # Must be a method taking self as first parameter
        if not updated_node.params or not updated_node.params.params or updated_node.params.params[0].name.value != "self":
            return updated_node

        # Abstain if docstatus is already referenced in function body
        if self._has_docstatus_reference(updated_node):
            return updated_node

        guard_stmt = cst.parse_statement("if self.docstatus != 1:\n    frappe.throw(_('Document must be submitted.'))\n")
        body_stmts = list(updated_node.body.body)
        insert_idx = 0
        if body_stmts and isinstance(body_stmts[0], cst.SimpleStatementLine):
            first = body_stmts[0].body[0]
            if isinstance(first, cst.Expr) and isinstance(first.value, cst.SimpleString):
                insert_idx = 1
        new_body = [*body_stmts[:insert_idx], guard_stmt, *body_stmts[insert_idx:]]
        self.patched = True
        return updated_node.with_changes(body=updated_node.body.with_changes(body=new_body))

    @staticmethod
    def _has_docstatus_reference(node: cst.FunctionDef) -> bool:
        visitor = _DocstatusCheckVisitor()
        node.visit(visitor)
        return visitor.found


class _DocstatusCheckVisitor(cst.CSTVisitor):
    def __init__(self):
        self.found = False

    def visit_Attribute(self, node: cst.Attribute):
        if node.attr.value == "docstatus":
            self.found = True


class EnqueueDedupeKeyFixer(_cst_base):
    """FR-HOOK-004: Injects job_id keyword argument into frappe.enqueue calls."""
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, target_line: int):
        self.target_line = target_line
        self.patched = False

    def leave_Call(self, original_node, updated_node):
        pos = self.get_metadata(PositionProvider, original_node)
        if pos.start.line != self.target_line:
            return updated_node

        func_name = ""
        if isinstance(updated_node.func, cst.Attribute) and isinstance(updated_node.func.value, cst.Name):
            func_name = f"{updated_node.func.value.value}.{updated_node.func.attr.value}"
        elif isinstance(updated_node.func, cst.Name):
            func_name = updated_node.func.value

        if func_name != "frappe.enqueue":
            return updated_node

        # Check if job_id or job_name keyword arg is already present
        for kw in updated_node.args:
            if kw.keyword and kw.keyword.value in ("job_id", "job_name"):
                return updated_node

        # Derive a deterministic job_id expression from the enqueued target
        job_id_expr = None
        if updated_node.args:
            arg0 = updated_node.args[0].value
            if isinstance(arg0, cst.Attribute) and isinstance(arg0.value, cst.Name) and arg0.value.value == "self":
                # e.g. frappe.enqueue(self._bulk_assign, ...)
                method_name = arg0.attr.value
                job_id_expr = cst.parse_expression(f'f"{{self.doctype}}_{{self.name}}_{method_name}"')
            elif isinstance(arg0, cst.SimpleString):
                # e.g. frappe.enqueue("hrms.payroll...", ...)
                fn_str = arg0.value.strip("\"'")
                job_id_expr = cst.SimpleString(f'"{fn_str}"')

        if job_id_expr is None:
            # Abstain if job_id cannot be safely derived
            return updated_node

        new_kw = cst.Arg(keyword=cst.Name("job_id"), value=job_id_expr)
        self.patched = True
        return updated_node.with_changes(args=[*updated_node.args, new_kw])
