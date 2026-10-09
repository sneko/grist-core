"""
Runs the data engine in-process, for hosts that embed Python directly rather than talking to it
over pipes. This is used to run the engine inside Pyodide in a browser Web Worker, for
end-to-end encrypted documents whose data the server never sees.

Calls are exchanged as marshalled buffers, exactly as over the pipes (see sandbox.py), so the
host side can reuse the same (un)marshalling as NSandbox:
  - The host calls `call(buf)` where buf is marshal.dumps([func_name, args...]). It returns
    marshal.dumps((msgCode, data)) where msgCode is Sandbox.DATA or Sandbox.EXC.
  - The engine calls back into the host via `call_external_js(buf)` with buf being
    marshal.dumps((func_name, args...)), and expects a buffer with marshal.dumps((msgCode, data)).
"""
import logging
import marshal
import traceback

import sandbox as sandbox_module
from sandbox import Sandbox

log = logging.getLogger(__name__)


def _to_bytes(buf):
  # Pyodide passes JS typed arrays as JsProxy objects; convert them to Python bytes.
  if hasattr(buf, 'to_py'):
    buf = buf.to_py()
  return bytes(buf)


class DirectSandbox(Sandbox):
  def __init__(self, call_external_js=None):
    super(DirectSandbox, self).__init__(None, None)
    self._call_external_js = call_external_js

  def call_external(self, name, *args):
    if not self._call_external_js:
      raise Exception("call_external not available: %s" % name)
    response = self._call_external_js(marshal.dumps((name,) + args, 2))
    (msg_code, data) = marshal.loads(_to_bytes(response))
    if msg_code == Sandbox.EXC:
      raise Exception(data)
    return data

  def run(self, break_on_response=False):
    # Nothing to loop on: calls come in via call().
    pass

  def call(self, buf):
    fname = None
    try:
      data = marshal.loads(_to_bytes(buf))
      if not isinstance(data, (list, tuple)) or len(data) < 1:
        raise ValueError("Bad call %r" % (data,))
      fname = data[0]
      with formula_lockdown():
        ret = self._functions[fname](*data[1:])
      return marshal.dumps((Sandbox.DATA, ret), 2)
    except Exception as e:  # pylint: disable=broad-except
      log.warning("Call error in %s: %s", fname, traceback.format_exc())
      return marshal.dumps((Sandbox.EXC, "%s %s" % (type(e).__name__, e)), 2)


def create(call_external_js=None):
  """
  Creates the sandbox, makes it the default one (used by call_external() throughout the engine),
  and registers all the engine functions on it. Returns the sandbox, whose call() method is the
  entry point for the host.
  """
  direct = DirectSandbox(call_external_js)
  sandbox_module.default_sandbox = direct
  _install_formula_lockdown()
  # pylint: disable=import-outside-toplevel
  import main
  import actions
  import migrations
  import objtypes

  # main.run() creates the Engine and registers the standard functions. We wrap register() to
  # get hold of the engine-bound functions we build on below.
  registered = {}
  orig_register = direct.register
  def register(name, func):
    registered[name] = func
    orig_register(name, func)
  direct.register = register
  main.run(direct)

  # Without SQLite in the picture, tables travel as encoded TableData actions (the same
  # representation fetch_table() returns), rather than as marshalled SQLite rows.
  def from_repr(table_repr):
    return actions.action_from_repr(table_repr)

  # The engine is reachable through the bound methods main.run() exported (wrapped by
  # functools.wraps, which keeps the original as __wrapped__).
  eng = registered['load_empty'].__wrapped__.__self__

  def load_meta_tables_repr(meta_tables, meta_columns):
    return eng.load_meta_tables(from_repr(meta_tables), from_repr(meta_columns))

  def load_table_repr(table_repr):
    return eng.load_table(from_repr(table_repr))

  def fetch_all_tables():
    """Returns {table_id: TableData repr} for all tables, metadata and user tables alike."""
    return {table_id: actions.get_action_repr(eng.fetch_table(table_id, formulas=True))
            for table_id in eng.tables}

  def create_migrations_repr(all_tables, metadata_only=False):
    doc_actions = migrations.create_migrations(
      {table_id: from_repr(table_repr) for table_id, table_repr in all_tables.items()},
      metadata_only)
    return [actions.get_action_repr(action) for action in doc_actions]

  apply_user_actions = registered['apply_user_actions']

  def apply_doc_actions_exactly(doc_action_reprs, user=None):
    """
    Applies doc actions computed by another copy of the engine (another browser), ending up with
    the formula values they set. Plain ApplyDocActions recomputes formula cells, which for
    formulas like NOW(), UUID() or RANDBETWEEN() would leave each browser with different values.

    This is done in two passes. The first applies the actions normally: formulas get evaluated,
    which is also how the engine learns what they depend on. The second sets the formula cells
    that came out differently to the values computed by the author, and keeps them from being
    recomputed (as the engine does for data columns explicitly set in a user action, see
    docactions.BulkUpdateRecord).
    """
    result = apply_user_actions([['ApplyDocActions', doc_action_reprs]], user)
    try:
      corrections = _get_formula_corrections(eng, doc_action_reprs)
      if not corrections:
        return result
      return _merge_results(result, _apply_corrections(corrections, user))
    except Exception:
      # All or nothing: each call to apply_user_actions reverts itself if it fails, but the
      # first pass must be reverted too.
      undo = [action for (_env, action) in result['undo']]
      apply_user_actions([['ApplyUndoActions', undo]], user)
      raise

  def calculate_exactly(user=None):
    """
    Brings a freshly loaded document up to date, as the 'Calculate' action does when Grist opens
    a document, but keeping the formula values that were loaded. Evaluating all formulas is
    needed for the engine to learn what they depend on; but the loaded values are those all
    browsers share, and re-evaluating formulas like NOW() or RANDBETWEEN() in each browser would
    leave each with values of its own. Changes nothing, so returns nothing.
    """
    loaded = []
    for table_id, table in eng.tables.items():
      if table_id.startswith('_grist'):
        continue
      formula_cols = [col.col_id for col in table.all_columns.values()
                      if col.is_formula() and not col.col_id.startswith('#')]
      if formula_cols:
        row_ids = list(table.row_ids)
        loaded.append(['TableData', table_id, row_ids, {
          col_id: [objtypes.encode_object(table.get_column(col_id).raw_get(r)) for r in row_ids]
          for col_id in formula_cols}])
    apply_user_actions([['Calculate']], user)
    corrections = _get_formula_corrections(eng, loaded)
    if corrections:
      _apply_corrections(corrections, user)

  def _apply_corrections(corrections, user):
    """Sets formula cells to the given values, keeping them from being recomputed."""
    doc_actions = eng.doc_actions
    def bulk_update_record(table_id, row_ids, columns):
      type(doc_actions).BulkUpdateRecord(doc_actions, table_id, row_ids, columns)
      table = eng.tables[table_id]
      for col_id in columns:
        col = table.get_column(col_id)
        if col.is_formula():
          eng.prevent_recalc(col.node, row_ids, should_prevent=True)
    # UpdateRecord delegates to self.BulkUpdateRecord, so patching the instance covers both.
    doc_actions.BulkUpdateRecord = bulk_update_record
    try:
      return apply_user_actions([['ApplyDocActions', corrections]], user)
    finally:
      del doc_actions.BulkUpdateRecord

  # Formula columns this copy of the engine must never evaluate (see set_frozen_columns).
  frozen = set()

  class PreventRecomputeMap(dict):
    """
    The engine's map of cells not to recompute, extended to cover all cells of frozen columns.
    """
    def get(self, node, default=None):
      exempt = dict.get(self, node, default)
      if node in frozen:
        table = eng.tables.get(node.table_id)
        rows = set(table.row_ids) if table else set()
        return rows.union(exempt) if exempt else rows
      return exempt

    def clear(self):
      dict.clear(self)

  eng._prevent_recompute_map = PreventRecomputeMap()

  def set_frozen_columns(columns):
    """
    Sets the formula columns ([table_id, col_id] pairs) this copy of the engine must not
    evaluate, keeping whatever values they are given. In an encrypted document, these are the
    formulas depending on private columns this member can't read: they couldn't compute them,
    and get their values from members who can (or a placeholder, if they can't read them either).
    """
    import depend  # pylint: disable=import-outside-toplevel
    frozen.clear()
    frozen.update(depend.Node(table_id, col_id) for (table_id, col_id) in columns)

  scope_monitor = ScopeMonitor(eng)

  def set_column_scopes(entries):
    """
    Sets which columns are private ([table_id, col_id, scopes] for each column whose values need
    keys to be read, with the scopes of those keys), for the engine to keep formulas from reading
    private values beyond what they're known to read (see ScopeMonitor).
    """
    scope_monitor.set_scopes(entries)

  for func in (load_meta_tables_repr, load_table_repr, fetch_all_tables, create_migrations_repr,
               apply_doc_actions_exactly, calculate_exactly, set_frozen_columns, set_column_scopes):
    orig_register(func.__name__, func)
  return direct


def _get_formula_corrections(eng, doc_action_reprs):
  """
  Returns BulkUpdateRecord action reprs setting formula cells to the final values given to them
  in doc_action_reprs, for the cells where the engine currently has a different value.
  """
  import objtypes  # pylint: disable=import-outside-toplevel
  # Maps (table_id, col_id) to {row_id: encoded value}, as of the end of the actions.
  final = {}
  def set_values(table_id, row_ids, columns):
    for col_id, values in columns.items():
      cells = final.setdefault((table_id, col_id), {})
      for row_id, value in zip(row_ids, values):
        cells[row_id] = value

  for action in doc_action_reprs:
    name = action[0]
    if name == 'UpdateRecord' or name == 'AddRecord':
      set_values(action[1], [action[2]], {c: [v] for c, v in action[3].items()})
    elif name in ('BulkUpdateRecord', 'BulkAddRecord', 'ReplaceTableData', 'TableData'):
      set_values(action[1], action[2], action[3])
    elif name in ('RemoveRecord', 'BulkRemoveRecord'):
      row_ids = set(action[2] if name == 'BulkRemoveRecord' else [action[2]])
      for (table_id, _), cells in final.items():
        if table_id == action[1]:
          for row_id in row_ids:
            cells.pop(row_id, None)
    elif name == 'RemoveColumn':
      final.pop((action[1], action[2]), None)
    elif name == 'RenameColumn':
      cells = final.pop((action[1], action[2]), None)
      if cells is not None:
        final[(action[1], action[3])] = cells
    elif name == 'RemoveTable':
      final = {key: cells for key, cells in final.items() if key[0] != action[1]}
    elif name == 'RenameTable':
      final = {((action[2] if key[0] == action[1] else key[0]), key[1]): cells
               for key, cells in final.items()}

  corrections = []
  for (table_id, col_id), cells in sorted(final.items()):
    table = eng.tables.get(table_id)
    if not table or not table.has_column(col_id):
      continue
    col = table.get_column(col_id)
    if not col.is_formula():
      continue
    row_ids, values = [], []
    for row_id, value in sorted(cells.items()):
      if row_id in table.row_ids and objtypes.encode_object(col.raw_get(row_id)) != value:
        row_ids.append(row_id)
        values.append(value)
    if row_ids:
      corrections.append(['BulkUpdateRecord', table_id, row_ids, {col_id: values}])
  return corrections


def _merge_results(first, second):
  """Merges two results of apply_user_actions, as if they came from one call."""
  offset = len(first['stored'])
  merged = dict(first)
  for key in ('stored', 'direct', 'calc', 'undo'):
    merged[key] = first[key] + second[key]
  merged['undoOwner'] = first['undoOwner'] + [
    (env, None if owner is None else owner + offset) for (env, owner) in second['undoOwner']]
  merged['rowCount'] = second['rowCount']
  if second.get('requests'):
    merged['requests'] = dict(first.get('requests', {}), **second['requests'])
  return merged


# ---------------------------------------------------------------------------------------------
# Protection of private columns from formulas.
#
# In an encrypted document, private columns' values are only known to members holding their
# keys, and formulas reading them are private too (with the same keys). Which formulas read which
# columns is decided by the browser by looking for column names in formulas (see
# ColumnPrivacy.ts): the same everywhere, but formulas could read columns in ways this doesn't
# see, e.g. with names built at runtime. In the data engine of a member holding the keys, such a
# formula would compute a result from private values, which would then be shared as if it
# weren't private. Two things prevent that:
#
#   - ScopeMonitor checks, as formulas get evaluated, that they only read columns whose scopes
#     they're known to have. Formulas read columns through the engine's dependency tracking
#     (Engine._use_node), which it hooks into. Formulas reading more get an error instead.
#   - The formula lockdown keeps formulas from going around the engine to get at values: no
#     access to the engine's internals (names starting with "_", UserTable.table), no
#     introspection (getattr(), vars(), frames, ...), no imports, no format strings built at
#     runtime (they can reach attributes), and modules are only available without their
#     submodules (e.g. no `re.enum.sys`).
#
# Both give the same results in every browser, whether or not it holds the keys, so formulas
# still compute the same values everywhere.
# ---------------------------------------------------------------------------------------------

class _LockdownState(object):
  depth = 0


def formula_lockdown():
  """Context manager: formulas compiled or evaluated within it are subject to the lockdown."""
  import contextlib  # pylint: disable=import-outside-toplevel

  @contextlib.contextmanager
  def lockdown():
    _LockdownState.depth += 1
    try:
      yield
    finally:
      _LockdownState.depth -= 1
  return lockdown()


def _is_locked_down():
  return _LockdownState.depth > 0


# Names formulas can't use (as names or attributes): ways to introspect objects and reach
# beyond the values formulas are given.
DENIED_NAMES = frozenset([
  'getattr', 'setattr', 'delattr', 'hasattr', 'vars', 'dir', 'globals', 'locals', 'eval', 'exec',
  'compile', 'open', 'breakpoint', 'input', 'help', 'type', 'object', 'super', 'memoryview',
  'classmethod', 'staticmethod', 'property', 'exit', 'quit',
  'grist', 'sys', 'modules', 'builtins', 'bltns', 'os', 'gc', 'inspect', 'importlib', 'ctypes',
  'subprocess', 'mro', 'vformat', 'Formatter', 'exc_info', 'settrace', 'setprofile',
  'get_objects', 'get_referents', 'get_referrers',
  'gi_frame', 'gi_code', 'gi_yieldfrom', 'cr_frame', 'cr_code', 'cr_await', 'ag_frame', 'ag_code',
  'ag_await', 'f_back', 'f_builtins', 'f_code', 'f_globals', 'f_locals', 'f_trace', 'tb_frame',
  'tb_next', 'func_globals', 'func_code', 'im_func', 'im_self',
])


class FormulaNotAllowed(Exception):
  pass


def check_formula(formula):
  """
  Raises FormulaNotAllowed if the formula uses something the lockdown doesn't allow. Formulas
  that don't parse are left alone (the engine reports their syntax errors).
  """
  import ast  # pylint: disable=import-outside-toplevel
  import codebuilder  # pylint: disable=import-outside-toplevel
  import textwrap  # pylint: disable=import-outside-toplevel
  text = codebuilder.DOLLAR_REGEX.sub('DOLLAR', textwrap.dedent(formula))
  try:
    tree = ast.parse(text)
  except SyntaxError:
    return

  # Format strings are allowed when written out in the formula, without attributes or indexing.
  allowed_format_attrs = set()
  for node in ast.walk(tree):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
        node.func.attr in ('format', 'format_map'):
      fmt = node.func.value
      if isinstance(fmt, ast.Name) and fmt.id == 'str' and node.args:
        fmt = node.args[0]
      if isinstance(fmt, ast.Constant) and isinstance(fmt.value, str) and _is_simple_format(fmt.value):
        allowed_format_attrs.add(id(node.func))

  for node in ast.walk(tree):
    if isinstance(node, (ast.Import, ast.ImportFrom)):
      raise FormulaNotAllowed("imports are not available (datetime, math and re are)")
    if isinstance(node, (ast.Global, ast.Nonlocal)):
      raise FormulaNotAllowed("global and nonlocal are not available")
    if isinstance(node, ast.Name):
      name = node.id
    elif isinstance(node, ast.Attribute):
      name = node.attr
      if name in ('format', 'format_map') and id(node) not in allowed_format_attrs:
        raise FormulaNotAllowed("only format strings written out in the formula can be used, "
                                "without attributes or indexing (f-strings are fine)")
    else:
      continue
    if name.startswith('_'):
      raise FormulaNotAllowed("names starting with '_' are not available")
    if name in DENIED_NAMES:
      raise FormulaNotAllowed("'%s' is not available" % name)


def _is_simple_format(fmt):
  import string  # pylint: disable=import-outside-toplevel
  try:
    fields = list(string.Formatter().parse(fmt))
  except ValueError:
    return False
  for (_literal, field_name, spec, _conversion) in fields:
    if field_name is not None and ('.' in field_name or '[' in field_name):
      return False
    if spec and not _is_simple_format(spec):
      return False
  return True


_lockdown_installed = []


def _install_formula_lockdown():
  """Patches the engine (once) so that formulas get locked down within formula_lockdown()."""
  if _lockdown_installed:
    return
  _lockdown_installed.append(True)
  # pylint: disable=import-outside-toplevel,protected-access
  import sys
  import types
  import codebuilder
  import gencode
  import table as table_module
  import textbuilder

  # Formulas that aren't allowed compile into code raising an error.
  orig_make_body = codebuilder._do_make_formula_body
  def make_formula_body(formula, default_value, assoc_value=None):
    if _is_locked_down() and isinstance(formula, str) and formula.strip():
      try:
        check_formula(formula)
      except FormulaNotAllowed as e:
        message = "In encrypted documents, %s" % e
        return textbuilder.Text("raise PermissionError(%r)" % message, assoc_value)
    return orig_make_body(formula, default_value, assoc_value=assoc_value)
  codebuilder._do_make_formula_body = make_formula_body

  # Modules available to formulas are given without their submodules.
  orig_exec_module_text = gencode.exec_module_text
  def exec_module_text(module_text):
    mod = orig_exec_module_text(module_text)
    if _is_locked_down():
      for name, value in list(vars(mod).items()):
        if isinstance(value, types.ModuleType) and not name.startswith('_'):
          setattr(mod, name, _module_without_submodules(value))
    return mod
  gencode.exec_module_text = exec_module_text

  # UserTable.table is the engine's own Table object: formulas mustn't get it.
  def get_table(self):
    if _is_locked_down() and sys._getframe(1).f_code.co_filename == codebuilder.code_filename:
      raise AttributeError("table")
    return self.__dict__.get('_impl_table')
  def set_table(self, value):
    self.__dict__['_impl_table'] = value
  table_module.UserTable.table = property(get_table, set_table)


def _module_without_submodules(module):
  import types  # pylint: disable=import-outside-toplevel
  return types.SimpleNamespace(**{
    name: value for name, value in vars(module).items()
    if not name.startswith('_') and not isinstance(value, types.ModuleType)
  })


class ScopeMonitor(object):
  """
  Keeps formulas from reading private columns beyond those they're known to read: a formula may
  read a column only if the column's scopes are among the formula's own (see the comment above).
  """
  def __init__(self, eng):
    self._eng = eng
    self._scopes = {}     # (table_id, col_id) -> frozenset of scopes
    self._orig_use_node = eng._use_node
    self._orig_recompute_one_cell = eng._recompute_one_cell

  def set_scopes(self, entries):
    self._scopes = {(table_id, col_id): frozenset(scopes) for (table_id, col_id, scopes) in entries
                    if scopes}
    # Only check anything when there are private columns (_use_node is the engine's hot path).
    if self._scopes:
      self._eng._use_node = self._use_node
      self._eng._recompute_one_cell = self._recompute_one_cell
    elif '_use_node' in vars(self._eng):
      del self._eng._use_node
      del self._eng._recompute_one_cell

  def _recompute_one_cell(self, table, col, row_id, *args, **kwargs):
    # Cells evaluated on their own (e.g. to show a formula's error) are checked like the others.
    eng = self._eng
    if eng._current_node is not None:
      return self._orig_recompute_one_cell(table, col, row_id, *args, **kwargs)
    eng._current_node = col.node
    try:
      return self._orig_recompute_one_cell(table, col, row_id, *args, **kwargs)
    finally:
      eng._current_node = None

  def _use_node(self, node, relation, row_ids=[]):  # pylint: disable=dangerous-default-value
    current = self._eng._current_node
    if current is not None and node.col_id and _is_locked_down():
      needed = self._node_scopes(node)
      allowed = self._allowed_scopes(current)
      if needed and allowed is not None and not needed.issubset(allowed):
        raise PermissionError(
          "This formula reads a private column without naming it: in encrypted documents, "
          "private columns can only be read by formulas mentioning them (e.g. $%s)"
          % self._first_private_col(node))
    return self._orig_use_node(node, relation, row_ids)

  def _allowed_scopes(self, node):
    """The scopes a formula may read, or None if there is no limit."""
    # The engine's own helper columns (lookups, summaries) compute on behalf of formulas, which
    # are themselves checked when reading them.
    if node.col_id is None or node.col_id.startswith('#'):
      return None
    return self._scopes.get((node.table_id, node.col_id), frozenset())

  def _node_scopes(self, node):
    return frozenset().union(*(self._scopes.get((node.table_id, c), frozenset())
                               for c in self._columns_of(node)))

  def _first_private_col(self, node):
    for c in self._columns_of(node):
      if (node.table_id, c) in self._scopes:
        return c
    return node.col_id

  def _columns_of(self, node):
    """The user columns whose values reading the node gives (or reveals)."""
    # pylint: disable=import-outside-toplevel
    col_id = node.col_id
    if not col_id.startswith('#'):
      return [col_id]
    if col_id.startswith('#lookup#'):
      # "#lookup#A:B" for lookups by A and B, with "#<sort spec>" appended for sorted ones.
      import lookup
      cols = []
      for part in col_id[len('#lookup#'):].split('#'):
        for c in part.split(':'):
          c = c.lstrip('-')
          if c:
            try:
              cols.append(lookup.extract_column_id(c))
            except Exception:  # pylint: disable=broad-except
              cols.append(c)
      return cols
    if col_id.startswith('#summary#'):
      # Maps source rows to summary rows: reveals the source columns grouped by.
      summary_table = self._eng.tables.get(col_id[len('#summary#'):])
      source_table = self._eng.tables.get(node.table_id)
      if summary_table and source_table:
        return [c for c in summary_table.all_columns
                if source_table.has_column(c) and not summary_table.get_column(c).is_formula()]
    return []

