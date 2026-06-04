"""
ast_parser.py — Parse Python source code using the built-in ast module.

Extracts:
  - functions: name, starting line number, argument names
  - imports: module names brought in via `import` / `from ... import`
  - call_graph: which function names are called inside each defined function
"""

import ast
from typing import Any


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_code(source: str) -> dict[str, Any]:
    """
    Parse *source* and return a structured analysis dict.

    Returns
    -------
    {
        "functions": [
            {"name": str, "line": int, "args": [str, ...]},
            ...
        ],
        "imports": [str, ...],
        "call_graph": {
            "<function_name>": ["<callee_name>", ...],
            ...
        }
    }

    Raises
    ------
    SyntaxError
        If *source* is not valid Python.
    """
    tree = ast.parse(source)

    functions = _extract_functions(tree)
    imports   = _extract_imports(tree)
    call_graph = _build_call_graph(tree)

    return {
        "functions":  functions,
        "imports":    imports,
        "call_graph": call_graph,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_functions(tree: ast.AST) -> list[dict[str, Any]]:
    """Return a list of dicts describing every top-level or nested function."""
    results: list[dict[str, Any]] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = [arg.arg for arg in node.args.args]
            results.append({
                "name": node.name,
                "line": node.lineno,
                "args": args,
            })

    return results


def _extract_imports(tree: ast.AST) -> list[str]:
    """Return a flat list of every module/name imported in the source."""
    imports: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                imports.append(f"{module}.{alias.name}" if module else alias.name)

    return imports


def _build_call_graph(tree: ast.AST) -> dict[str, list[str]]:
    """
    Build a simple call graph mapping each function definition to the list
    of function names it calls directly.
    """
    call_graph: dict[str, list[str]] = {}

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            callees: list[str] = []
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    name = _resolve_call_name(child.func)
                    if name:
                        callees.append(name)
            call_graph[node.name] = callees

    return call_graph


def _resolve_call_name(node: ast.expr) -> str | None:
    """
    Attempt to resolve a Call's func node to a human-readable name.
    Handles plain names (``foo()``) and attribute accesses (``obj.method()``).
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr  # simplified: just the method name
    return None
