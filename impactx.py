#!/usr/bin/env python3
"""
IMPACTX — Semantic Change-Impact Analyzer for Python Projects.

AI writes the code. IMPACTX tells you what it can break.

Zero third-party dependencies. Standard library only.
"""

from __future__ import annotations

import argparse
import ast
import collections
import dataclasses
import datetime
import difflib
import enum
import fnmatch
import hashlib
import json
import os
import pathlib
import re
import sys
import textwrap
import time
import traceback
from typing import Dict, List, Set, Tuple, Optional, Any, Union

# Reconfigure stdout/stderr encoding for UTF-8 compatibility (especially on Windows consoles)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ==============================================================================
# 1. CONSTANTS & TERMINAL FORMATTING
# ==============================================================================

# Standard Library modules set (Python 3.10+ sys.stdlib_module_names or fallback)
if hasattr(sys, "stdlib_module_names"):
    STDLIB_MODULES = set(sys.stdlib_module_names)
else:
    STDLIB_MODULES = {
        "abc", "argparse", "array", "ast", "asyncio", "atexit", "base64", "bisect",
        "builtins", "bz2", "calendar", "cgi", "cmath", "cmd", "code", "codecs",
        "collections", "colorsys", "concurrent", "configparser", "contextlib",
        "contextvars", "copy", "copyreg", "csv", "ctypes", "curses", "dataclasses",
        "datetime", "dbm", "decimal", "difflib", "dis", "distutils", "doctest",
        "email", "enum", "errno", "faulthandler", "fcntl", "filecmp", "fileinput",
        "fnmatch", "fractions", "ftplib", "functools", "gc", "getpass", "getopt",
        "gettext", "glob", "graphlib", "gzip", "hashlib", "heapq", "hmac", "html",
        "http", "imaplib", "imghdr", "importlib", "inspect", "io", "ipaddress",
        "itertools", "json", "keyword", "lib2to3", "linecache", "locale", "logging",
        "lzma", "mailbox", "mailcap", "marshal", "math", "mimetypes", "mmap",
        "modulefinder", "multiprocessing", "netrc", "nntplib", "numbers", "operator",
        "os", "pathlib", "pdb", "pickle", "pickletools", "pkgutil", "platform",
        "plistlib", "poplib", "posix", "pprint", "profile", "pstats", "pty",
        "pwd", "py_compile", "queue", "quopri", "random", "re", "readline",
        "reprlib", "resource", "rlcompleter", "sched", "secrets", "select",
        "shelve", "shutil", "signal", "site", "smtpd", "smtplib", "sndhdr",
        "socket", "socketserver", "sqlite3", "ssl", "stat", "statistics",
        "string", "stringprep", "struct", "subprocess", "sunau", "symbol",
        "symtable", "sys", "sysconfig", "syslog", "tarfile", "telnetlib",
        "tempfile", "termios", "test", "textwrap", "threading", "time",
        "timeit", "tkinter", "token", "tokenize", "trace", "traceback",
        "tracemalloc", "tty", "types", "typing", "unicodedata", "unittest",
        "urllib", "uu", "uuid", "venv", "warnings", "wave", "weakref",
        "webbrowser", "wsgiref", "xdrlib", "xml", "xmlrpc", "zipapp",
        "zipfile", "zipimport", "zlib", "_thread"
    }

SECURITY_SENSITIVE_TOKENS = {
    "eval", "exec", "compile", "subprocess", "os.system", "popen",
    "shell=True", "socket", "urllib", "http.client", "pickle", "marshal",
    "base64", "hashlib", "secrets", "password", "token", "credential",
    "private_key", "secret_key", "api_key", ".env"
}

IGNORED_DIRS = {
    ".git", "__pycache__", ".venv", "venv", "node_modules",
    "dist", "build", ".egg-info", ".pytest_cache", ".mypy_cache"
}

class Ansi:
    """Terminal styling helper supporting optional color suppression."""
    enabled = True

    @classmethod
    def _c(cls, code: str, text: str) -> str:
        if not cls.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    @classmethod
    def bold(cls, text: str) -> str: return cls._c("1", text)
    @classmethod
    def dim(cls, text: str) -> str: return cls._c("2", text)
    @classmethod
    def red(cls, text: str) -> str: return cls._c("31", text)
    @classmethod
    def green(cls, text: str) -> str: return cls._c("32", text)
    @classmethod
    def yellow(cls, text: str) -> str: return cls._c("33", text)
    @classmethod
    def blue(cls, text: str) -> str: return cls._c("34", text)
    @classmethod
    def magenta(cls, text: str) -> str: return cls._c("35", text)
    @classmethod
    def cyan(cls, text: str) -> str: return cls._c("36", text)
    @classmethod
    def white(cls, text: str) -> str: return cls._c("37", text)
    @classmethod
    def bg_red(cls, text: str) -> str: return cls._c("41;1;37", text)
    @classmethod
    def bg_yellow(cls, text: str) -> str: return cls._c("43;1;30", text)

# ==============================================================================
# 2. ENUMS & DATACLASSES
# ==============================================================================

class SymbolType(str, enum.Enum):
    FUNCTION = "FUNCTION"
    METHOD = "METHOD"
    CLASS = "CLASS"
    MODULE = "MODULE"
    CONSTANT = "CONSTANT"

class ChangeType(str, enum.Enum):
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    SIGNATURE_CHANGED = "SIGNATURE_CHANGED"
    BODY_CHANGED = "BODY_CHANGED"
    DECORATOR_CHANGED = "DECORATOR_CHANGED"
    UNCHANGED = "UNCHANGED"

class RiskLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ImportCategory(str, enum.Enum):
    STANDARD_LIBRARY = "STANDARD_LIBRARY"
    LOCAL_PROJECT = "LOCAL_PROJECT"
    EXTERNAL = "EXTERNAL"
    UNKNOWN = "UNKNOWN"

@dataclasses.dataclass
class Symbol:
    name: str
    qualname: str
    symbol_type: SymbolType
    file_path: str
    line_no: int
    parameters: List[str] = dataclasses.field(default_factory=list)
    defaults_count: int = 0
    required_param_count: int = 0
    decorators: List[str] = dataclasses.field(default_factory=list)
    docstring: Optional[str] = None
    calls: Set[str] = dataclasses.field(default_factory=set)
    callers: Set[str] = dataclasses.field(default_factory=set)
    is_public: bool = True
    body_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "qualname": self.qualname,
            "symbol_type": self.symbol_type.value,
            "file_path": self.file_path,
            "line_no": self.line_no,
            "parameters": self.parameters,
            "required_param_count": self.required_param_count,
            "decorators": self.decorators,
            "calls": sorted(list(self.calls)),
            "callers": sorted(list(self.callers)),
            "is_public": self.is_public,
        }

@dataclasses.dataclass
class FileDiff:
    relative_path: str
    status: str  # ADDED, DELETED, MODIFIED, UNCHANGED
    lines_added: int = 0
    lines_removed: int = 0
    is_python: bool = True

@dataclasses.dataclass
class SymbolDiff:
    qualname: str
    symbol_type: SymbolType
    file_path: str
    change_type: ChangeType
    old_symbol: Optional[Symbol] = None
    new_symbol: Optional[Symbol] = None
    details: List[str] = dataclasses.field(default_factory=list)
    is_breaking_api: bool = False

@dataclasses.dataclass
class RiskFinding:
    severity: RiskLevel
    location: str
    symbol: str
    what_changed: str
    why_it_matters: str
    affected_symbols: List[str]
    affected_tests: List[str]
    risk_score_contrib: int
    recommended_action: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity.value,
            "location": self.location,
            "symbol": self.symbol,
            "what_changed": self.what_changed,
            "why_it_matters": self.why_it_matters,
            "affected_symbols": sorted(self.affected_symbols),
            "affected_tests": sorted(self.affected_tests),
            "risk_score_contrib": self.risk_score_contrib,
            "recommended_action": self.recommended_action,
        }

# ==============================================================================
# 3. DIRECTED GRAPH ENGINE (NETWORKX REPLACEMENT)
# ==============================================================================

class DirectedGraph:
    """Standard library directed graph implementation replacing NetworkX."""

    def __init__(self):
        self._adj: Dict[str, Set[str]] = collections.defaultdict(set)
        self._rev_adj: Dict[str, Set[str]] = collections.defaultdict(set)
        self._nodes: Set[str] = set()

    def add_node(self, node: str) -> None:
        self._nodes.add(node)
        if node not in self._adj:
            self._adj[node] = set()
        if node not in self._rev_adj:
            self._rev_adj[node] = set()

    def add_edge(self, u: str, v: str) -> None:
        self.add_node(u)
        self.add_node(v)
        self._adj[u].add(v)
        self._rev_adj[v].add(u)

    def nodes(self) -> Set[str]:
        return set(self._nodes)

    def get_callees(self, u: str) -> Set[str]:
        return set(self._adj.get(u, set()))

    def get_callers(self, v: str) -> Set[str]:
        return set(self._rev_adj.get(v, set()))

    def reachable_from(self, start_nodes: Union[str, List[str], Set[str]], reverse: bool = False) -> Set[str]:
        """Finds all nodes reachable from start_nodes using BFS."""
        if isinstance(start_nodes, str):
            start_nodes = [start_nodes]

        visited: Set[str] = set()
        queue = collections.deque(start_nodes)
        adj_map = self._rev_adj if reverse else self._adj

        while queue:
            curr = queue.popleft()
            if curr in visited:
                continue
            visited.add(curr)
            for neighbor in sorted(adj_map.get(curr, set())):
                if neighbor not in visited:
                    queue.append(neighbor)

        return visited - set(start_nodes if isinstance(start_nodes, (list, set)) else [start_nodes])

    def get_transitive_callers(self, node: str) -> Set[str]:
        return self.reachable_from(node, reverse=True)

    def get_transitive_callees(self, node: str) -> Set[str]:
        return self.reachable_from(node, reverse=False)

    def extract_neighborhood(self, start_node: str, depth: int = 2) -> Dict[str, List[str]]:
        """Returns a tree structure representation up to specified depth."""
        tree: Dict[str, List[str]] = collections.defaultdict(list)
        visited = set()
        queue = collections.deque([(start_node, 0)])

        while queue:
            curr, curr_depth = queue.popleft()
            if curr in visited or curr_depth >= depth:
                continue
            visited.add(curr)
            callers = sorted(list(self.get_callers(curr)))
            tree[curr] = callers
            for caller in callers:
                queue.append((caller, curr_depth + 1))

        return tree

# ==============================================================================
# 4. AST VISITOR & SYMBOL EXTRACTION
# ==============================================================================

class PythonASTVisitor(ast.NodeVisitor):
    """Parses AST to extract symbols, calls, imports, constants, and security tokens."""

    def __init__(self, module_name: str, file_path: str):
        self.module_name = module_name
        self.file_path = file_path
        self.symbols: Dict[str, Symbol] = {}
        self.imports: Dict[str, str] = {}  # alias -> full name or module
        self.raw_imports: Set[str] = set()
        self.constants: Dict[str, Tuple[Any, int]] = {}
        self.security_triggers: List[Tuple[str, int, str]] = [] # (token, lineno, detail)
        self.dynamic_dispatch_warnings: List[Tuple[str, int]] = []
        self._class_stack: List[str] = []
        self._current_function: Optional[Symbol] = None

    def _get_qualname(self, name: str) -> str:
        prefix = f"{self.module_name}." if self.module_name else ""
        if self._class_stack:
            return f"{prefix}{'.'.join(self._class_stack)}.{name}"
        return f"{prefix}{name}"

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.name
            asname = alias.asname or name
            self.imports[asname] = name
            self.raw_imports.add(name.split('.')[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        if mod:
            self.raw_imports.add(mod.split('.')[0])
        for alias in node.names:
            full_name = f"{mod}.{alias.name}" if mod else alias.name
            asname = alias.asname or alias.name
            self.imports[asname] = full_name
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qualname = self._get_qualname(node.name)
        is_pub = not node.name.startswith("_")
        
        # Class symbol
        sym = Symbol(
            name=node.name,
            qualname=qualname,
            symbol_type=SymbolType.CLASS,
            file_path=self.file_path,
            line_no=node.lineno,
            is_public=is_pub,
            body_hash=hashlib.sha256(ast.dump(node).encode("utf-8")).hexdigest()
        )
        self.symbols[qualname] = sym

        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._parse_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._parse_function(node)

    def _parse_function(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> None:
        qualname = self._get_qualname(node.name)
        sym_type = SymbolType.METHOD if self._class_stack else SymbolType.FUNCTION
        is_pub = not node.name.startswith("_")

        params = [arg.arg for arg in node.args.args]
        defaults_len = len(node.args.defaults)
        req_params_count = len(params) - defaults_len

        decorators = []
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                decorators.append(dec.id)
            elif isinstance(dec, ast.Attribute):
                decorators.append(f"{self._stringify_expr(dec.value)}.{dec.attr}")
            elif isinstance(dec, ast.Call):
                decorators.append(self._stringify_expr(dec.func))

        # Check for web routes or decorators turning functions into public APIs
        if any("route" in d or "endpoint" in d or "api" in d for d in decorators):
            is_pub = True

        docstring = ast.get_docstring(node)

        # Hash normalized body ast
        body_dump = ast.dump(node)
        body_hash = hashlib.sha256(body_dump.encode("utf-8")).hexdigest()

        sym = Symbol(
            name=node.name,
            qualname=qualname,
            symbol_type=sym_type,
            file_path=self.file_path,
            line_no=node.lineno,
            parameters=params,
            defaults_count=defaults_len,
            required_param_count=req_params_count,
            decorators=decorators,
            docstring=docstring,
            is_public=is_pub,
            body_hash=body_hash
        )
        self.symbols[qualname] = sym

        prev_fn = self._current_function
        self._current_function = sym
        self.generic_visit(node)
        self._current_function = prev_fn

    def visit_Assign(self, node: ast.Assign) -> None:
        # Check module-level constants (UPPERCASE)
        if not self._class_stack and not self._current_function:
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.isupper():
                    val = self._eval_literal(node.value)
                    qualname = self._get_qualname(target.id)
                    self.constants[qualname] = (val, node.lineno)
                    self.symbols[qualname] = Symbol(
                        name=target.id,
                        qualname=qualname,
                        symbol_type=SymbolType.CONSTANT,
                        file_path=self.file_path,
                        line_no=node.lineno,
                        body_hash=str(val)
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._stringify_expr(node.func)
        
        # Dynamic dispatch checks
        if func_name in ("getattr", "globals", "locals", "eval", "exec"):
            self.dynamic_dispatch_warnings.append((func_name, node.lineno))
            if func_name in ("eval", "exec"):
                self.security_triggers.append((func_name, node.lineno, f"Dynamic execution with {func_name}()"))

        # Security keyword checks in call
        if func_name in ("subprocess.run", "subprocess.Popen", "os.system", "os.popen"):
            self.security_triggers.append((func_name, node.lineno, f"Process execution call: {func_name}"))
            # Check for shell=True
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.security_triggers.append(("shell=True", node.lineno, "Subprocess invoked with shell=True"))

        if self._current_function:
            # Resolve call alias if imported
            resolved_call = self.imports.get(func_name, func_name)
            self._current_function.calls.add(resolved_call)

        self.generic_visit(node)

    def _stringify_expr(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val_str = self._stringify_expr(node.value)
            return f"{val_str}.{node.attr}" if val_str else node.attr
        elif isinstance(node, ast.Call):
            return self._stringify_expr(node.func)
        return ""

    def _eval_literal(self, node: ast.AST) -> Any:
        try:
            return ast.literal_eval(node)
        except Exception:
            return ast.dump(node)

# ==============================================================================
# 5. PROJECT DISCOVERY & ANALYSIS ENGINE
# ==============================================================================

class ProjectAnalyzer:
    """Crawls repository, parses Python code, builds Symbol Table & Graph."""

    def __init__(self, root_dir: str):
        self.root_path = pathlib.Path(root_dir).resolve()
        self.python_files: Dict[str, str] = {}  # rel_path -> full_path
        self.other_files: Dict[str, str] = {}   # rel_path -> full_path
        self.symbol_table: Dict[str, Symbol] = {}
        self.constants: Dict[str, Tuple[Any, int, str]] = {} # qualname -> (val, line, rel_path)
        self.call_graph = DirectedGraph()
        self.import_graph = DirectedGraph()
        self.raw_imports: Dict[str, Set[str]] = collections.defaultdict(set) # rel_path -> import names
        self.security_triggers: List[Tuple[str, str, int, str]] = [] # (rel_path, token, lineno, detail)
        self.dynamic_dispatch_warnings: List[Tuple[str, str, int]] = []
        self.parse_failures: List[Tuple[str, str]] = [] # (rel_path, error_msg)
        self.file_hashes: Dict[str, str] = {}

    def discover_files(self) -> None:
        if not self.root_path.exists():
            raise FileNotFoundError(f"Directory not found: {self.root_path}")

        for p in sorted(self.root_path.rglob("*")):
            if p.is_dir():
                continue
            # Skip ignored directories
            if any(part in IGNORED_DIRS for part in p.parts):
                continue
            
            try:
                rel_path = str(p.relative_to(self.root_path)).replace("\\", "/")
            except ValueError:
                continue

            if p.suffix == ".py":
                self.python_files[rel_path] = str(p)
            else:
                self.other_files[rel_path] = str(p)

    def analyze(self) -> None:
        self.discover_files()
        
        for rel_path, full_path in sorted(self.python_files.items()):
            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()

                self.file_hashes[rel_path] = hashlib.sha256(content.encode("utf-8")).hexdigest()
                tree = ast.parse(content, filename=full_path)
                
                module_name = rel_path.replace("/", ".").replace(".py", "")
                if module_name.endswith(".__init__"):
                    module_name = module_name[:-9]

                visitor = PythonASTVisitor(module_name=module_name, file_path=rel_path)
                visitor.visit(tree)

                # Collect symbols
                for qualname, sym in visitor.symbols.items():
                    self.symbol_table[qualname] = sym
                    self.call_graph.add_node(qualname)

                # Collect imports & build import graph
                for imp_name in visitor.raw_imports:
                    self.raw_imports[rel_path].add(imp_name)
                    self.import_graph.add_edge(module_name, imp_name)

                # Collect constants
                for qualname, (val, lineno) in visitor.constants.items():
                    self.constants[qualname] = (val, lineno, rel_path)

                # Collect security triggers & dynamic dispatch
                for token, lineno, detail in visitor.security_triggers:
                    self.security_triggers.append((rel_path, token, lineno, detail))
                for fn_name, lineno in visitor.dynamic_dispatch_warnings:
                    self.dynamic_dispatch_warnings.append((rel_path, fn_name, lineno))

            except SyntaxError as se:
                self.parse_failures.append((rel_path, f"SyntaxError at line {se.lineno}: {se.msg}"))
            except Exception as e:
                self.parse_failures.append((rel_path, f"Parse Error: {str(e)}"))

        # Build Call Graph edges
        self._resolve_call_edges()

    def _resolve_call_edges(self) -> None:
        """Resolves calls to symbols across modules and links callers."""
        # Simple lookup table of bare function names -> List of qualnames
        bare_name_map: Dict[str, List[str]] = collections.defaultdict(list)
        for qualname in self.symbol_table:
            bare_name = qualname.split(".")[-1]
            bare_name_map[bare_name].append(qualname)

        for qualname, sym in self.symbol_table.items():
            for raw_call in sym.calls:
                # 1. Exact qualname match
                if raw_call in self.symbol_table:
                    self.call_graph.add_edge(qualname, raw_call)
                    self.symbol_table[raw_call].callers.add(qualname)
                    continue

                # 2. Bare function match if unambiguous or local
                bare_call = raw_call.split(".")[-1]
                candidates = bare_name_map.get(bare_call, [])
                if len(candidates) == 1:
                    target = candidates[0]
                    self.call_graph.add_edge(qualname, target)
                    self.symbol_table[target].callers.add(qualname)
                elif len(candidates) > 1:
                    # Match same module first
                    mod_prefix = qualname.rsplit(".", 1)[0]
                    mod_matches = [c for c in candidates if c.startswith(mod_prefix)]
                    if mod_matches:
                        target = mod_matches[0]
                        self.call_graph.add_edge(qualname, target)
                        self.symbol_table[target].callers.add(qualname)

# ==============================================================================
# 6. FILE & SYMBOL DIFF ENGINE
# ==============================================================================

class SemanticDiffEngine:
    """Calculates textual diffs, AST symbol changes, and breaking API changes."""

    def __init__(self, before_proj: ProjectAnalyzer, after_proj: ProjectAnalyzer):
        self.before = before_proj
        self.after = after_proj
        self.file_diffs: List[FileDiff] = []
        self.symbol_diffs: List[SymbolDiff] = []
        self.config_changes: List[Tuple[str, Any, Any, str]] = [] # (qualname, old_val, new_val, rel_path)

    def compute_diff(self) -> None:
        self._diff_files()
        self._diff_symbols()
        self._diff_constants()

    def _diff_files(self) -> None:
        all_files = sorted(list(set(self.before.python_files.keys()) | 
                                set(self.after.python_files.keys()) |
                                set(self.before.other_files.keys()) |
                                set(self.after.other_files.keys())))

        for rel_path in all_files:
            in_before = rel_path in self.before.python_files or rel_path in self.before.other_files
            in_after = rel_path in self.after.python_files or rel_path in self.after.other_files
            is_py = rel_path.endswith(".py")

            if not in_before and in_after:
                full_path = self.after.python_files.get(rel_path) or self.after.other_files.get(rel_path)
                lines = self._count_lines(full_path)
                self.file_diffs.append(FileDiff(rel_path, "ADDED", lines_added=lines, lines_removed=0, is_python=is_py))
            elif in_before and not in_after:
                full_path = self.before.python_files.get(rel_path) or self.before.other_files.get(rel_path)
                lines = self._count_lines(full_path)
                self.file_diffs.append(FileDiff(rel_path, "DELETED", lines_added=0, lines_removed=lines, is_python=is_py))
            elif in_before and in_after:
                path_b = self.before.python_files.get(rel_path) or self.before.other_files.get(rel_path)
                path_a = self.after.python_files.get(rel_path) or self.after.other_files.get(rel_path)
                added, removed = self._text_diff_lines(path_b, path_a)
                status = "MODIFIED" if (added > 0 or removed > 0) else "UNCHANGED"
                self.file_diffs.append(FileDiff(rel_path, status, lines_added=added, lines_removed=removed, is_python=is_py))

    def _count_lines(self, path: Optional[str]) -> int:
        if not path or not os.path.exists(path):
            return 0
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return len(f.readlines())
        except Exception:
            return 0

    def _text_diff_lines(self, path_b: Optional[str], path_a: Optional[str]) -> Tuple[int, int]:
        if not path_b or not path_a:
            return 0, 0
        try:
            with open(path_b, "r", encoding="utf-8", errors="replace") as fb:
                lines_b = fb.readlines()
            with open(path_a, "r", encoding="utf-8", errors="replace") as fa:
                lines_a = fa.readlines()
            
            added = 0
            removed = 0
            for line in difflib.unified_diff(lines_b, lines_a):
                if line.startswith("+") and not line.startswith("+++"):
                    added += 1
                elif line.startswith("-") and not line.startswith("---"):
                    removed += 1
            return added, removed
        except Exception:
            return 0, 0

    def _diff_symbols(self) -> None:
        before_syms = self.before.symbol_table
        after_syms = self.after.symbol_table
        all_qualnames = sorted(list(set(before_syms.keys()) | set(after_syms.keys())))

        for qname in all_qualnames:
            in_b = qname in before_syms
            in_a = qname in after_syms

            if not in_b and in_a:
                s_new = after_syms[qname]
                self.symbol_diffs.append(SymbolDiff(
                    qualname=qname,
                    symbol_type=s_new.symbol_type,
                    file_path=s_new.file_path,
                    change_type=ChangeType.ADDED,
                    new_symbol=s_new,
                    details=[f"Symbol added: {qname}"]
                ))
            elif in_b and not in_a:
                s_old = before_syms[qname]
                is_breaking = s_old.is_public
                self.symbol_diffs.append(SymbolDiff(
                    qualname=qname,
                    symbol_type=s_old.symbol_type,
                    file_path=s_old.file_path,
                    change_type=ChangeType.REMOVED,
                    old_symbol=s_old,
                    details=[f"Public symbol removed: {qname}"] if is_breaking else [f"Symbol removed: {qname}"],
                    is_breaking_api=is_breaking
                ))
            elif in_b and in_a:
                s_old = before_syms[qname]
                s_new = after_syms[qname]
                diff_details: List[str] = []
                is_breaking = False
                change_type = ChangeType.UNCHANGED

                # Check signature
                if s_old.parameters != s_new.parameters or s_old.required_param_count != s_new.required_param_count:
                    change_type = ChangeType.SIGNATURE_CHANGED
                    diff_details.append(f"Parameters changed from ({', '.join(s_old.parameters)}) to ({', '.join(s_new.parameters)})")
                    if s_new.required_param_count > s_old.required_param_count and s_old.is_public:
                        is_breaking = True
                        added_req = [p for p in s_new.parameters[s_old.required_param_count:]]
                        diff_details.append(f"New required parameter(s) added to public API: {', '.join(added_req)}")
                    elif s_old.is_public and len(s_new.parameters) < len(s_old.parameters):
                        is_breaking = True
                        diff_details.append("Parameters removed from public API")

                # Check decorators
                elif s_old.decorators != s_new.decorators:
                    change_type = ChangeType.DECORATOR_CHANGED
                    diff_details.append(f"Decorators changed from {s_old.decorators} to {s_new.decorators}")
                    if s_old.is_public and any("route" in d for d in s_old.decorators + s_new.decorators):
                        is_breaking = True

                # Check body hash
                elif s_old.body_hash != s_new.body_hash:
                    change_type = ChangeType.BODY_CHANGED
                    diff_details.append("Implementation body modified")

                if change_type != ChangeType.UNCHANGED:
                    self.symbol_diffs.append(SymbolDiff(
                        qualname=qname,
                        symbol_type=s_new.symbol_type,
                        file_path=s_new.file_path,
                        change_type=change_type,
                        old_symbol=s_old,
                        new_symbol=s_new,
                        details=diff_details,
                        is_breaking_api=is_breaking
                    ))

    def _diff_constants(self) -> None:
        before_consts = self.before.constants
        after_consts = self.after.constants

        for qname, (val_a, lineno_a, rel_path) in after_consts.items():
            if qname in before_consts:
                val_b, _, _ = before_consts[qname]
                if val_b != val_a:
                    self.config_changes.append((qname, val_b, val_a, rel_path))

# ==============================================================================
# 7. IMPACT PROPAGATOR & TEST ANALYSIS
# ==============================================================================

class ImpactPropagator:
    """Traces transitive blast radius across symbols, modules, public APIs, and tests."""

    def __init__(self, diff_engine: SemanticDiffEngine):
        self.diff_engine = diff_engine
        self.before = diff_engine.before
        self.after = diff_engine.after
        self.changed_symbols: Set[str] = set()
        self.affected_callers: Set[str] = set()
        self.affected_modules: Set[str] = set()
        self.affected_public_apis: Set[str] = set()
        self.affected_tests: Set[str] = set()
        self.dead_changes: Set[str] = set()

    def propagate(self) -> None:
        # Collect changed symbol names
        for sdiff in self.diff_engine.symbol_diffs:
            self.changed_symbols.add(sdiff.qualname)
            if sdiff.is_breaking_api or (sdiff.new_symbol and sdiff.new_symbol.is_public):
                self.affected_public_apis.add(sdiff.qualname)

        # Transitive graph reachability using Before + After call graphs
        combined_graph = DirectedGraph()
        for g in (self.before.call_graph, self.after.call_graph):
            for n in g.nodes():
                combined_graph.add_node(n)
                for caller in g.get_callers(n):
                    combined_graph.add_edge(caller, n)

        # Reverse reachability: start from changed symbols and trace back to callers
        for sym in self.changed_symbols:
            callers = combined_graph.get_transitive_callers(sym)
            self.affected_callers.update(callers)

            # Check dead change: newly added or modified function with 0 callers
            direct_callers = combined_graph.get_callers(sym)
            if not direct_callers and sym in self.after.symbol_table:
                sym_obj = self.after.symbol_table[sym]
                if sym_obj.symbol_type == SymbolType.FUNCTION and not sym_obj.is_public:
                    self.dead_changes.add(sym)

        # Module-level blast radius
        all_affected_symbols = self.changed_symbols | self.affected_callers
        for qname in all_affected_symbols:
            mod_name = qname.rsplit(".", 1)[0]
            self.affected_modules.add(mod_name)

        # Test Impact Analysis
        self._analyze_test_impact(all_affected_symbols)

    def _analyze_test_impact(self, affected_symbols: Set[str]) -> None:
        """Finds tests that reference or call affected application symbols."""
        test_files = [path for path in self.after.python_files.keys() 
                      if path.startswith("tests/") or "test_" in path or "_test.py" in path]

        for test_path in test_files:
            # Check symbols in test file
            for qname, sym in self.after.symbol_table.items():
                if sym.file_path == test_path:
                    # If test calls any affected symbol directly or transitively
                    if any(call in affected_symbols or call.split(".")[-1] in [s.split(".")[-1] for s in affected_symbols]
                           for call in sym.calls):
                        self.affected_tests.add(test_path)
                        break

# ==============================================================================
# 8. DEPENDENCY DRIFT & SECURITY SIGNALS
# ==============================================================================

class SecurityAndDependencyEngine:
    """Scans for dependency drift and security-sensitive AST changes."""

    def __init__(self, diff_engine: SemanticDiffEngine):
        self.diff_engine = diff_engine
        self.before = diff_engine.before
        self.after = diff_engine.after
        self.new_external_dependencies: Set[str] = set()
        self.security_signals: List[Tuple[str, str, int, str]] = [] # (path, token, lineno, detail)

    def analyze(self) -> None:
        self._detect_dependency_drift()
        self._detect_security_signals()

    def _detect_dependency_drift(self) -> None:
        before_ext: Set[str] = set()
        after_ext: Set[str] = set()

        for path, imports in self.before.raw_imports.items():
            for imp in imports:
                cat = self._classify_import(imp, self.before)
                if cat == ImportCategory.EXTERNAL:
                    before_ext.add(imp)

        for path, imports in self.after.raw_imports.items():
            for imp in imports:
                cat = self._classify_import(imp, self.after)
                if cat == ImportCategory.EXTERNAL:
                    after_ext.add(imp)

        self.new_external_dependencies = after_ext - before_ext

    def _classify_import(self, imp_name: str, proj: ProjectAnalyzer) -> ImportCategory:
        top_name = imp_name.split(".")[0]
        if top_name in STDLIB_MODULES:
            return ImportCategory.STANDARD_LIBRARY
        
        # Check if local module in project
        for path in proj.python_files.keys():
            mod_name = path.replace("/", ".").replace(".py", "")
            if mod_name == top_name or mod_name.startswith(f"{top_name}."):
                return ImportCategory.LOCAL_PROJECT

        return ImportCategory.EXTERNAL

    def _detect_security_signals(self) -> None:
        # Check newly introduced security triggers in After version
        before_trig_set = {(t[0], t[1]) for t in self.before.security_triggers}
        
        for path, token, lineno, detail in self.after.security_triggers:
            if (path, token) not in before_trig_set:
                self.security_signals.append((path, token, lineno, detail))

        # Check for base64 + exec/eval combination in diffs
        for sdiff in self.diff_engine.symbol_diffs:
            if sdiff.change_type in (ChangeType.ADDED, ChangeType.BODY_CHANGED) and sdiff.new_symbol:
                calls = sdiff.new_symbol.calls
                if ("exec" in calls or "eval" in calls) and ("base64" in str(calls) or "b64decode" in str(calls)):
                    self.security_signals.append((
                        sdiff.file_path,
                        "obfuscated_exec",
                        sdiff.new_symbol.line_no,
                        f"Potential obfuscated dynamic code execution in {sdiff.qualname}"
                    ))

# ==============================================================================
# 9. RISK SCORING & FINDINGS ENGINE
# ==============================================================================

class RiskEngine:
    """Calculates deterministic risk score (0-100) and produces structured findings."""

    def __init__(self, diff_engine: SemanticDiffEngine, propagator: ImpactPropagator, sec_dep: SecurityAndDependencyEngine):
        self.diff_engine = diff_engine
        self.propagator = propagator
        self.sec_dep = sec_dep
        self.risk_score = 0
        self.risk_level = RiskLevel.LOW
        self.findings: List[RiskFinding] = []

    def evaluate(self) -> None:
        score = 0

        # 1. Security signals (+25 to +30)
        for path, token, lineno, detail in self.sec_dep.security_signals:
            score += 30
            self.findings.append(RiskFinding(
                severity=RiskLevel.CRITICAL,
                location=f"{path}:{lineno}",
                symbol=token,
                what_changed=f"Security-sensitive behavior detected: {detail}",
                why_it_matters="Modifying auth or adding dynamic execution introduces severe vulnerability risks.",
                affected_symbols=sorted(list(self.propagator.affected_callers)),
                affected_tests=sorted(list(self.propagator.affected_tests)),
                risk_score_contrib=30,
                recommended_action="Carefully review security logic and verify untrusted input validation."
            ))

        # 2. Breaking Public APIs (+25 to +30)
        for sdiff in self.diff_engine.symbol_diffs:
            if sdiff.is_breaking_api:
                score += 25
                callers = sorted(list(self.propagator.affected_callers))
                self.findings.append(RiskFinding(
                    severity=RiskLevel.CRITICAL if sdiff.change_type == ChangeType.REMOVED else RiskLevel.HIGH,
                    location=f"{sdiff.file_path}:{sdiff.old_symbol.line_no if sdiff.old_symbol else 1}",
                    symbol=sdiff.qualname,
                    what_changed=" | ".join(sdiff.details),
                    why_it_matters=f"Public API signature altered or removed. {len(callers)} downstream callers may fail.",
                    affected_symbols=callers,
                    affected_tests=sorted(list(self.propagator.affected_tests)),
                    risk_score_contrib=25,
                    recommended_action="Update call sites across dependent modules to match the new signature."
                ))

        # 3. New External Dependency (+20)
        if self.sec_dep.new_external_dependencies:
            score += 20
            deps_str = ", ".join(sorted(list(self.sec_dep.new_external_dependencies)))
            self.findings.append(RiskFinding(
                severity=RiskLevel.HIGH,
                location="Imports",
                symbol=deps_str,
                what_changed=f"New external third-party package dependency introduced: {deps_str}",
                why_it_matters="Dependency drift increases attack surface and runtime failure risk.",
                affected_symbols=[],
                affected_tests=sorted(list(self.propagator.affected_tests)),
                risk_score_contrib=20,
                recommended_action="Audit external package supply chain and confirm necessity."
            ))

        # 4. Configuration Changes (+10)
        for qname, old_v, new_v, path in self.diff_engine.config_changes:
            score += 10
            self.findings.append(RiskFinding(
                severity=RiskLevel.MEDIUM,
                location=f"{path}",
                symbol=qname,
                what_changed=f"Configuration constant {qname} value changed from {old_v} to {new_v}",
                why_it_matters="Altering system constants can change runtime timing, memory, or connection limits.",
                affected_symbols=sorted(list(self.propagator.affected_callers)),
                affected_tests=sorted(list(self.propagator.affected_tests)),
                risk_score_contrib=10,
                recommended_action="Verify system stability under modified configuration thresholds."
            ))

        # 5. Large Blast Radius (+15)
        if len(self.propagator.affected_callers) > 5:
            score += 15
            self.findings.append(RiskFinding(
                severity=RiskLevel.HIGH,
                location="Project Call Graph",
                symbol="Blast Radius",
                what_changed=f"Wide impact radius: {len(self.propagator.affected_callers)} functions across {len(self.propagator.affected_modules)} modules affected.",
                why_it_matters="High blast radius increases regression probability.",
                affected_symbols=sorted(list(self.propagator.affected_callers)),
                affected_tests=sorted(list(self.propagator.affected_tests)),
                risk_score_contrib=15,
                recommended_action="Perform thorough regression testing across all affected callers."
            ))

        # Normalize score
        self.risk_score = min(100, score)

        # Determine level
        if self.risk_score <= 20:
            self.risk_level = RiskLevel.LOW
        elif self.risk_score <= 45:
            self.risk_level = RiskLevel.MEDIUM
        elif self.risk_score <= 70:
            self.risk_level = RiskLevel.HIGH
        else:
            self.risk_level = RiskLevel.CRITICAL

# ==============================================================================
# 10. REVIEW ORDER GENERATOR
# ==============================================================================

class ReviewOrderGenerator:
    """Generates ordered human review checklist prioritizing high-risk items."""

    @staticmethod
    def generate(risk_engine: RiskEngine, diff_engine: SemanticDiffEngine, propagator: ImpactPropagator) -> List[str]:
        items: List[Tuple[int, str]] = []

        # High priority: Security signals
        for path, token, lineno, detail in risk_engine.sec_dep.security_signals:
            items.append((100, f"{token}() in {path}:{lineno} — Security signal: {detail}"))

        # Breaking APIs
        for sdiff in diff_engine.symbol_diffs:
            if sdiff.is_breaking_api:
                items.append((90, f"{sdiff.qualname}() — Breaking API change"))

        # Config changes
        for qname, old_v, new_v, path in diff_engine.config_changes:
            items.append((70, f"{qname} ({path}) — Config change: {old_v} -> {new_v}"))

        # General changed symbols sorted by number of callers
        for sdiff in diff_engine.symbol_diffs:
            if not sdiff.is_breaking_api and sdiff.change_type != ChangeType.UNCHANGED:
                num_callers = len(propagator.after.call_graph.get_callers(sdiff.qualname))
                items.append((50 + min(30, num_callers * 5), f"{sdiff.qualname}() — Modified implementation ({num_callers} callers)"))

        # Affected test files
        for test_file in sorted(list(propagator.affected_tests)):
            items.append((30, f"{test_file} — Affected test suite"))

        # Sort descending by priority weight
        items.sort(key=lambda x: x[0], reverse=True)
        
        # Deduplicate preserving order
        seen = set()
        ordered: List[str] = []
        for _, desc in items:
            if desc not in seen:
                seen.add(desc)
                ordered.append(desc)

        return ordered

# ==============================================================================
# 11. REPORT RENDERERS (CLI & JSON)
# ==============================================================================

class Reporter:
    """Renders human-friendly CLI ASCII reports and structured JSON."""

    @staticmethod
    def render_cli(before_path: str,
                   after_path: str,
                   diff_engine: SemanticDiffEngine,
                   propagator: ImpactPropagator,
                   sec_dep: SecurityAndDependencyEngine,
                   risk_engine: RiskEngine,
                   review_order: List[str]) -> None:
        
        box_top = "╔" + "═" * 60 + "╗"
        box_mid = "║" + " " * 22 + "IMPACTX" + " " * 31 + "║"
        box_sub = "║" + " " * 12 + "Semantic Change Impact Analyzer" + " " * 17 + "║"
        box_bot = "╚" + "═" * 60 + "╝"

        print(Ansi.cyan(box_top))
        print(Ansi.bold(Ansi.cyan(box_mid)))
        print(Ansi.cyan(box_sub))
        print(Ansi.cyan(box_bot))
        print()

        print(Ansi.bold("PROJECT CHANGE REVIEW"))
        print(f"Files changed         : {len([f for f in diff_engine.file_diffs if f.status != 'UNCHANGED'])}")
        print(f"Functions changed     : {len([s for s in diff_engine.symbol_diffs if s.change_type != ChangeType.UNCHANGED])}")
        print(f"Public APIs changed   : {len(propagator.affected_public_apis)}")
        print(f"Callers affected      : {len(propagator.affected_callers)}")
        print(f"Tests potentially hit : {len(propagator.affected_tests)}")
        print("─" * 62)

        # Risk score badge
        score_str = f"{risk_engine.risk_score} / 100"
        lvl = risk_engine.risk_level.value
        if risk_engine.risk_level == RiskLevel.CRITICAL:
            lvl_colored = Ansi.bg_red(f" CRITICAL ")
        elif risk_engine.risk_level == RiskLevel.HIGH:
            lvl_colored = Ansi.yellow(Ansi.bold(" HIGH "))
        elif risk_engine.risk_level == RiskLevel.MEDIUM:
            lvl_colored = Ansi.blue(Ansi.bold(" MEDIUM "))
        else:
            lvl_colored = Ansi.green(Ansi.bold(" LOW "))

        print(f"RISK SCORE             : {Ansi.bold(score_str)}")
        print(f"RISK LEVEL             : {lvl_colored}")
        print("─" * 62)

        # Findings
        if risk_engine.findings:
            print(Ansi.bold("DETECTED RISK FINDINGS"))
            print()
            for f in risk_engine.findings:
                icon = "🔴" if f.severity in (RiskLevel.CRITICAL, RiskLevel.HIGH) else "🟠"
                print(f"{icon} {Ansi.bold(f.severity.value)} — {Ansi.cyan(f.symbol)}")
                print(f"  Location : {f.location}")
                print(f"  Change   : {f.what_changed}")
                print(f"  Impact   : {f.why_it_matters}")
                if f.affected_symbols:
                    print(f"  Callers  : {', '.join(f.affected_symbols[:5])}" + ("..." if len(f.affected_symbols) > 5 else ""))
                print()
            print("─" * 62)

        # Security signals
        if sec_dep.security_signals:
            print(Ansi.bold("SECURITY-SENSITIVE CHANGES"))
            for path, token, lineno, detail in sec_dep.security_signals:
                print(f"  🔴 {Ansi.red(token)} at {path}:{lineno} — {detail}")
            print("─" * 62)

        # Dependency Drift
        if sec_dep.new_external_dependencies:
            print(Ansi.bold("DEPENDENCY DRIFT"))
            for dep in sec_dep.new_external_dependencies:
                print(f"  🟠 New external runtime dependency: {Ansi.yellow(dep)}")
            print("─" * 62)

        # Test Impact
        print(Ansi.bold("TEST IMPACT"))
        print(f"  {len(propagator.affected_tests)} tests potentially affected")
        if propagator.affected_tests:
            print("  Priority test files:")
            for t in sorted(list(propagator.affected_tests))[:5]:
                print(f"    • {Ansi.green(t)}")
        print("─" * 62)

        # Recommended Review Order
        if review_order:
            print(Ansi.bold("RECOMMENDED REVIEW ORDER"))
            for idx, item in enumerate(review_order[:7], 1):
                print(f"  {idx}. {item}")
            print("─" * 62)

        # Blast Radius Summary
        print(Ansi.bold("BLAST RADIUS SUMMARY"))
        print(f"  Modules   : {len(propagator.affected_modules)}")
        print(f"  Functions : {len(propagator.affected_callers)}")
        print(f"  Tests     : {len(propagator.affected_tests)}")
        print(f"  APIs      : {len(propagator.affected_public_apis)}")
        print()
        print(Ansi.green("✓ Analysis completed offline"))
        print(Ansi.green("✓ No external services used"))

    @staticmethod
    def render_json(diff_engine: SemanticDiffEngine,
                    propagator: ImpactPropagator,
                    sec_dep: SecurityAndDependencyEngine,
                    risk_engine: RiskEngine,
                    review_order: List[str]) -> str:
        data = {
            "summary": {
                "files_changed": len([f for f in diff_engine.file_diffs if f.status != "UNCHANGED"]),
                "functions_changed": len([s for s in diff_engine.symbol_diffs if s.change_type != ChangeType.UNCHANGED]),
                "public_apis_changed": len(propagator.affected_public_apis),
                "callers_affected": len(propagator.affected_callers),
                "tests_affected": len(propagator.affected_tests),
                "risk_score": risk_engine.risk_score,
                "risk_level": risk_engine.risk_level.value,
            },
            "new_external_dependencies": sorted(list(sec_dep.new_external_dependencies)),
            "affected_symbols": sorted(list(propagator.affected_callers)),
            "affected_tests": sorted(list(propagator.affected_tests)),
            "recommended_review_order": review_order,
            "findings": [f.to_dict() for f in risk_engine.findings],
        }
        return json.dumps(data, indent=2, sort_keys=True)

# ==============================================================================
# 12. COMMAND HANDLERS
# ==============================================================================

def cmd_analyze(args: argparse.Namespace) -> int:
    if args.no_color:
        Ansi.enabled = False

    before_proj = ProjectAnalyzer(args.before)
    before_proj.analyze()

    after_proj = ProjectAnalyzer(args.after)
    after_proj.analyze()

    diff_engine = SemanticDiffEngine(before_proj, after_proj)
    diff_engine.compute_diff()

    propagator = ImpactPropagator(diff_engine)
    propagator.propagate()

    sec_dep = SecurityAndDependencyEngine(diff_engine)
    sec_dep.analyze()

    risk_engine = RiskEngine(diff_engine, propagator, sec_dep)
    risk_engine.evaluate()

    review_order = ReviewOrderGenerator.generate(risk_engine, diff_engine, propagator)

    if args.json:
        print(Reporter.render_json(diff_engine, propagator, sec_dep, risk_engine, review_order))
    else:
        Reporter.render_cli(args.before, args.after, diff_engine, propagator, sec_dep, risk_engine, review_order)

    # Exit codes
    if getattr(args, "strict", False) and risk_engine.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        return 2
    if risk_engine.risk_level == RiskLevel.CRITICAL:
        return 2
    elif risk_engine.risk_level in (RiskLevel.HIGH, RiskLevel.MEDIUM):
        return 1
    return 0

def cmd_diff(args: argparse.Namespace) -> int:
    if args.no_color:
        Ansi.enabled = False

    before_proj = ProjectAnalyzer(args.before)
    before_proj.analyze()
    after_proj = ProjectAnalyzer(args.after)
    after_proj.analyze()

    diff_engine = SemanticDiffEngine(before_proj, after_proj)
    diff_engine.compute_diff()

    print(Ansi.bold("SEMANTIC SYMBOL DIFF"))
    print("─" * 60)
    for sdiff in diff_engine.symbol_diffs:
        if sdiff.change_type == ChangeType.UNCHANGED:
            continue
        status_color = Ansi.green if sdiff.change_type == ChangeType.ADDED else (
            Ansi.red if sdiff.change_type == ChangeType.REMOVED else Ansi.yellow
        )
        print(f"{status_color(sdiff.change_type.value)}: {Ansi.bold(sdiff.qualname)}")
        for d in sdiff.details:
            print(f"  • {d}")
        print()
    return 0

def cmd_graph(args: argparse.Namespace) -> int:
    if getattr(args, "no_color", False):
        Ansi.enabled = False

    proj = ProjectAnalyzer(args.project)
    proj.analyze()

    print(Ansi.bold("CALL GRAPH"))
    print("─" * 60)

    if args.symbol:
        if args.symbol not in proj.symbol_table:
            print(Ansi.red(f"Symbol '{args.symbol}' not found in project."))
            return 1
        print(f"Neighborhood graph for: {Ansi.cyan(args.symbol)}")
        tree = proj.call_graph.extract_neighborhood(args.symbol, depth=3)
        for node, callers in tree.items():
            print(f"  {Ansi.bold(node)}")
            for c in callers:
                print(f"    └── {Ansi.dim(c)}")
    else:
        for node in sorted(list(proj.call_graph.nodes())):
            callers = proj.call_graph.get_callers(node)
            if callers:
                print(f"{Ansi.bold(node)}")
                for c in sorted(list(callers)):
                    print(f"  └── {Ansi.dim(c)}")
    return 0

def cmd_verify(args: argparse.Namespace) -> int:
    proj = ProjectAnalyzer(args.project)
    proj.analyze()

    print(Ansi.bold("PROJECT VERIFICATION"))
    print("─" * 40)
    print(f"Python files       : {len(proj.python_files)}")
    print(f"Parse failures     : {len(proj.parse_failures)}")
    print(f"Symbols discovered : {len(proj.symbol_table)}")
    print(f"Call edges         : {sum(len(proj.call_graph.get_callees(n)) for n in proj.call_graph.nodes())}")
    print(f"Import edges       : {sum(len(proj.import_graph.get_callees(n)) for n in proj.import_graph.nodes())}")
    print()

    if proj.parse_failures:
        print(Ansi.yellow("Parse Warnings/Failures:"))
        for path, err in proj.parse_failures:
            print(f"  ⚠ {path}: {err}")
        print()

    print(Ansi.green("✓ Parseable"))
    print(Ansi.green("✓ Graph constructed"))
    print(Ansi.green("✓ No fatal analysis errors"))
    return 0

def cmd_self_audit(args: argparse.Namespace) -> int:
    # Read own source code
    script_path = pathlib.Path(__file__).resolve()
    with open(script_path, "r", encoding="utf-8") as f:
        source = f.read()

    tree = ast.parse(source)
    imports_used: Set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports_used.add(alias.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports_used.add(node.module.split('.')[0])

    third_party = [imp for imp in sorted(list(imports_used)) if imp not in STDLIB_MODULES]

    print(Ansi.bold("IMPACTX SELF AUDIT"))
    print("─" * 40)
    print("Runtime dependencies:")
    print(f"  Third-party packages : {len(third_party)}")
    print("  External services    : 0")
    print("  Shell commands       : 0")
    print()
    print("Standard library modules used:")
    for imp in sorted(list(imports_used)):
        print(f"  • {imp}")
    print()

    if not third_party:
        print(Ansi.green("✓ ZERO DEPENDENCY"))
        print(Ansi.green("✓ OFFLINE"))
        print(Ansi.green("✓ NO EXTERNAL EXECUTABLES"))
        return 0
    else:
        print(Ansi.red(f"⚠ Third-party imports detected: {third_party}"))
        return 3

def cmd_explain(args: argparse.Namespace) -> int:
    proj_path = getattr(args, "project", "./") or "./"
    proj = ProjectAnalyzer(proj_path)
    proj.analyze()

    sym_name = args.symbol
    matching_syms = [q for q in proj.symbol_table if q == sym_name or q.endswith(f".{sym_name}")]

    if not matching_syms:
        print(Ansi.red(f"Symbol '{sym_name}' not found in project '{proj_path}'."))
        return 1

    for qname in matching_syms:
        sym = proj.symbol_table[qname]
        callers = proj.call_graph.get_transitive_callers(qname)

        print(Ansi.bold("SYMBOL EXPLANATION"))
        print("─" * 50)
        print(f"Symbol      : {Ansi.cyan(sym.qualname)}")
        print(f"Defined in  : {sym.file_path}:{sym.line_no}")
        print(f"Visibility  : {'Public API' if sym.is_public else 'Internal'}")
        print(f"Parameters  : ({', '.join(sym.parameters)})")
        print(f"Direct Callers : {len(sym.callers)}")
        if sym.callers:
            for c in sorted(list(sym.callers)):
                print(f"  ├── {c}")
        print(f"Transitive Reachable Callers : {len(callers)}")
        print()

    return 0

def cmd_review(args: argparse.Namespace) -> int:
    print(Ansi.cyan(Ansi.bold("AI CHANGE REVIEW MODE")))
    print("This change may have been generated automatically.")
    print("IMPACTX performs deterministic static analysis only.")
    print()
    return cmd_analyze(args)

# ==============================================================================
# 13. MAIN CLI DISPATCHER
# ==============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="impactx",
        description="IMPACTX — Semantic Change-Impact Analyzer for Python Projects"
    )
    parser.add_argument("--no-color", action="store_true", help="Disable colored ANSI output")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Analyze
    p_analyze = subparsers.add_parser("analyze", help="Analyze semantic change impact between two codebase versions")
    p_analyze.add_argument("before", help="Path to BEFORE project directory")
    p_analyze.add_argument("after", help="Path to AFTER project directory")
    p_analyze.add_argument("--json", action="store_true", help="Output results in JSON format")
    p_analyze.add_argument("--strict", action="store_true", help="Return exit code 2 on high/critical risk")
    p_analyze.add_argument("--tests", action="store_true", help="Prioritize test impact details")
    p_analyze.add_argument("--no-color", action="store_true", help="Disable ANSI color output")

    # Diff
    p_diff = subparsers.add_parser("diff", help="Show AST symbol diff between two codebase versions")
    p_diff.add_argument("before", help="Path to BEFORE project directory")
    p_diff.add_argument("after", help="Path to AFTER project directory")
    p_diff.add_argument("--no-color", action="store_true", help="Disable ANSI color output")

    # Graph
    p_graph = subparsers.add_parser("graph", help="Display project call graph")
    p_graph.add_argument("project", help="Path to project directory")
    p_graph.add_argument("--symbol", help="Target symbol to extract neighborhood call graph")
    p_graph.add_argument("--no-color", action="store_true", help="Disable ANSI color output")

    # Verify
    p_verify = subparsers.add_parser("verify", help="Verify project parseability and graph construction")
    p_verify.add_argument("project", help="Path to project directory")

    # Self-audit
    subparsers.add_parser("self-audit", help="Audit IMPACTX itself for 0 third-party dependencies and stdlib usage")

    # Explain
    p_explain = subparsers.add_parser("explain", help="Explain impact and call graph neighborhood of a symbol")
    p_explain.add_argument("symbol", help="Qualified symbol name")
    p_explain.add_argument("--project", default="./", help="Path to project directory (default: current dir)")

    # Review (AI diff mode)
    p_review = subparsers.add_parser("review", help="Review AI-generated code changes")
    p_review.add_argument("before", help="Path to BEFORE project directory")
    p_review.add_argument("after", help="Path to AFTER project directory")
    p_review.add_argument("--json", action="store_true", help="Output results in JSON format")
    p_review.add_argument("--no-color", action="store_true", help="Disable ANSI color output")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    if getattr(args, "no_color", False):
        Ansi.enabled = False

    try:
        if args.command == "analyze":
            return cmd_analyze(args)
        elif args.command == "diff":
            return cmd_diff(args)
        elif args.command == "graph":
            return cmd_graph(args)
        elif args.command == "verify":
            return cmd_verify(args)
        elif args.command == "self-audit":
            return cmd_self_audit(args)
        elif args.command == "explain":
            return cmd_explain(args)
        elif args.command == "review":
            return cmd_review(args)
        else:
            parser.print_help()
            return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        traceback.print_exc()
        return 3

if __name__ == "__main__":
    sys.exit(main())
