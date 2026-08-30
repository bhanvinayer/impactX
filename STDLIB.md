# Standard Library Substitutions in IMPACTX

IMPACTX is built with **zero third-party runtime dependencies**. All analysis, parsing, graph computation, diffing, risk evaluation, and CLI rendering are powered strictly by Python's Standard Library.

Below is a detailed inventory of 10+ meaningful standard library substitutions used across IMPACTX.

---

## 1. Graph Computation & Reachability Engine

* **Third-Party Package:** `networkx`
* **STDLIB Replacement:** `dict[str, set[str]]` + `collections.deque`
* **Implementation Class:** `DirectedGraph`
* **Engineering Rationale:**
  IMPACTX only requires directed graph representation, edge insertion, forward/reverse reachability (BFS), and transitive caller lookup. Replacing `networkx` with a lightweight stdlib dictionary-based adjacency list avoids hundreds of kilobytes of external overhead while executing graph traversals in $O(V + E)$ time.

---

## 2. Command Line Interface Parsing

* **Third-Party Package:** `click` / `typer`
* **STDLIB Replacement:** `argparse`
* **Implementation Function:** `main()` & `subparsers`
* **Engineering Rationale:**
  `argparse` natively supports subcommands (`analyze`, `diff`, `graph`, `verify`, `self-audit`, `explain`, `review`), flags (`--json`, `--strict`, `--no-color`), help generation, and argument validation without external CLI frameworks.

---

## 3. Terminal Rich Text & ASCII Box Rendering

* **Third-Party Package:** `rich` / `colorama`
* **STDLIB Replacement:** ANSI escape sequences + custom `Ansi` helper class
* **Implementation Class:** `Ansi` & `Reporter`
* **Engineering Rationale:**
  Terminal styling in IMPACTX uses direct ANSI escape sequences (`\033[31m`, `\033[1m`, etc.) with automatic TTY detection (`sys.stdout.isatty()`) and an explicit `--no-color` override flag for CI environments.

---

## 4. AST Parsing & Semantic Extraction

* **Third-Party Package:** `radon` / `redbaron` / `parso`
* **STDLIB Replacement:** `ast`
* **Implementation Class:** `PythonASTVisitor`
* **Engineering Rationale:**
  Python's built-in `ast` module provides full syntax tree inspection. IMPACTX uses `ast.NodeVisitor` to extract functions, classes, parameters, default values, decorators, calls, docstrings, imports, and security-sensitive function call nodes directly from source text without external language parsers.

---

## 5. File Discovery & Path Traversal

* **Third-Party Package:** `pathlib2` / `watchdog`
* **STDLIB Replacement:** `pathlib.Path` & `fnmatch`
* **Implementation Function:** `ProjectAnalyzer.discover_files()`
* **Engineering Rationale:**
  `pathlib.Path.rglob()` allows recursive cross-platform directory crawling. Coupled with `fnmatch` and set-based ignore rules (`.git`, `__pycache__`, `.venv`, `node_modules`), IMPACTX discovers project files cleanly without shell utilities or external filesystem tools.

---

## 6. Textual Code Differencing

* **Third-Party Package:** `GitPython` / `git diff`
* **STDLIB Replacement:** `difflib.unified_diff`
* **Implementation Class:** `SemanticDiffEngine`
* **Engineering Rationale:**
  IMPACTX operates completely offline on local directory snapshots without needing a Git repository. `difflib` provides line-by-line diff statistics and line change counts directly.

---

## 7. Data Modeling & Structured Records

* **Third-Party Package:** `pydantic` / `attrs`
* **STDLIB Replacement:** `@dataclasses.dataclass`
* **Implementation Classes:** `Symbol`, `FileDiff`, `SymbolDiff`, `RiskFinding`
* **Engineering Rationale:**
  `dataclasses` standard module offers clean data encapsulation, default factory lists/sets, type hint clarity, and dictionary serialization methods without pydantic dependency.

---

## 8. Deterministic AST Hashing & Caching

* **Third-Party Package:** `xxhash` / `joblib`
* **STDLIB Replacement:** `hashlib.sha256`
* **Implementation Function:** `PythonASTVisitor` & `ProjectAnalyzer`
* **Engineering Rationale:**
  `hashlib.sha256()` produces deterministic hashes of normalized AST dumps (`ast.dump()`) and source content. This enables body modification detection independent of line numbers or docstring formatting.

---

## 9. Formatted JSON Output Engine

* **Third-Party Package:** `orjson` / `ujson`
* **STDLIB Replacement:** `json.dumps(..., indent=2, sort_keys=True)`
* **Implementation Class:** `Reporter.render_json()`
* **Engineering Rationale:**
  The `json` standard module easily converts nested dataclass dicts into machine-readable JSON reports. Using `sort_keys=True` guarantees deterministic output across runs.

---

## 10. Risk Level Categorization & Enums

* **Third-Party Package:** `enum34`
* **STDLIB Replacement:** `enum.Enum` & `enum.str`
* **Implementation Classes:** `SymbolType`, `ChangeType`, `RiskLevel`, `ImportCategory`
* **Engineering Rationale:**
  `enum` standard library module provides strongly-typed enumerations for symbols, change classifications, import types, and risk levels.

---

## 11. Queue-Based BFS Graph Reachability

* **Third-Party Package:** `queue` / `collections`
* **STDLIB Replacement:** `collections.deque`
* **Implementation Class:** `DirectedGraph.reachable_from()`
* **Engineering Rationale:**
  Double-ended queue `collections.deque` provides fast $O(1)$ append and popleft operations for breadth-first reachability search over directed call and import graphs.

---

## Summary Table

| Requirement | Replaced Third-Party Package | Standard Library Replacement |
| :--- | :--- | :--- |
| **Graph Traversal** | `networkx` | `dict[str, set[str]]` + `collections.deque` |
| **CLI Framework** | `click` / `typer` | `argparse` |
| **Terminal Formatting** | `rich` / `colorama` | ANSI escape sequences + `sys.stdout.isatty()` |
| **AST Analysis** | `radon` / `redbaron` | `ast` |
| **File Traversal** | `pathlib2` / `watchdog` | `pathlib.Path` + `fnmatch` |
| **Code Diffing** | `GitPython` / `git` | `difflib` |
| **Data Models** | `pydantic` | `dataclasses` |
| **AST Hashing** | `xxhash` | `hashlib` |
| **JSON Export** | `orjson` | `json` |
| **Enumerations** | `enum34` | `enum` |
