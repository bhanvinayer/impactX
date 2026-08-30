# IMPACTX

> **AI writes the code. IMPACTX tells you what it can break.**

IMPACTX is an offline, zero-third-party-dependency developer CLI that performs **semantic change-impact analysis** on Python projects. By comparing two codebase versions (`BEFORE` and `AFTER`), IMPACTX constructs dependency and call graphs, calculates the blast radius of changes, detects breaking API modifications, identifies affected test suites, detects security-sensitive code changes, and produces an explainable risk report.

---

## 1. The Problem

Modern developers increasingly use AI coding agents (and fast refactoring tools) to modify large portions of their codebase in seconds.

Traditional diff tools only answer:
> *"What lines changed?"*

The critical question for developers, reviewers, and CI/CD pipelines is:
> **"What does this change affect, what could it break, and what should I review or test first?"**

A standard textual diff shows line additions or removals, but fails to convey:
* Which functions call the modified function downstream.
* Which modules and public APIs are broken by signature changes.
* Which tests need to run to validate the change.
* Whether security-sensitive behavior (e.g., dynamic execution or auth changes) was introduced.
* How large the downstream blast radius is.

---

## 2. The Solution

IMPACTX parses Python source code into Abstract Syntax Trees (AST), extracts symbols and call graphs, and computes transitive reachability across the codebase:

```text
BEFORE VERSION
        +
AFTER VERSION
        ↓
     IMPACTX
        ↓
WHAT CHANGED?
WHAT DEPENDS ON IT?
WHAT COULD BREAK?
WHAT SHOULD BE TESTED?
HOW RISKY IS IT?
```

* **100% Offline**: Works without cloud APIs, internet access, or external executables.
* **Zero Runtime Dependencies**: Written entirely using standard Python 3 standard library modules.
* **Deterministic Risk Scoring**: Explainable 0–100 risk score with actionable recommendation rankings.

---

## 3. Features

* 🔍 **Deep AST Semantic Analysis**: Tracks functions, methods, classes, signatures, parameter changes, default values, decorators, and constants.
* 🕸️ **Custom Graph Engine**: Purpose-built stdlib directed graph replacing NetworkX to calculate transitive caller reachability.
* 🚨 **Breaking API Detection**: Automatically flags public function removals, parameter renames/additions, required parameters, or route changes.
* 💣 **Transitive Blast-Radius Tracing**: Traces changes from a single symbol through direct callers, indirect callers, modules, endpoints, and test suites.
* 🛡️ **Security Signal Detector**: Flags change-sensitive security modifications involving `eval`, `exec`, `subprocess`, `shell=True`, `base64`, `secrets`, `.env`, and credentials.
* 📦 **Dependency Drift Analysis**: Classifies imports as Standard Library, Local, or External to detect newly introduced third-party package dependencies.
* ⚙️ **Configuration Shift Detection**: Tracks changes in uppercase configuration constants (e.g., `TIMEOUT = 30` → `TIMEOUT = 300`) and identifies dependent components.
* 🧪 **Static Test Impact Mapping**: Discovers test suites (`test_*.py`, `*_test.py`) and maps them to impacted application symbols.
* 📋 **Prioritized Review Order**: Ranks modified symbols by risk score, blast radius, security sensitivity, and API impact.
* 📊 **JSON & CLI Modes**: Outputs rich terminal formatted tables and machine-readable JSON for CI integration.

---

## 4. Architecture

```text
                    IMPACTX CLI (impactx.py)
                                │
                                ▼
                        PROJECT DISCOVERY
                                │
                                ▼
                         FILE COMPARATOR
                          (difflib.py)
                                │
                                ▼
                         PYTHON PARSER
                            (ast.py)
                                │
            ┌───────────────────┼───────────────────┐
            ▼                   ▼                   ▼
       SYMBOL TABLE        CALL GRAPH          IMPORT GRAPH
            │                   │                   │
            └───────────────────┼───────────────────┘
                                ▼
                         CHANGE ANALYZER
                                │
                                ▼
                        IMPACT PROPAGATOR
                         (DirectedGraph)
                                │
                                ▼
                          RISK ENGINE
                                │
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                 ▼
          TEST IMPACT          API             SECURITY
                            IMPACT             SIGNALS
              │                 │                 │
              └─────────────────┼─────────────────┘
                                ▼
                          REPORT ENGINE
                                │
             ┌──────────────────┴──────────────────┐
             ▼                                     ▼
        Human CLI Report                       JSON Report
```

---

## 5. Quickstart & Usage

IMPACTX requires **Python 3.10+** (or Python 3.14) with **no `pip install` required**.

### Analyze Impact Between Two Versions
```bash
python impactx.py analyze ./demo_before ./demo_after
```

### JSON Output Mode (for CI/CD pipelines)
```bash
python impactx.py analyze ./demo_before ./demo_after --json
```

### CI Strict Mode (Exit code 2 on High/Critical Risk)
```bash
python impactx.py analyze ./demo_before ./demo_after --strict
```

### Show Symbol AST Diffs
```bash
python impactx.py diff ./demo_before ./demo_after
```

### Inspect Call Graph & Neighborhoods
```bash
python impactx.py graph ./demo_after
python impactx.py graph ./demo_after --symbol validate_token
```

### Explain Symbol Impact & Caller Hierarchy
```bash
python impactx.py explain validate_token --project ./demo_after
```

### Verify Project Parseability
```bash
python impactx.py verify ./demo_after
```

### Perform Self-Audit (0-Dependency Check)
```bash
python impactx.py self-audit
```

---

## 6. Example Output

```text
╔════════════════════════════════════════════════════════════╗
║                      IMPACTX                               ║
║            Semantic Change Impact Analyzer                 ║
╚════════════════════════════════════════════════════════════╝

PROJECT CHANGE REVIEW
Files changed         : 5
Functions changed     : 6
Public APIs changed   : 6
Callers affected      : 8
Tests potentially hit : 2
──────────────────────────────────────────────────────────────
RISK SCORE             : 100 / 100
RISK LEVEL             :  CRITICAL 
──────────────────────────────────────────────────────────────
DETECTED RISK FINDINGS

🔴 CRITICAL — exec
  Location : app/auth.py:9
  Change   : Security-sensitive behavior detected: Dynamic execution with exec()
  Impact   : Modifying auth or adding dynamic execution introduces severe vulnerability risks.

🔴 HIGH — app.auth.create_user
  Location : app/auth.py:33
  Change   : Parameters changed from (name, email) to (name, email, role) | New required parameter(s) added to public API: role
  Impact   : Public API signature altered or removed. 8 downstream callers may fail.

🟠 MEDIUM — app.config.TIMEOUT
  Location : app/config.py
  Change   : Configuration constant app.config.TIMEOUT value changed from 30 to 300
  Impact   : Altering system constants can change runtime timing, memory, or connection limits.

──────────────────────────────────────────────────────────────
TEST IMPACT
  2 tests potentially affected
  Priority test files:
    • tests/test_auth.py
    • tests/test_users.py
──────────────────────────────────────────────────────────────
RECOMMENDED REVIEW ORDER
  1. exec() in app/auth.py:9 — Security signal: Dynamic execution with exec()
  2. app.auth.create_user() — Breaking API change
  3. app.config.TIMEOUT (app/config.py) — Config change: 30 -> 300
──────────────────────────────────────────────────────────────
✓ Analysis completed offline
✓ No external services used
```

---

## 7. Zero Third-Party Dependencies

IMPACTX is built entirely using standard Python modules. No packages need to be installed.

`requirements.txt` is intentionally empty.

See [STDLIB.md](./STDLIB.md) for full engineering documentation on standard library replacements:
* `networkx` → Custom stdlib `DirectedGraph` using `dict` & `collections.deque`
* `rich` / `colorama` → ANSI escape codes with `sys.stdout.isatty()` auto-detection
* `click` / `typer` → `argparse` with subparsers
* `GitPython` → `pathlib` & `difflib`
* `pydantic` → `@dataclasses.dataclass`
* `orjson` → `json` with sorted keys

---

## 8. Limitations

IMPACTX performs **static code analysis**.

It cannot resolve:
* **Dynamic dispatch**: calls via `getattr(obj, name)()` or `globals()[name]()`.
* **Runtime magic**: heavy reflection, metaprogramming, or monkey-patching at runtime.
* **Dynamic imports**: `importlib.import_module(var)`.

When IMPACTX detects dynamic patterns like `getattr` or `eval`, it flags a warning and notes that static resolution may be incomplete for that specific call edge.

---

## 9. Testing

Run the included unit test suite:
```bash
python -m unittest discover -s tests
```

---

## 10. Security & Safety

IMPACTX:
* Never imports or executes analyzed source code.
* Never shells out to system binaries (`git`, `grep`, `diff`).
* Operates as a purely static analyzer, treating all analyzed repositories as untrusted inputs.

---

## License

[MIT License](./LICENSE)
