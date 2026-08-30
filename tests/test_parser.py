import unittest
import pathlib
import sys
import os

# Add root directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from impactx import PythonASTVisitor, SymbolType, Symbol

class TestParser(unittest.TestCase):
    def test_extract_symbols(self):
        code = """
import os
from app.config import TIMEOUT

class AuthManager:
    def login(self, username, password):
        return True

def create_user(name, email="default@example.com"):
    eval("print('test')")
    return name
"""
        visitor = PythonASTVisitor(module_name="auth", file_path="auth.py")
        import ast
        tree = ast.parse(code)
        visitor.visit(tree)

        # Check extracted symbols
        self.assertIn("auth.AuthManager", visitor.symbols)
        self.assertIn("auth.AuthManager.login", visitor.symbols)
        self.assertIn("auth.create_user", visitor.symbols)

        # Check params & defaults
        sym_fn = visitor.symbols["auth.create_user"]
        self.assertEqual(sym_fn.parameters, ["name", "email"])
        self.assertEqual(sym_fn.required_param_count, 1)

        # Check security trigger for eval
        eval_trigs = [t for t in visitor.security_triggers if t[0] == "eval"]
        self.assertTrue(len(eval_trigs) > 0)

if __name__ == "__main__":
    unittest.main()
