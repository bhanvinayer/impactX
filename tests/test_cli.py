import unittest
import subprocess
import sys
import os

class TestCLI(unittest.TestCase):
    def test_self_audit_command(self):
        result = subprocess.run(
            [sys.executable, "impactx.py", "self-audit"],
            capture_output=True, text=True, cwd="."
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("ZERO DEPENDENCY", result.stdout)

    def test_verify_command(self):
        result = subprocess.run(
            [sys.executable, "impactx.py", "verify", "demo_after"],
            capture_output=True, text=True, cwd="."
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("PROJECT VERIFICATION", result.stdout)

    def test_json_analyze_command(self):
        result = subprocess.run(
            [sys.executable, "impactx.py", "analyze", "demo_before", "demo_after", "--json"],
            capture_output=True, text=True, cwd="."
        )
        self.assertIn('"risk_level": "CRITICAL"', result.stdout)

if __name__ == "__main__":
    unittest.main()
