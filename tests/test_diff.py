import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from impactx import ProjectAnalyzer, SemanticDiffEngine, ChangeType

class TestDiff(unittest.TestCase):
    def test_semantic_diff_breaking_api(self):
        before = ProjectAnalyzer("demo_before")
        before.analyze()

        after = ProjectAnalyzer("demo_after")
        after.analyze()

        diff_engine = SemanticDiffEngine(before, after)
        diff_engine.compute_diff()

        # Check create_user breaking API
        create_user_diffs = [s for s in diff_engine.symbol_diffs if "create_user" in s.qualname]
        self.assertTrue(len(create_user_diffs) > 0)
        self.assertTrue(create_user_diffs[0].is_breaking_api)
        self.assertEqual(create_user_diffs[0].change_type, ChangeType.SIGNATURE_CHANGED)

if __name__ == "__main__":
    unittest.main()
