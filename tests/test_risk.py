import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from impactx import (ProjectAnalyzer, SemanticDiffEngine, ImpactPropagator,
                      SecurityAndDependencyEngine, RiskEngine, RiskLevel)

class TestRisk(unittest.TestCase):
    def test_risk_evaluation(self):
        before = ProjectAnalyzer("demo_before")
        before.analyze()

        after = ProjectAnalyzer("demo_after")
        after.analyze()

        diff_engine = SemanticDiffEngine(before, after)
        diff_engine.compute_diff()

        propagator = ImpactPropagator(diff_engine)
        propagator.propagate()

        sec_dep = SecurityAndDependencyEngine(diff_engine)
        sec_dep.analyze()

        risk_engine = RiskEngine(diff_engine, propagator, sec_dep)
        risk_engine.evaluate()

        self.assertEqual(risk_engine.risk_level, RiskLevel.CRITICAL)
        self.assertGreaterEqual(risk_engine.risk_score, 71)

if __name__ == "__main__":
    unittest.main()
