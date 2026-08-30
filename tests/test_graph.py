import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from impactx import DirectedGraph

class TestGraph(unittest.TestCase):
    def test_directed_graph_traversal(self):
        graph = DirectedGraph()
        # Edge: caller -> callee (reverse is callee -> caller)
        graph.add_edge("login", "validate_token")
        graph.add_edge("validate_token", "decode_token")
        graph.add_edge("admin_session", "validate_token")

        # Test callers
        callers = graph.get_callers("validate_token")
        self.assertEqual(callers, {"login", "admin_session"})

        # Test transitive callers
        trans_callers = graph.get_transitive_callers("decode_token")
        self.assertEqual(trans_callers, {"validate_token", "login", "admin_session"})

        # Test callees
        callees = graph.get_callees("login")
        self.assertEqual(callees, {"validate_token"})

    def test_cycle_handling(self):
        graph = DirectedGraph()
        graph.add_edge("fn_a", "fn_b")
        graph.add_edge("fn_b", "fn_a") # cycle

        reach = graph.get_transitive_callers("fn_a")
        self.assertIn("fn_b", reach)

if __name__ == "__main__":
    unittest.main()
