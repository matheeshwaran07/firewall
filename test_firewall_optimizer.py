import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from firewall_optimizer import (
    Rule, validate_rule, remove_duplicates, find_conflicts, optimize_rules
)


class FirewallOptimizerTests(unittest.TestCase):
    def setUp(self):
        self.rules = [
            Rule(1, "192.168.1.10", 80, "TCP", "ALLOW"),
            Rule(2, "192.168.1.10", 80, "TCP", "ALLOW"),
            Rule(3, "192.168.1.10", 80, "TCP", "DENY"),
        ]

    def test_valid_rule(self):
        self.assertTrue(validate_rule(self.rules[0]))

    def test_invalid_port(self):
        bad = Rule(4, "192.168.1.10", 70000, "TCP", "ALLOW")
        self.assertFalse(validate_rule(bad))

    def test_duplicate_removal(self):
        result, removed = remove_duplicates(self.rules)
        self.assertEqual(len(result), 2)
        self.assertEqual(removed, 1)

    def test_conflict_detection(self):
        conflicts = find_conflicts(self.rules)
        self.assertEqual(len(conflicts), 2)

    def test_optimization(self):
        result, removed = optimize_rules(self.rules)
        self.assertEqual(removed, 1)
        self.assertEqual(len(result), 2)


if __name__ == "__main__":
    unittest.main()
