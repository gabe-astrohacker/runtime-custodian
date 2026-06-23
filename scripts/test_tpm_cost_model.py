"""Hermetic unit tests for the RQ-P4 TPM-cost model.

No TPM needed: exercises the pure projection/decision-rule logic so the model
that turns a per-extend cost into the policy-triggered-vs-extend-everything
saving is verified without hardware.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "run_tpm_cost_experiments",
    Path(__file__).resolve().parent / "run_tpm_cost_experiments.py",
)
mod = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = mod
_SPEC.loader.exec_module(mod)


class ExtendCountTest(unittest.TestCase):
    def test_extends_match_the_monitor_formula(self) -> None:
        # N=1000 events, s=50 suspicious: 2 fixed + per-event by strategy.
        self.assertEqual(mod.extends_for_strategy("final-summary", 1000, 50), 2)
        self.assertEqual(mod.extends_for_strategy("policy-triggered", 1000, 50), 52)
        self.assertEqual(mod.extends_for_strategy("extend-everything", 1000, 50), 1002)


class ProjectionTest(unittest.TestCase):
    def test_saving_equals_acceptable_events_times_cost(self) -> None:
        cost = 2.0
        [row] = mod.project_extend_costs(cost, [1000], [0.1])
        self.assertEqual(row["suspicious_events"], 100)
        self.assertEqual(row["acceptable_events"], 900)
        saving = row["policy_triggered_saving_vs_extend_everything"]
        # 900 acceptable events => 900 avoided extends * 2 ms.
        self.assertEqual(saving["extends"], 900)
        self.assertAlmostEqual(saving["wall_ms"], 1800.0)
        premium = row["policy_triggered_premium_vs_final_summary"]
        self.assertEqual(premium["extends"], 100)  # the suspicious events

    def test_crossover_saving_vanishes_when_all_events_suspicious(self) -> None:
        [row] = mod.project_extend_costs(1.0, [500], [1.0])
        self.assertEqual(row["policy_triggered_saving_vs_extend_everything"]["extends"], 0)
        # At f=1 policy-triggered == extend-everything.
        self.assertEqual(
            row["extends"]["policy-triggered"], row["extends"]["extend-everything"]
        )

    def test_max_saving_when_no_events_suspicious(self) -> None:
        [row] = mod.project_extend_costs(1.0, [500], [0.0])
        self.assertEqual(row["policy_triggered_saving_vs_extend_everything"]["extends"], 500)
        # policy-triggered degenerates to final-summary when nothing is suspicious.
        self.assertEqual(
            row["extends"]["policy-triggered"], row["extends"]["final-summary"]
        )

    def test_saving_is_monotonic_in_acceptable_fraction(self) -> None:
        rows = mod.project_extend_costs(1.0, [1000], [0.0, 0.25, 0.5, 1.0])
        savings = [r["policy_triggered_saving_vs_extend_everything"]["extends"] for r in rows]
        self.assertEqual(savings, sorted(savings, reverse=True))

    def test_decision_rule_mentions_the_cost(self) -> None:
        self.assertIn("3.50 ms", mod.decision_rule(3.5))


if __name__ == "__main__":
    unittest.main()
