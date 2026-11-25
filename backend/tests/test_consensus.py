"""Pruebas del consenso y de sus métricas con abstención."""
import unittest
from app.analyzer.consensus import decide
from ml_scripts.evaluate_consensus import selective_metrics


class ConsensusTests(unittest.TestCase):
    def test_both_alert(self):
        self.assertEqual(decide(25, .4, .4)["level"], "high")

    def test_neither_alert(self):
        self.assertEqual(decide(24, .39, .4)["level"], "low")

    def test_disagreement_in_both_directions(self):
        self.assertEqual(decide(24, .4, .4)["level"], "uncertain")
        self.assertEqual(decide(25, .39, .4)["level"], "uncertain")

    def test_missing_or_invalid_ml_is_uncertain(self):
        for p in (None, float("nan"), -1, 2):
            self.assertEqual(decide(0, p, .4)["reason"], "ml_unavailable")

    def test_invalid_threshold_or_heuristic(self):
        for h, t in ((101, .4), (0, 0), (0, float("nan"))):
            with self.assertRaises(ValueError):
                decide(h, .5, t)

    def test_uncertainty_does_not_hide_missed_phishing(self):
        report = selective_metrics([0, 0, 0, 1, 1, 1],
                                   ["low", "uncertain", "high", "low", "uncertain", "high"])
        self.assertEqual(report["counts"]["phishing"]["low"], 1)
        self.assertEqual(report["coverage"], .6667)
        self.assertEqual(report["selective_error_rate"], .5)
        self.assertEqual(report["phishing_marked_low_rate"], .3333)
        self.assertEqual(report["phishing_alert_or_uncertain_rate"], .6667)
        self.assertEqual(report["legitimate_alert_or_uncertain_rate"], .6667)

    def test_all_uncertain_has_no_selective_error_estimate(self):
        report = selective_metrics([0, 1], ["uncertain", "uncertain"])
        self.assertEqual(report["coverage"], 0)
        self.assertIsNone(report["selective_error_rate"])

    def test_rejects_invalid_decisions(self):
        with self.assertRaises(ValueError):
            selective_metrics([0, 1], ["low", "safe"])


if __name__ == "__main__":
    unittest.main()
