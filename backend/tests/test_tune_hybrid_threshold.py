"""Selección de umbral: restricción FPR, desempates y aislamiento."""
import unittest

from ml_scripts.generate_synthetic import generate_synthetic
from ml_scripts.tune_hybrid_threshold import select_threshold, fit_hybrid


class ThresholdTests(unittest.TestCase):
    def test_optimizes_recall_with_fpr_constraint(self):
        result = select_threshold([0, 0, 0, 0, 1, 1], [.1, .2, .3, .4, .6, .9])
        selected = result["chosen"]
        self.assertEqual(selected["threshold"], .6)
        self.assertEqual(selected["metrics"]["recall"], 1.0)
        self.assertEqual(selected["metrics"]["error_rates"]["false_positive_rate"], 0.0)

    def test_no_feasible_threshold(self):
        result = select_threshold([0, 1], [1.0, 1.0])
        self.assertIsNone(result["chosen"])

    def test_invalid_inputs(self):
        for labels, values in [([0, 0], [.1, .2]), ([0, 1], [.5]),
                               ([0, 1], [float("nan"), .5]), ([0, 1], [-.1, .5])]:
            with self.assertRaises(ValueError):
                select_threshold(labels, values)

    def test_exact_fpr_constraint(self):
        labels = [0] * 9 + [1]
        result = select_threshold(labels, [.9] + [.1] * 8 + [.8])
        self.assertEqual(result["chosen"]["metrics"]["confusion_matrix"]["fp"], 0)

    def test_fit_does_not_include_validation_or_test_in_training(self):
        real = generate_synthetic(60, seed=11)
        synthetic = generate_synthetic(20, seed=12)
        report, bundle = fit_hybrid(real, synthetic, {"excluded-group"})
        self.assertEqual(report["evaluation_kind"], "development_threshold_selection_only")
        self.assertEqual(report["real_train_count"] + report["real_validation_count"] +
                         report["previous_test_not_used_count"], len(real))
        self.assertEqual(report["synthetic_train_count"], 40)
        if bundle is not None:
            self.assertTrue(bundle["experimental_only"])
            self.assertIn("excluded-group", bundle["dataset_group_fingerprints"])
            self.assertEqual(bundle["decision_threshold"], report["selection"]["chosen"]["threshold"])
            self.assertNotIn("test_metrics", bundle)

    def test_fit_rejects_overlap(self):
        real = generate_synthetic(60, seed=11)
        with self.assertRaisesRegex(ValueError, "Solapamiento"):
            fit_hybrid(real, real, set())


if __name__ == "__main__":
    unittest.main()
