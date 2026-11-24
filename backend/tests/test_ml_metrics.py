"""Pruebas de métricas e inspección de sesgo (ejemplos ficticios)."""

import json
import unittest

from ml_scripts.audit import dataset_audit, feature_bias_profile
from ml_scripts.train import scores, wilson_interval


class ModelMetricTests(unittest.TestCase):
    def test_test_sample_confusion_and_intervals(self):
        # Reproducción numérica del resumen 49 TN, 0 FP, 2 FN y 15 TP,
        # sin incluir URLs ni datos externos.
        true = [0] * 49 + [1] * 17
        predicted = [0] * 49 + [0] * 2 + [1] * 15
        result = scores(true, predicted)
        self.assertEqual(result["confusion_matrix"], {"tn": 49, "fp": 0, "fn": 2, "tp": 15})
        self.assertEqual(result["support"]["phishing"], 17)
        self.assertEqual(result["support"]["candidate_legitimate"], 49)
        self.assertEqual(result["error_rates"]["false_negative_rate"], 0.1176)
        self.assertEqual(result["error_rates"]["false_positive_rate"], 0.0)
        self.assertLess(result["confidence_intervals_95_wilson"]["recall"]["lower"], 0.8)
        self.assertGreater(result["confidence_intervals_95_wilson"]["false_positive_rate"]["upper"], 0.05)

    def test_zero_predictions_does_not_create_fake_precision_interval(self):
        result = scores([0, 1], [0, 0])
        self.assertIsNone(result["confidence_intervals_95_wilson"]["precision"])
        self.assertEqual(result["support"]["predicted_phishing"], 0)

    def test_wilson_guards_empty_and_invalid_counts(self):
        self.assertIsNone(wilson_interval(0, 0))
        with self.assertRaises(ValueError):
            wilson_interval(4, 3)
        with self.assertRaises(ValueError):
            wilson_interval(-1, 3)
        bounds = wilson_interval(0, 49)
        self.assertEqual(bounds["lower"], 0.0)
        self.assertGreater(bounds["upper"], 0.05)


class FeatureBiasTests(unittest.TestCase):
    def test_profile_warns_about_http_shortcuts_without_urls(self):
        # Orden del esquema ficticio: uses_http, path_depth, url_length.
        feats = ("uses_http", "path_depth", "url_length")
        records = [
            ([1.0, 4.0, 150.0], 1, "a", "http://u:clave@phish.example/?token=SECRETO"),
            ([1.0, 5.0, 160.0], 1, "b", "http://other.example/"),
            ([0.0, 0.0, 20.0], 0, "c", "https://safe.example/"),
            ([0.0, 1.0, 25.0], 0, "d", "https://good.example/"),
        ]
        profile = feature_bias_profile(records, feats)
        self.assertEqual(profile["uses_http"]["phishing_mean"], 1.0)
        self.assertEqual(profile["uses_http"]["candidate_legitimate_mean"], 0.0)
        audit = dataset_audit(
            records, phishing_input_count=2, legitimate_input_count=2,
            conflicting_domain_groups=0, source="Muestras ficticias",
            feature_names=feats,
        )
        self.assertTrue(any("HTTP" in warning for warning in audit["warnings"]))
        self.assertTrue(any("profundidad" in warning for warning in audit["warnings"]))
        dumped = json.dumps(audit, ensure_ascii=False)
        self.assertNotIn("SECRETO", dumped)
        self.assertNotIn("clave", dumped)
        self.assertNotIn("phish.example", dumped)


if __name__ == "__main__":
    unittest.main()
