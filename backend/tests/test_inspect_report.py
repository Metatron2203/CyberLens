"""Inspección del informe ya generado: no descargar ni reentrenar."""

import unittest

from ml_scripts.inspect_report import inspect_report


class InspectReportTests(unittest.TestCase):
    def test_interprets_existing_confusion_matrix(self):
        report = {"test_metrics": {"confusion_matrix": {"tn": 49, "fp": 0, "fn": 2, "tp": 15}}}
        out = inspect_report(report)
        self.assertEqual(out["test_total"], 66)
        self.assertEqual(out["test_phishing"], 17)
        self.assertEqual(out["false_negative_count"], 2)
        self.assertEqual(out["recall"], 0.8824)
        self.assertGreater(out["false_positive_rate_wilson_95"]["upper"], 0.05)

    def test_invalid_values_are_rejected(self):
        for matrix in (
            {"tn": -1, "fp": 0, "fn": 0, "tp": 1},
            {"tn": "2", "fp": 0, "fn": 0, "tp": 1},
            {"tn": 1, "fp": 0, "fn": 0},
        ):
            with self.subTest(matrix=matrix):
                with self.assertRaises(ValueError):
                    inspect_report({"test_metrics": {"confusion_matrix": matrix}})


if __name__ == "__main__":
    unittest.main()
