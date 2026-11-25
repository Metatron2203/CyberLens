"""Pruebas de infraestructura para el experimento sintético/híbrido."""
import unittest
from collections import Counter
from urllib.parse import urlsplit

from ml_scripts.generate_synthetic import generate_synthetic
from ml_scripts.compare_hybrid import compare_modes


class SyntheticComparisonTests(unittest.TestCase):
    def test_balanced_reserved_and_reproducible(self):
        rows = generate_synthetic(40, seed=10)
        self.assertEqual(rows, generate_synthetic(40, seed=10))
        self.assertEqual(Counter(r[1] for r in rows), {0: 40, 1: 40})
        self.assertEqual(len({r[2] for r in rows}), 80)
        for _, _, _, url in rows:
            parts = urlsplit(url)
            self.assertEqual(parts.scheme, "https")
            self.assertTrue(parts.hostname.endswith(".test"))
            self.assertIsNone(parts.username)
            self.assertIsNone(parts.password)

    def test_size_bounds(self):
        for count in (0, 19, 1001):
            with self.assertRaises(ValueError):
                generate_synthetic(count)

    def test_shared_validation_and_separate_training_counts(self):
        # Datos ficticios también para esta prueba de infraestructura.
        real_fixture = generate_synthetic(60, seed=11)
        synthetic = generate_synthetic(20, seed=12)
        report = compare_modes(real_fixture, synthetic)
        self.assertEqual(report["evaluation_kind"], "development_validation_only")
        self.assertEqual(set(report["experiments"]), {"A_real", "B_synthetic", "C_hybrid"})
        experiments = report["experiments"]
        n = report["real_train_count"]
        self.assertEqual(experiments["A_real"]["training_count"], n)
        self.assertEqual(experiments["B_synthetic"]["training_count"], 40)
        self.assertEqual(experiments["C_hybrid"]["training_count"], n + 40)
        for result in experiments.values():
            self.assertEqual(result["validation_metrics"]["support"]["total"],
                             report["real_validation_count"])
        self.assertEqual(n + report["real_validation_count"] +
                         report["previous_test_not_used_count"], 120)

    def test_rejects_overlapping_groups(self):
        rows = generate_synthetic(60, seed=13)
        with self.assertRaisesRegex(ValueError, "superponen"):
            compare_modes(rows, rows)


if __name__ == "__main__":
    unittest.main()
