"""Pruebas de la evaluación histórica Phish360 con fixtures ficticios."""
import tempfile
import unittest
from pathlib import Path
from collections import Counter

from app.ml.features import FEATURE_NAMES, FEATURE_SCHEMA, group_key
from ml_scripts.evaluate_phish360 import select_cases, compare, read_parquet_rows


def fixture():
    return [(f"https://demo-{label}-{i}.test/account", label)
            for label in (0, 1) for i in range(12)]


class MockModel:
    classes_ = [0, 1]

    def predict_proba(self, X):
        return [[.55, .45] for _ in X]


class Phish360Tests(unittest.TestCase):
    def test_deterministic_balanced_group_selection(self):
        a, audit = select_cases(fixture(), set(), cap=5, minimum=2)
        b, _ = select_cases(fixture(), set(), cap=5, minimum=2)
        self.assertEqual(a, b)
        self.assertEqual(Counter(r[1] for r in a), {0: 5, 1: 5})
        self.assertEqual(audit["unique_groups"], 10)

    def test_excludes_known_duplicate_conflicting_and_invalid(self):
        rows = fixture()
        known = group_key(rows[0][0])
        conflict = group_key(rows[1][0])
        rows.extend([rows[2], (rows[1][0], 1), ("invalid", 0)])
        cases, audit = select_cases(rows, {known}, cap=20, minimum=2)
        self.assertFalse({known, conflict} & {r[2] for r in cases})
        self.assertEqual(audit["counts"]["conflicting_groups"], 1)
        self.assertEqual(audit["counts"]["duplicate"], 1)
        self.assertEqual(audit["counts"]["invalid"], 1)

    def test_insufficient_groups_rejected(self):
        with self.assertRaises(ValueError):
            select_cases(fixture(), set(), minimum=25)

    def test_same_cases_and_frozen_thresholds(self):
        cases, _ = select_cases(fixture(), set(), cap=5, minimum=2)
        base = {"schema": FEATURE_SCHEMA, "feature_names": FEATURE_NAMES,
                "model": MockModel(), "model_name": "mock"}
        results = compare(cases, {"A_original": base, "C_hybrid": {**base, "decision_threshold": .4}})
        self.assertEqual(results["A_original"]["metrics"]["support"]["predicted_phishing"], 0)
        self.assertEqual(results["C_hybrid"]["metrics"]["support"]["predicted_phishing"], 10)
        self.assertEqual(results["consensus_v1"]["metrics"]["total"], 10)
        self.assertEqual(results["C_hybrid"]["by_subset"]["https"]["support"]["total"], 10)

    def test_parquet_only_url_and_class_and_label_check(self):
        try:
            import pyarrow as pa
            import pyarrow.parquet as pq
        except ImportError:
            self.skipTest("PyArrow opcional para evaluación externa")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "fixture.parquet"
            pq.write_table(pa.table({"URL": ["https://demo.test/"],
                                     "class": ["legit"], "full_html": ["ignored"]}), path)
            self.assertEqual(list(read_parquet_rows(path, 0)), [("https://demo.test/", 0)])
            with self.assertRaisesRegex(ValueError, "etiqueta"):
                list(read_parquet_rows(path, 1))


if __name__ == "__main__":
    unittest.main()
