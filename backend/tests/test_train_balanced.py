"""Pruebas offline del muestreo equilibrado. No se visitan URLs."""
import csv
import tempfile
import unittest
from pathlib import Path

from app.ml.features import group_key
from ml_scripts.train_balanced import collect


class BalancedSamplingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "source.csv"

    def write(self, rows):
        with self.path.open("w", encoding="utf-8", newline="") as fp:
            writer = csv.writer(fp)
            writer.writerow(["URL", "label"])
            writer.writerows(rows)

    def rows(self):
        result = []
        for i in range(40):
            for label, prefix in (("1", "benign"), ("0", "phish")):
                result.append((f"https://{prefix}-simple-{i}.example/", label))
                result.append((f"https://{prefix}-complex-{i}.example/account?id=1", label))
        return result

    def test_balance_in_each_stratum_and_unique_groups(self):
        self.write(self.rows())
        items, report = collect([("Test", self.path, "label")], set(), per_stratum=25)
        self.assertEqual(len(items), 100)
        self.assertEqual(len({r[2] for r in items}), 100)
        self.assertEqual(sum(r[1] for r in items), 50)
        self.assertEqual(report["complex_per_class"], 25)
        self.assertEqual(report["matched_strata"]["Test_simple"]["selected_per_class"], 25)

    def test_excludes_historical_groups_and_conflicting_labels(self):
        rows = self.rows()
        historical = group_key(rows[0][0])
        conflict = group_key(rows[1][0])
        rows.append((rows[1][0], "0"))
        rows.append(("http://insecure.example/", "0"))
        self.write(rows)
        items, report = collect([("Test", self.path, "label")], {historical}, per_stratum=25)
        self.assertNotIn(historical, {r[2] for r in items})
        self.assertNotIn(conflict, {r[2] for r in items})
        self.assertEqual(report["counts"]["conflicting_groups"], 1)
        self.assertEqual(report["counts"]["excluded_non_https"], 1)
        self.assertTrue(all(r[3].startswith("https://") for r in items))

    def test_deterministic_selection(self):
        self.write(self.rows())
        first, _ = collect([("Test", self.path, "label")], set(), per_stratum=25)
        second, _ = collect([("Test", self.path, "label")], set(), per_stratum=25)
        self.assertEqual(first, second)

    def test_aborts_when_complex_cases_missing(self):
        self.write([(url, label) for url, label in self.rows() if "simple" in url])
        with self.assertRaises(ValueError):
            collect([("Test", self.path, "label")], set(), per_stratum=25)


if __name__ == "__main__":
    unittest.main()
