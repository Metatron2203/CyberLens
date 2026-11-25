"""Fase 3: pruebas de evaluación externa y challenge ficticio sin red."""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from app.ml.features import FEATURE_NAMES, FEATURE_SCHEMA, group_key
from ml_scripts.external_eval import (
    evaluate_cases, load_cases, synthetic_challenge,
)


class MockEstimator:
    """Simula una predicción basada en HTTP, solo para pruebas de infraestructura."""

    def predict_proba(self, rows):
        pos = FEATURE_NAMES.index("uses_http")
        return [[0.1, 0.9] if row[pos] else [0.9, 0.1] for row in rows]


def bundle(*, groups=None):
    result = {
        "schema": FEATURE_SCHEMA,
        "feature_names": FEATURE_NAMES,
        "model": MockEstimator(),
        "model_name": "simulado de prueba",
    }
    if groups is not None:
        result["dataset_group_fingerprints"] = groups
    return result


class ExternalEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.cases = [
            ("https://comercio-uno.example/login?token=SECRETO_XYZ", 0, "login"),
            ("http://cuenta-dos.example/login?token=SECRETO_ABC", 1, "login"),
            ("https://servicio-tres.example/?q=normal&lang=es", 0, "query"),
            ("http://alerta-cuatro.example/?verify=1", 1, "query"),
        ]

    def test_external_report_has_only_aggregated_metrics(self):
        report = evaluate_cases(
            self.cases, bundle(groups=["otro-grupo-que-no-existe"]),
            source="Corpus local etiquetado", strict=True,
        )
        self.assertEqual(report["evaluation_kind"], "external")
        self.assertEqual(report["sample_count"], 4)
        self.assertEqual(report["group_overlap_check"], "passed")
        self.assertEqual(report["model_metrics"]["confusion_matrix"],
                         {"tn": 2, "fp": 0, "fn": 0, "tp": 2})
        self.assertEqual(set(report["by_category"]), {"login", "query"})
        dumped = json.dumps(report, ensure_ascii=False)
        for secret in ("SECRETO_XYZ", "SECRETO_ABC", "cuenta-dos", "comercio-uno"):
            self.assertNotIn(secret, dumped)

    def test_rejects_old_model_without_corpus_manifest(self):
        with self.assertRaisesRegex(ValueError, "no registra grupos"):
            evaluate_cases(self.cases, bundle(),
                           source="Corpus local etiquetado", strict=True)

    def test_rejects_overlap_with_previous_train_or_test_group(self):
        reused = group_key(self.cases[1][0])
        with self.assertRaisesRegex(ValueError, "comparte 1 grupo"):
            evaluate_cases(
                self.cases, bundle(groups=[reused]),
                source="Corpus local etiquetado", strict=True,
            )

    def test_demo_is_explicitly_not_external(self):
        report = evaluate_cases(
            synthetic_challenge(), bundle(),
            source="Demo ficticia", strict=False,
        )
        self.assertEqual(report["evaluation_kind"], "synthetic_diagnostic_only")
        self.assertEqual(report["sample_count"], 18)
        self.assertIn("ficticias", " ".join(report["limitations"]))
        self.assertNotIn("dataset_group_fingerprints", report)

    def test_frozen_threshold_is_used_and_invalid_value_rejected(self):
        candidate = bundle()
        candidate["decision_threshold"] = 0.95
        report = evaluate_cases(self.cases, candidate, source="Demo ficticia", strict=False)
        self.assertEqual(report["decision_threshold"], 0.95)
        self.assertEqual(report["model_metrics"]["support"]["predicted_phishing"], 0)
        candidate["decision_threshold"] = float("nan")
        with self.assertRaisesRegex(ValueError, "Umbral"):
            evaluate_cases(self.cases, candidate, source="Demo ficticia", strict=False)

    def test_source_description_cannot_contain_secret_url(self):
        with self.assertRaises(ValueError):
            evaluate_cases(self.cases, bundle(),
                           source="https://example.org/?token=SECRETO", strict=False)

    def test_csv_reader_accepts_known_labels_and_categories(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "external.csv"
            with file.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["url", "label", "category"])
                writer.writeheader()
                writer.writerow({"url": self.cases[0][0], "label": "legitimate", "category": "login"})
                writer.writerow({"url": self.cases[1][0], "label": "1", "category": "query"})
            samples = load_cases(file)
            self.assertEqual([s[1] for s in samples], [0, 1])
            self.assertEqual([s[2] for s in samples], ["login", "query"])

    def test_csv_reader_rejects_duplicates_without_echoing_urls(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "external.csv"
            with file.open("w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["url", "label"])
                writer.writerow([self.cases[0][0], 0])
                writer.writerow([self.cases[0][0], 0])
            with self.assertRaises(ValueError) as context:
                load_cases(file)
            self.assertNotIn("SECRETO_XYZ", str(context.exception))


if __name__ == "__main__":
    unittest.main()
