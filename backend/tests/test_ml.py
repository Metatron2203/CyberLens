"""Pruebas de infraestructura ML con ejemplos FICTICIOS, no métricas del mundo real."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.ml import model as serving
from app.ml.features import FEATURE_NAMES, extract_features, feature_vector, group_key
from ml_scripts.train import grouped_split, prepare, train_models


class MLFeatureTests(unittest.TestCase):
    def test_vector_is_fixed_numeric_schema(self):
        url = "https://good.example.org/login"
        vector = feature_vector(url)
        self.assertEqual(len(vector), len(FEATURE_NAMES))
        self.assertTrue(all(isinstance(x, float) for x in vector))

    def test_detect_embedded_external_url_without_fetching(self):
        feat = extract_features("https://redirector.example.org/r?next=https%3A%2F%2Ffake.example.net%2Flogin")
        self.assertEqual(feat["redirect_named_parameter"], 1)
        self.assertEqual(feat["embedded_url_candidate"], 1)
        self.assertEqual(feat["external_embedded_host"], 1)

    def test_no_embedded_url_not_flagged(self):
        feat = extract_features("https://example.com/?next=/internal")
        self.assertEqual(feat["external_embedded_host"], 0)

    def test_group_key_uses_parent_domain(self):
        self.assertEqual(group_key("https://a.b.example.co.uk/a"), group_key("https://example.co.uk/b"))
        self.assertNotEqual(group_key("https://example.co.uk"), group_key("https://example.com"))

    def test_reject_invalid_url(self):
        with self.assertRaises(ValueError):
            feature_vector("file:///tmp/private.txt")


class MLTrainingTests(unittest.TestCase):
    def fake_items(self):
        legit = [f"https://www.sitiovalido{i}.test/" for i in range(60)]
        phishing = [f"http://cuenta-verificar{i}.example/login/password?verify=true" for i in range(60)]
        prepared, _ = prepare(phishing, legit)
        return prepared

    def test_dataset_grouped_split_has_no_overlap(self):
        items = self.fake_items()
        train, valid, test = grouped_split([i[0] for i in items], [i[1] for i in items], [i[2] for i in items], 42)
        self.assertFalse({items[k][2] for k in train} & {items[k][2] for k in valid})
        self.assertFalse({items[k][2] for k in train} & {items[k][2] for k in test})
        self.assertFalse({items[k][2] for k in valid} & {items[k][2] for k in test})

    def test_train_compare_save_and_infer_without_leaking_url(self):
        items = self.fake_items()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "model.joblib"
            report, saved = train_models(items, source="dataset artificial de prueba", model_path=path)
            self.assertTrue(saved.is_file())
            self.assertTrue(path.with_suffix(".metrics.json").is_file())
            self.assertEqual(set(report["validation_metrics"]), {"Regresión logística", "Random Forest"})
            self.assertIn("confusion_matrix", report["test_metrics"])
            self.assertEqual(report["samples"]["total"], len(items))
            with patch.object(serving, "MODEL_PATH", path):
                loaded = serving.status()
                self.assertTrue(loaded["trained"])
                prediction = serving.predict("https://safe.example.org/?secret=top-secret-value")
                self.assertTrue(prediction["available"])
                self.assertNotIn("top-secret-value", str(prediction))
                self.assertGreaterEqual(prediction["phishing_probability"], 0)
                self.assertLessEqual(prediction["phishing_probability"], 1)
        # Cache no debe filtrarse a pruebas posteriores.
        serving._cache_stamp = None
        serving._cache_bundle = None
        serving._cache_path = None

    def test_untrained_path_has_safe_fallback(self):
        with patch.object(serving, "MODEL_PATH", Path("/no/existing/model.joblib")):
            self.assertFalse(serving.status()["trained"])
            self.assertFalse(serving.predict("https://example.org/")["available"])


if __name__ == "__main__":
    unittest.main()
