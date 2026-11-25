"""La auditoría ML registra cifras agregadas, no URLs sensibles."""

import json
import unittest

from ml_scripts.audit import dataset_audit


class DatasetAuditTests(unittest.TestCase):
    def setUp(self):
        self.items = [
            ([1.0], 1, "grupo-a", "http://usuario:clave@phishing.example/?token=PRIVADO"),
            ([2.0], 1, "grupo-b", "http://phishing2.example/"),
            ([3.0], 0, "grupo-c", "https://bueno.example/?q=PRIVADO"),
        ]

    def test_counts_and_exclusions(self):
        result = dataset_audit(
            self.items, phishing_input_count=3, legitimate_input_count=2,
            conflicting_domain_groups=1, source="Muestras locales",
        )
        self.assertEqual(result["input_counts"]["phishing"], 3)
        self.assertEqual(result["accepted_counts"]["phishing"], 2)
        self.assertEqual(result["accepted_counts"]["candidate_legitimate"], 1)
        self.assertEqual(result["excluded_counts"]["phishing"], 1)
        self.assertEqual(result["unique_domain_groups"]["phishing"], 2)
        self.assertEqual(result["conflicting_domain_groups"], 1)

    def test_never_exposes_urls_or_secrets(self):
        result = dataset_audit(
            self.items, phishing_input_count=2, legitimate_input_count=1,
            conflicting_domain_groups=0, source="Datos locales",
        )
        dumped = json.dumps(result)
        for secret in ("PRIVADO", "usuario", "clave", "phishing.example", "bueno.example"):
            self.assertNotIn(secret, dumped)

    def test_warns_on_tranco_label_bias(self):
        result = dataset_audit(
            self.items, phishing_input_count=2, legitimate_input_count=1,
            conflicting_domain_groups=0, source="OpenPhish Community y Tranco",
        )
        self.assertTrue(any("NO etiquetas verificadas" in warning for warning in result["warnings"]))

    def test_rejects_cross_class_group_leakage(self):
        items = self.items + [([4.0], 0, "grupo-a", "https://otra.example/")]
        with self.assertRaises(ValueError):
            dataset_audit(
                items, phishing_input_count=2, legitimate_input_count=2,
                conflicting_domain_groups=0, source="Datos locales",
            )

    def test_rejects_invalid_counts_and_labels(self):
        with self.assertRaises(ValueError):
            dataset_audit(
                self.items, phishing_input_count=1, legitimate_input_count=1,
                conflicting_domain_groups=0, source="Datos locales",
            )
        with self.assertRaises(ValueError):
            dataset_audit(
                [([1.0], 3, "x", "https://example.org/")],
                phishing_input_count=1, legitimate_input_count=0,
                conflicting_domain_groups=0, source="Datos locales",
            )


if __name__ == "__main__":
    unittest.main()
