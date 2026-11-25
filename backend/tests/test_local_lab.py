"""Pruebas del laboratorio educativo: URLs reservadas y ausencia de envío."""
import unittest
from collections import Counter
from urllib.parse import urlsplit

from ml_scripts.local_lab import CASES, render_lab, validate_cases


class LocalLabTests(unittest.TestCase):
    def test_catalog_is_balanced_and_reserved(self):
        validate_cases()
        self.assertEqual(Counter(c[2] for c in CASES), {0: 6, 1: 6})
        self.assertEqual(len({c[1] for c in CASES}), len(CASES))
        for _, url, _, _ in CASES:
            self.assertEqual(urlsplit(url).scheme, "https")
            self.assertTrue(urlsplit(url).hostname.endswith(".example"))

    def test_context_pairs_have_both_labels(self):
        for context in {c[0] for c in CASES}:
            self.assertEqual({c[2] for c in CASES if c[0] == context}, {0, 1})

    def test_page_has_explicit_demo_notice_and_csp(self):
        page = render_lab()
        self.assertIn("SIMULACION EDUCATIVA", page)
        self.assertIn("connect-src 'none'", page)
        self.assertIn("form-action 'none'", page)

    def test_page_has_no_submission_or_network_code(self):
        page = render_lab().lower()
        for fragment in ("<form", "fetch(", "xmlhttprequest", "sendbeacon",
                         "localstorage", "sessionstorage", "document.cookie",
                         "<iframe", "<script src=", "window.location"):
            self.assertNotIn(fragment, page)

    def test_practice_fields_are_cleared(self):
        page = render_lab()
        self.assertIn('userField.value = "";', page)
        self.assertIn('codeField.value = "";', page)
        self.assertIn("Juanito_777", page)
        self.assertIn("DEMO_123", page)


if __name__ == "__main__":
    unittest.main()
