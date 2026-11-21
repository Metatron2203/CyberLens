"""Pruebas del detector de redirecciones (solo URLs ficticias)."""

import unittest

from app.analyzer.redirect_analysis import inspect_redirect_parameters
from app.analyzer.url_analyzer import analyze_url


class RedirectAnalysisTests(unittest.TestCase):
    def test_encoded_external_destination_is_visible_as_indicators(self):
        url = (
            "https://redirector.example.org/r?"
            "next=https%3A%2F%2Fotro.example.net%2Flogin"
        )
        signals = inspect_redirect_parameters(url)
        self.assertTrue(signals.named_parameter)
        self.assertTrue(signals.embedded_url)
        self.assertTrue(signals.external_host)

        result = analyze_url(url)
        names = {i["name"] for i in result["indicators"]}
        self.assertIn("URL anidada en parámetro", names)
        self.assertIn("Destino en otro host", names)
        self.assertIn("redirección", result["message"].lower())
        # Sin métricas reales todavía no se cambia el puntaje heurístico.
        self.assertEqual(result["risk_score"], 7)

    def test_double_encoded_destination(self):
        url = (
            "https://redirector.example.org/?"
            "next=https%253A%252F%252Fexterno.example.net%252Flogin"
        )
        self.assertTrue(inspect_redirect_parameters(url).external_host)

    def test_relative_destination_is_not_embedded_url(self):
        signals = inspect_redirect_parameters("https://example.org/?next=/dashboard")
        self.assertTrue(signals.named_parameter)
        self.assertFalse(signals.embedded_url)
        self.assertFalse(signals.external_host)

    def test_same_host_is_not_external(self):
        signals = inspect_redirect_parameters(
            "https://example.org/?next=https%3A%2F%2Fexample.org%2Fhome"
        )
        self.assertTrue(signals.embedded_url)
        self.assertFalse(signals.external_host)

    def test_subdomain_destination_is_not_external(self):
        signals = inspect_redirect_parameters(
            "https://example.org/?next=https%3A%2F%2Faccounts.example.org%2Fhome"
        )
        self.assertTrue(signals.embedded_url)
        self.assertFalse(signals.external_host)

    def test_unrelated_query_parameter_is_not_redirect(self):
        signals = inspect_redirect_parameters(
            "https://example.org/?q=https%3A%2F%2Fother.example.net"
        )
        self.assertFalse(signals.named_parameter)
        self.assertFalse(signals.embedded_url)

    def test_non_http_target_is_not_redirect_candidate(self):
        signals = inspect_redirect_parameters(
            "https://example.org/?next=javascript%3Aalert%281%29"
        )
        self.assertFalse(signals.embedded_url)

    def test_malformed_nested_url_is_ignored_safely(self):
        signals = inspect_redirect_parameters(
            "https://example.org/?next=http%3A%2F%2F%5Bbad"
        )
        self.assertFalse(signals.embedded_url)

    def test_sensitive_nested_values_are_not_returned(self):
        url = (
            "https://redirector.example.org/?"
            "next=https%3A%2F%2Fusuario%3Aclave%40otro.example.net%2Fprivate"
            "%3Ftoken%3DSUPERSECRETO&state=SUPERSECRETO"
        )
        result = analyze_url(url)
        dumped = str(result)
        for secret in ("SUPERSECRETO", "usuario", "clave", "private", "otro.example.net"):
            self.assertNotIn(secret, dumped)
        self.assertEqual(result["url"], "https://redirector.example.org/[contenido omitido]")


if __name__ == "__main__":
    unittest.main()
