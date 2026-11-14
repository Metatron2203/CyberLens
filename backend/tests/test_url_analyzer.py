import unittest

from app.analyzer.url_analyzer import analyze_url, safe_url_for_storage


class UrlAnalyzerTests(unittest.TestCase):
    def test_simple_https_url_is_low_risk(self):
        result = analyze_url("https://example.com/")
        self.assertEqual(result["risk_level"], "low")
        self.assertEqual(result["risk_score"], 0)

    def test_ip_http_url_accumulates_risk_without_subdomain_false_positive(self):
        result = analyze_url("http://192.0.2.10/login/verify")
        self.assertGreaterEqual(result["risk_score"], 40)
        names = {indicator["name"] for indicator in result["indicators"]}
        self.assertIn("Uso de dirección IP", names)
        self.assertIn("Conexión HTTP", names)
        self.assertNotIn("Múltiples subdominios", names)

    def test_punycode_is_detected(self):
        result = analyze_url("https://xn--example-9za.com/login")
        names = {indicator["name"] for indicator in result["indicators"]}
        self.assertIn("Dominio internacionalizado (Punycode)", names)

    def test_credentials_before_at_are_detected_and_not_returned(self):
        result = analyze_url("https://usuario:clave@example.com/reset/abc?token=secret")
        names = {indicator["name"] for indicator in result["indicators"]}
        self.assertIn("Credenciales en la URL", names)
        self.assertEqual(result["risk_level"], "medium")
        for sensitive in ("usuario", "clave", "abc", "secret", "token"):
            self.assertNotIn(sensitive, result["url"])

    def test_invalid_scheme_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_url("ftp://example.com/file")

    def test_ipv6_not_subdomains(self):
        result = analyze_url("http://[2001:db8::1]/login")
        names = {indicator["name"] for indicator in result["indicators"]}
        self.assertIn("Uso de dirección IP", names)
        self.assertNotIn("Múltiples subdominios", names)

    def test_nonstandard_port(self):
        result = analyze_url("https://example.com:8443/")
        self.assertIn("Puerto no estándar", {i["name"] for i in result["indicators"]})

    def test_bad_port_raises_error(self):
        with self.assertRaises(ValueError):
            analyze_url("https://example.com:99999/")

    def test_typo_brand(self):
        result = analyze_url("https://g00gle.com/")
        self.assertEqual(result["risk_level"], "medium")
        self.assertIn("Posible imitación visual de marca", {i["name"] for i in result["indicators"]})

    def test_lookalike_brand_outside_official_domain(self):
        result = analyze_url("https://login-paypal-account-verify.example.net/")
        self.assertGreaterEqual(result["risk_score"], 25)
        self.assertNotEqual(result["risk_level"], "low")

    def test_official_brand_domain_not_brand_flagged(self):
        result = analyze_url("https://accounts.google.com/login")
        self.assertNotIn("Marca conocida fuera de sus dominios habituales", {i["name"] for i in result["indicators"]})

    def test_long_url_score_capped(self):
        url = "http://login-paypal-account-verify.example.net:8080/" + ("login/" * 35) + "?token=" + "%41" * 20
        result = analyze_url(url)
        self.assertLessEqual(result["risk_score"], 100)

    def test_safe_url_hides_all_paths_queries_and_fragments(self):
        redacted = safe_url_for_storage("https://a:b@example.net/private/otp-123?q=secret&password=123#x")
        self.assertEqual(redacted, "https://example.net/[contenido omitido]")
        self.assertNotIn("password", redacted)

    def test_safe_url_is_stable_when_already_redacted(self):
        original = "https://example.net/[contenido omitido]"
        self.assertEqual(safe_url_for_storage(original), original)

    def test_query_detection_still_works_despite_redaction(self):
        result = analyze_url("https://example.org/?password=hello")
        self.assertIn("Términos sensibles en la URL", {i["name"] for i in result["indicators"]})
        self.assertEqual(result["url"], "https://example.org/[contenido omitido]")


if __name__ == "__main__":
    unittest.main()
