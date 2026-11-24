import json
import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db, prepare_database
from app.main import app
from app.models.analysis import AnalysisRecord


class APIIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
        )
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(self.engine)

        def override_db():
            with self.Session() as db:
                yield db

        app.dependency_overrides[get_db] = override_db
        self.client = TestClient(app)
        self.other_client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()
        self.client.close()
        self.other_client.close()
        self.engine.dispose()

    def test_health_returns_current_version(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["version"], "0.4.0")

    def test_ml_status_endpoint_does_not_break_if_untrained(self):
        response = self.client.get("/api/ml/status")
        self.assertEqual(response.status_code, 200)
        self.assertIn("trained", response.json())

    def test_ml_data_in_response_does_not_echo_secret(self):
        response = self.client.post("/api/analyze", json={"url": "https://example.org/private?secret=valorultrasecreto"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("ml", response.json())
        self.assertNotIn("valorultrasecreto", response.text)
        history = self.client.get("/api/history")
        self.assertIn("ml", history.json()[0])
        self.assertNotIn("valorultrasecreto", history.text)

    def test_empty_history_for_other_browser(self):
        url = "https://example.net/private?token=extremadamente-secreto"
        response = self.client.post("/api/analyze", json={"url": url})
        self.assertEqual(response.status_code, 200)
        self.assertIn("cyberlens_session", self.client.cookies)
        self.assertNotIn("token=", response.text)
        self.assertEqual(self.other_client.get("/api/history").json(), [])
        history = self.client.get("/api/history")
        self.assertEqual(history.status_code, 200)
        self.assertEqual(len(history.json()), 1)
        self.assertNotIn("extremadamente-secreto", history.text)
        self.assertNotIn("private", history.text)

    def test_only_session_hash_is_saved(self):
        self.client.post("/api/analyze", json={"url": "https://user:password@example.net/x/secret?token=abcdef"})
        with self.Session() as session:
            record = session.query(AnalysisRecord).one()
            self.assertEqual(record.url, "https://example.net/[contenido omitido]")
            self.assertEqual(len(record.session_hash), 64)
            self.assertNotIn(self.client.cookies["cyberlens_session"], record.session_hash)
            self.assertNotIn("password", str(record.__dict__))

    def test_invalid_request_does_not_echo_secret(self):
        response = self.client.post("/api/analyze", json={"url": "ftp://usuario:ultrasecreto@example.com/"})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("ultrasecreto", response.text)
        self.assertNotIn("ftp://", response.text)

    def test_cannot_read_without_valid_cookie(self):
        self.client.post("/api/analyze", json={"url": "https://example.com/"})
        self.other_client.cookies.set("cyberlens_session", "invalid")
        self.assertEqual(self.other_client.get("/api/history").json(), [])

    def test_delete_only_own_history(self):
        self.client.post("/api/analyze", json={"url": "https://example.com/a"})
        self.other_client.post("/api/analyze", json={"url": "https://example.com/b"})
        deleted = self.client.delete("/api/history")
        self.assertEqual(deleted.json(), {"deleted": 1})
        self.assertEqual(self.client.get("/api/history").json(), [])
        self.assertEqual(len(self.other_client.get("/api/history").json()), 1)

    def test_limit_validation_is_safe(self):
        self.assertEqual(self.client.get("/api/history?limit=999").status_code, 422)
        self.assertEqual(self.client.get("/api/history?limit=10").status_code, 200)

    def test_api_responses_not_cached(self):
        response = self.client.post("/api/analyze", json={"url": "https://example.com/"})
        self.assertEqual(response.headers.get("cache-control"), "no-store")
        self.assertEqual(response.headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(self.client.get("/api/history").headers.get("cache-control"), "no-store")

    def test_cors_not_wildcard(self):
        good = self.client.options("/api/analyze", headers={
            "origin": "http://localhost:3000", "access-control-request-method": "POST"
        })
        self.assertEqual(good.headers.get("access-control-allow-origin"), "http://localhost:3000")
        bad = self.client.options("/api/analyze", headers={
            "origin": "https://malicious.example", "access-control-request-method": "POST"
        })
        self.assertNotIn("access-control-allow-origin", bad.headers)


class LegacyMigrationTests(unittest.TestCase):
    def test_migrate_legacy_history_anonymizes_data_and_does_not_assign_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.db"
            eng = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
            with eng.begin() as conn:
                conn.execute(text("""
                CREATE TABLE analysis_records (
                    id INTEGER PRIMARY KEY, url TEXT NOT NULL, risk_score INTEGER NOT NULL,
                    risk_level VARCHAR(16) NOT NULL, indicators_json TEXT NOT NULL,
                    message TEXT NOT NULL, created_at DATETIME NOT NULL
                )
                """))
                conn.execute(text("""
                INSERT INTO analysis_records (url, risk_score, risk_level, indicators_json, message, created_at)
                VALUES ('https://user:secret@example.com/private?q=token', 20, 'low', '[]', 'ok', CURRENT_TIMESTAMP)
                """))
            prepare_database(eng)
            with eng.begin() as conn:
                result = conn.execute(text("SELECT url, session_hash FROM analysis_records")).one()
                self.assertEqual(result.url, "https://example.com/[contenido omitido]")
                self.assertIsNone(result.session_hash)
            eng.dispose()


if __name__ == "__main__":
    unittest.main()
