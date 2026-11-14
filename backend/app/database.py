"""Persistencia local y migración mínima desde el esquema CyberLens V0.2."""

import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

BASE_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BASE_DIR / ".env")
DATABASE_URL = os.getenv("DATABASE_URL") or f"sqlite:///{BASE_DIR / 'cyberlens.db'}"
if not DATABASE_URL.startswith("sqlite:"):
    raise RuntimeError("CyberLens V0.3 solo admite SQLite. PostgreSQL es una fase posterior.")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def prepare_database(db_engine=None) -> None:
    """Crea las tablas y migra registros antiguos SIN exponer datos privados.

    Los registros de V0.2 quedan marcados como heredados, no visibles en ninguna
    sesión. Sus URLs se anonimizan inmediatamente; conserva métricas y fecha.
    """
    from app.analyzer.url_analyzer import safe_url_for_storage
    from app.models.analysis import AnalysisRecord  # noqa: F401: registra modelo

    target = db_engine or engine
    Base.metadata.create_all(bind=target)
    if "analysis_records" not in inspect(target).get_table_names():
        return

    with target.begin() as connection:
        columns = {col["name"] for col in inspect(connection).get_columns("analysis_records")}
        if "session_hash" not in columns:
            connection.execute(text("ALTER TABLE analysis_records ADD COLUMN session_hash VARCHAR(64)"))
        if "ml_result_json" not in columns:
            connection.execute(text("ALTER TABLE analysis_records ADD COLUMN ml_result_json TEXT"))
        # Protege datos que pudieron quedar guardados por una versión anterior.
        rows = connection.execute(text("SELECT id, url FROM analysis_records")).fetchall()
        for row in rows:
            safe = safe_url_for_storage(row.url)
            if safe != row.url:
                connection.execute(
                    text("UPDATE analysis_records SET url=:url WHERE id=:id"),
                    {"url": safe, "id": row.id},
                )
        connection.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_analysis_records_session_created "
            "ON analysis_records (session_hash, created_at, id)"
        ))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
