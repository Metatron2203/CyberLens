"""API REST de CyberLens: historial aislado por cookie de sesión del navegador."""

import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.analyzer.url_analyzer import analyze_url
from app.database import get_db
from app.ml.model import predict, status
from app.models.analysis import AnalysisRecord
from app.schemas.analysis import AnalyzeRequest, AnalyzeResponse, AnalysisHistoryItem

router = APIRouter()
SESSION_COOKIE = "cyberlens_session"
SESSION_MAX_AGE = 30 * 24 * 60 * 60
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
HISTORY_RETENTION_DAYS = max(1, int(os.getenv("HISTORY_RETENTION_DAYS", "30")))


def _hash_token(token: str | None) -> str | None:
    if not token or not 40 <= len(token) <= 128:
        return None
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest, response: Response, http_request: Request, db: Session = Depends(get_db)):
    try:
        result = analyze_url(str(request.url))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Inferencia opcional: no altera la puntuación heurística de V0.2.1.
    # La URL sin redactar solo existe durante esta petición.
    result["ml"] = predict(str(request.url))

    token = http_request.cookies.get(SESSION_COOKIE)
    token_hash = _hash_token(token)
    if token_hash is None:
        token = secrets.token_urlsafe(32)
        token_hash = _hash_token(token)
        assert token_hash is not None

    cutoff = datetime.now(timezone.utc) - timedelta(days=HISTORY_RETENTION_DAYS)
    db.execute(delete(AnalysisRecord).where(AnalysisRecord.created_at < cutoff))
    db.add(AnalysisRecord(
        url=result["url"],
        session_hash=token_hash,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        indicators_json=json.dumps(result["indicators"], ensure_ascii=False),
        message=result["message"],
        ml_result_json=json.dumps(result["ml"], ensure_ascii=False),
    ))
    db.commit()
    response.set_cookie(
        key=SESSION_COOKIE, value=token, max_age=SESSION_MAX_AGE,
        httponly=True, secure=COOKIE_SECURE, samesite="lax", path="/",
    )
    return result


@router.get("/history", response_model=list[AnalysisHistoryItem])
def history(http_request: Request, limit: int = Query(default=10, ge=1, le=50), db: Session = Depends(get_db)):
    session_hash = _hash_token(http_request.cookies.get(SESSION_COOKIE))
    if session_hash is None:
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(days=HISTORY_RETENTION_DAYS)
    db.execute(delete(AnalysisRecord).where(AnalysisRecord.created_at < cutoff))
    db.commit()
    records = db.scalars(
        select(AnalysisRecord)
        .where(AnalysisRecord.session_hash == session_hash)
        .order_by(AnalysisRecord.created_at.desc(), AnalysisRecord.id.desc())
        .limit(limit)
    ).all()
    return [
        AnalysisHistoryItem(
            id=record.id,
            url=record.url,
            risk_score=record.risk_score,
            risk_level=record.risk_level,
            indicators=json.loads(record.indicators_json),
            message=record.message,
            ml=json.loads(record.ml_result_json) if record.ml_result_json else None,
            created_at=record.created_at,
        )
        for record in records
    ]


@router.delete("/history")
def clear_history(http_request: Request, db: Session = Depends(get_db)):
    session_hash = _hash_token(http_request.cookies.get(SESSION_COOKIE))
    if session_hash is None:
        return {"deleted": 0}
    deleted = db.execute(
        delete(AnalysisRecord).where(AnalysisRecord.session_hash == session_hash)
    ).rowcount
    db.commit()
    return {"deleted": deleted or 0}


@router.get("/ml/status")
def ml_status():
    """Estado y métricas agregadas; no expone muestras de entrenamiento."""
    return status()
