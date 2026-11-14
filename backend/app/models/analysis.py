from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class AnalysisRecord(Base):
    __tablename__ = "analysis_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)  # URL redactada, nunca URL completa
    session_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)
    indicators_json: Mapped[str] = mapped_column(Text, nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    ml_result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
