from datetime import datetime

from pydantic import BaseModel, Field, HttpUrl


class Indicator(BaseModel):
    name: str
    description: str
    points: int
    severity: str


class AnalyzeRequest(BaseModel):
    url: HttpUrl = Field(max_length=2048)


class MLResult(BaseModel):
    available: bool
    message: str
    model: str | None = None
    model_version: str | None = None
    phishing_probability: float | None = Field(default=None, ge=0, le=1)
    prediction: str | None = None


class AnalyzeResponse(BaseModel):
    url: str
    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    indicators: list[Indicator]
    message: str
    ml: MLResult | None = None


class AnalysisHistoryItem(AnalyzeResponse):
    id: int
    created_at: datetime
