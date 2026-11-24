"""Aplicación API y configuración de seguridad para la demo local."""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import router
from app.database import prepare_database


@asynccontextmanager
async def lifespan(_: FastAPI):
    prepare_database()
    yield


app = FastAPI(
    title="CyberLens API",
    version="0.4.0",
    description="Análisis heurístico y ML experimental (sin visitar las URLs).",
    lifespan=lifespan,
)

origins = [
    item.strip() for item in os.getenv(
        "ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"
    ).split(",") if item.strip()
]
if "*" in origins:
    raise RuntimeError("ALLOWED_ORIGINS debe enumerar orígenes concretos; '*' no está permitido.")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type"],
)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_, __):
    # FastAPI/Pydantic incluyen 'input' en su error por defecto, lo que puede
    # devolver credenciales o tokens que llegaron dentro de una URL mal formada.
    return JSONResponse(
        status_code=422,
        content={"detail": "Entrada inválida. Introduce una URL HTTP/HTTPS bien formada (máximo 2048 caracteres)."},
    )


@app.middleware("http")
async def response_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
    return response


app.include_router(router, prefix="/api")


@app.get("/health")
def health():
    return {"status": "ok", "service": "cyberlens-api", "version": "0.4.0"}
