"""Inferencia local opcional; no realiza solicitudes de red.

Nunca cargues un fichero joblib desconocido: deserializarlo ejecuta código.
Solo se permite el modelo generado localmente por ml_scripts.train.
"""

import os
from datetime import datetime
from pathlib import Path
from threading import RLock

from app.ml.features import FEATURE_NAMES, FEATURE_SCHEMA, feature_vector

MODEL_PATH = Path(os.environ.get("CYBERLENS_ML_MODEL") or Path(__file__).resolve().parents[2] / "models" / "cyberlens_ml.joblib")
_cache_lock = RLock()
_cache_path = None
_cache_stamp = None
_cache_bundle = None


def _load():
    global _cache_path, _cache_stamp, _cache_bundle
    with _cache_lock:
        try:
            stamp = MODEL_PATH.stat().st_mtime_ns
        except OSError:
            return None
        if _cache_stamp == stamp and _cache_path == str(MODEL_PATH):
            return _cache_bundle
        try:
            # Paquete ML opcional: si no está instalado, funciona el heurístico.
            import joblib
            obj = joblib.load(MODEL_PATH)
            if not isinstance(obj, dict) or obj.get("schema") != FEATURE_SCHEMA or tuple(obj.get("feature_names", [])) != FEATURE_NAMES:
                return None
            # Candidatos de desarrollo no se exponen en la API antes de la revisión.
            if obj.get("experimental_only", False):
                return None
            if not hasattr(obj.get("model"), "predict_proba"):
                return None
        except (ImportError, ValueError, TypeError, KeyError, OSError, AttributeError):
            return None
        _cache_bundle, _cache_stamp, _cache_path = obj, stamp, str(MODEL_PATH)
        return obj


def status() -> dict:
    bundle = _load()
    if bundle is None:
        return {
            "trained": False,
            "message": "Aún no hay un modelo local entrenado. El analizador heurístico sigue funcionando.",
            "feature_schema": FEATURE_SCHEMA,
        }
    return {
        "trained": True,
        "model": bundle.get("model_name", "modelo experimental"),
        "version": bundle.get("created_utc", "sin fecha"),
        "feature_schema": FEATURE_SCHEMA,
        "samples": bundle.get("samples", {}),
        "metrics": bundle.get("test_metrics", {}),
        "baseline_metrics": bundle.get("baseline_metrics", {}),
        "data_notes": bundle.get("data_notes", ""),
        "message": "Resultados experimentales; no equivalen a una certificación de seguridad.",
    }


def predict(url: str) -> dict:
    bundle = _load()
    if bundle is None:
        return {"available": False, "message": "ML pendiente de entrenamiento; se muestra solo el análisis heurístico."}
    try:
        probability = float(bundle["model"].predict_proba([feature_vector(url)])[0][1])
    except (ValueError, TypeError, IndexError, AttributeError):
        return {"available": False, "message": "No fue posible aplicar el modelo; el análisis heurístico permanece disponible."}
    probability = min(1.0, max(0.0, probability))
    return {
        "available": True,
        "model": str(bundle.get("model_name", "modelo experimental")),
        "model_version": str(bundle.get("created_utc", "sin fecha")),
        "phishing_probability": round(probability, 4),
        "prediction": "suspicious" if probability >= 0.5 else "low_risk",
        "message": "Estimación experimental aprendida de un dataset; no garantiza que la URL sea segura o maliciosa.",
    }
