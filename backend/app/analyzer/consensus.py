"""Regla experimental de consenso, independiente de la API y de la red.

Las dos señales comparten características léxicas: su acuerdo no es
confirmación independiente. Riesgo bajo nunca significa sitio seguro.
"""
import math

POLICY_VERSION = "consensus-v1"
HEURISTIC_THRESHOLD = 25
LEVELS = ("low", "uncertain", "high")


def decide(heuristic_score, ml_score, threshold):
    """Sin ML válido, devolver incertidumbre; no inferir seguridad."""
    if type(heuristic_score) not in (int, float) or not 0 <= heuristic_score <= 100:
        raise ValueError("Puntaje heurístico inválido")
    if type(threshold) not in (int, float) or not 0 < threshold <= 1:
        raise ValueError("Umbral ML inválido")
    if (type(ml_score) not in (int, float) or not math.isfinite(ml_score)
            or not 0 <= ml_score <= 1):
        return {"level": "uncertain", "reason": "ml_unavailable"}
    heuristic_alert = heuristic_score >= HEURISTIC_THRESHOLD
    ml_alert = ml_score >= threshold
    if heuristic_alert and ml_alert:
        return {"level": "high", "reason": "both_alert"}
    if heuristic_alert or ml_alert:
        return {"level": "uncertain", "reason": "disagreement"}
    return {"level": "low", "reason": "neither_alert"}
