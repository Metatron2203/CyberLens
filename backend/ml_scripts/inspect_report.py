"""Resume la incertidumbre del último informe ML guardado localmente.

No entrena, no descarga feeds, no visita URLs ni modifica el modelo.
Uso desde backend:
  python -m ml_scripts.inspect_report
  python -m ml_scripts.inspect_report --report models/cyberlens_ml.metrics.json
"""

import argparse
import json
from pathlib import Path

from ml_scripts.train import OUTPUT_DIR, wilson_interval


def inspect_report(report: dict) -> dict:
    """Analiza únicamente los cuatro conteos agregados del test anterior."""
    try:
        matrix = report["test_metrics"]["confusion_matrix"]
        counts = {key: matrix[key] for key in ("tn", "fp", "fn", "tp")}
    except (KeyError, TypeError) as exc:
        raise ValueError("El informe no contiene una matriz de confusión válida") from exc
    if any(type(value) is not int or value < 0 for value in counts.values()):
        raise ValueError("Los valores de la matriz deben ser enteros no negativos")
    tn, fp, fn, tp = (counts[key] for key in ("tn", "fp", "fn", "tp"))
    positives = tp + fn
    negatives = tn + fp
    warned = [
        "Estos intervalos son aproximaciones por observación; no corrigen sesgo "
        "de fuente, errores de etiqueta ni dependencia entre dominios/campañas.",
        "La clase negativa basada en Tranco no equivale a sitios verificados como seguros.",
    ]
    if positives < 100 or negatives < 100:
        warned.append("Test pequeño: los resultados tienen alta incertidumbre.")
    return {
        "test_total": positives + negatives,
        "test_phishing": positives,
        "test_candidate_legitimate": negatives,
        "false_negative_count": fn,
        "false_positive_count": fp,
        "recall": round(tp / positives, 4) if positives else None,
        "false_positive_rate": round(fp / negatives, 4) if negatives else None,
        "recall_wilson_95": wilson_interval(tp, positives),
        "false_positive_rate_wilson_95": wilson_interval(fp, negatives),
        "warnings": warned,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inspección local de incertidumbre del test ML")
    parser.add_argument("--report", type=Path, default=OUTPUT_DIR / "cyberlens_ml.metrics.json")
    args = parser.parse_args(argv)
    try:
        raw = json.loads(args.report.read_text(encoding="utf-8"))
        summary = inspect_report(raw)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(f"No fue posible interpretar el reporte: {exc}")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print("NOTA: 95 % Wilson no significa 95 % de eficacia en Internet.")


if __name__ == "__main__":
    main()
