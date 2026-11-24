"""Evaluación offline de CyberLens V0.5 con un conjunto independiente.

No descarga feeds, abre URLs ni reentrena. Nunca imprime URLs de evaluación.
Para datos reales exige un modelo con huellas del corpus original y comprueba
que ningún grupo aparezca tanto en entrenamiento/test previo como en la
evaluación externa. Los modelos anteriores a esta fase no tienen esas huellas.

Uso desde backend:
  python -m ml_scripts.external_eval --demo-synthetic
  python -m ml_scripts.external_eval --csv data/external.csv --source "Corpus independiente verificado"
"""

import argparse
import csv
import json
from pathlib import Path

from app.analyzer.url_analyzer import analyze_url
from app.ml.features import FEATURE_NAMES, FEATURE_SCHEMA, feature_vector, group_key
from ml_scripts.train import OUTPUT_DIR, scores

MODEL_FILE = OUTPUT_DIR / "cyberlens_ml.joblib"
REPORT_FILE = OUTPUT_DIR / "external_eval.metrics.json"
CATEGORIES = {"login", "query", "redirect", "other"}
LABELS = {"0": 0, "1": 1, "legitimate": 0, "phishing": 1}


def load_cases(path: Path, *, max_rows: int = 5000) -> list[tuple[str, int, str]]:
    """CSV: url,label,category. Procesa cadenas offline y evita imprimir secretos."""
    if path.stat().st_size > 12_000_000:
        raise ValueError("El CSV excede 12 MB")
    rows: list[tuple[str, int, str]] = []
    seen = set()
    with path.open("r", encoding="utf-8-sig", newline="") as fp:
        reader = csv.DictReader(fp)
        fields = {str(x).strip().lower(): x for x in (reader.fieldnames or [])}
        if not {"url", "label"}.issubset(fields):
            raise ValueError("El CSV debe contener encabezados url,label; category es opcional")
        for n, row in enumerate(reader, start=2):
            if len(rows) >= max_rows:
                raise ValueError("Demasiadas muestras: máximo 5000")
            url = (row.get(fields["url"]) or "").strip()
            raw_label = (row.get(fields["label"]) or "").strip().lower()
            category = (row.get(fields["category"]) or "other").strip().lower() if "category" in fields else "other"
            if raw_label not in LABELS or category not in CATEGORIES:
                raise ValueError(f"Etiqueta o categoría inválida en la fila {n}")
            if not url or url in seen:
                raise ValueError(f"URL vacía o duplicada en la fila {n}")
            try:
                feature_vector(url)
                group_key(url)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"URL inválida en la fila {n}") from None
            seen.add(url)
            rows.append((url, LABELS[raw_label], category))
    if len(rows) < 2:
        raise ValueError("Se requieren al menos dos URLs")
    return rows


def synthetic_challenge() -> list[tuple[str, int, str]]:
    """Casos totalmente ficticios .example; NO son una evaluación externa real."""
    return [
        ("https://tienda-uno.example/login", 0, "login"),
        ("https://biblioteca-dos.example/accounts/signin", 0, "login"),
        ("https://escuela-tres.example/auth/password/reset", 0, "login"),
        ("https://portal-cuatro.example/user/login?return=/dashboard", 0, "login"),
        ("https://universidad-cinco.example/session?continue=/campus", 0, "login"),
        ("https://salud-seis.example/login/mfa/verify", 0, "login"),
        ("https://proveedor-siete.example/search?q=login&sort=desc", 0, "query"),
        ("https://municipio-ocho.example/servicio/tramite?id=3&lang=es", 0, "query"),
        ("https://comercio-nueve.example/account/orders?page=2&mode=summary", 0, "query"),
        ("https://sitio-diez.example/r?next=https%3A%2F%2Fportal-once.example%2Flogin", 0, "redirect"),
        ("https://sitio-doce.example/out?target=https%3A%2F%2Fbanco-trece.example%2Fayuda", 0, "redirect"),
        ("https://sitio-catorce.example/redirect?url=%2Fperfil%2Flogin", 0, "redirect"),
        ("http://cuenta-falsa-uno.example/login/verify?secure=1", 1, "login"),
        ("http://actualiza-clave-dos.example/account/reset/password", 1, "login"),
        ("http://premio-tres.example/?claim=urgent&token=test", 1, "query"),
        ("https://alerta-cuatro.example/login?next=https%3A%2F%2Fcuenta-falsa-cinco.example%2Fauth", 1, "redirect"),
        ("http://servicio-seis.example/verify?account=update&pin=123", 1, "query"),
        ("http://premio-siete.example/login/confirm", 1, "login"),
    ]


def evaluate_cases(cases, bundle: dict, *, source: str, strict: bool) -> dict:
    """Devuelve solo métricas agregadas. Exige huellas para evaluación real."""
    if bundle.get("schema") != FEATURE_SCHEMA or tuple(bundle.get("feature_names", [])) != FEATURE_NAMES:
        raise ValueError("El modelo tiene un esquema de características incompatible")
    model = bundle.get("model")
    if not callable(getattr(model, "predict_proba", None)):
        raise ValueError("El modelo no admite inferencia predict_proba")
    if not source or len(source) > 120 or any(x in source for x in ("/", "\\", "@", "?", ":")):
        raise ValueError("La fuente debe ser una descripción corta, sin URLs o rutas")

    fingerprints = bundle.get("dataset_group_fingerprints")
    if strict:
        if not isinstance(fingerprints, (list, tuple)) or not fingerprints:
            raise ValueError(
                "El modelo anterior no registra grupos de dominio. Para una evaluación "
                "externa verificable debes reentrenar con V0.5 fase 3; "
                "no se ejecutó la evaluación."
            )
        known = set(fingerprints)
        overlap = {group_key(url) for url, _, _ in cases} & known
        if overlap:
            raise ValueError(
                f"El conjunto externo comparte {len(overlap)} grupo(s) con el corpus previo; "
                "no se ejecutó la evaluación."
            )

    actual = []
    predicted = []
    baseline = []
    category_true: dict[str, list[int]] = {}
    category_predictions: dict[str, list[int]] = {}
    for url, label, category in cases:
        features = feature_vector(url)
        probability = float(model.predict_proba([features])[0][1])
        if not 0 <= probability <= 1:
            raise ValueError("El modelo produjo una estimación fuera del rango")
        guess = int(probability >= 0.5)
        actual.append(label)
        predicted.append(guess)
        baseline.append(int(analyze_url(url)["risk_score"] >= 25))
        category_true.setdefault(category, []).append(label)
        category_predictions.setdefault(category, []).append(guess)

    result = {
        "evaluation_kind": "external" if strict else "synthetic_diagnostic_only",
        "model_name": str(bundle.get("model_name", "ML experimental")),
        "model_created_utc": str(bundle.get("created_utc", "sin fecha")),
        "source_description": source,
        "sample_count": len(cases),
        "unique_domain_groups": len({group_key(url) for url, _, _ in cases}),
        "group_overlap_check": "passed" if strict else "not verified (synthetic demo)",
        "model_metrics": scores(actual, predicted),
        "heuristic_baseline_metrics": scores(actual, baseline),
        "by_category": {
            name: scores(category_true[name], category_predictions[name])
            for name in sorted(category_true)
        },
        "limitations": [
            "No visita ni valida el contenido o la seguridad de las URLs.",
            "Las etiquetas y la independencia del proveedor requieren auditoría humana.",
            "Las huellas de dominio son una aproximación: la separación temporal y de campaña no está garantizada.",
            "El porcentaje ML no está calibrado.",
        ],
    }
    if not strict:
        result["limitations"].insert(
            0, "Muestras ficticias .example; nunca utilizar estas métricas para afirmar eficacia real."
        )
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evalúa offline un modelo CyberLens entrenado")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo-synthetic", action="store_true")
    mode.add_argument("--csv", type=Path, help="CSV externo con url,label,category")
    parser.add_argument("--source", help="Procedencia documentada, sin URLs ni rutas")
    parser.add_argument("--model", type=Path, default=MODEL_FILE)
    parser.add_argument("--output", type=Path, default=REPORT_FILE)
    args = parser.parse_args(argv)

    if args.csv and not args.source:
        parser.error("--source es obligatorio para CSV externo")
    if args.demo_synthetic and args.source:
        parser.error("La demo usa una fuente ficticia fija")

    try:
        # joblib carga objetos Python: solamente utilizar modelos propios, locales,
        # generados por CyberLens; nunca ficheros de terceros.
        import joblib
        bundle = joblib.load(args.model)
        if not isinstance(bundle, dict):
            raise ValueError("El modelo local no contiene un diccionario válido")
        cases = synthetic_challenge() if args.demo_synthetic else load_cases(args.csv)
        result = evaluate_cases(
            cases,
            bundle,
            source="Casos inventados .example (smoke test)" if args.demo_synthetic else args.source,
            strict=not args.demo_synthetic,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    except (OSError, ValueError, TypeError, IndexError, ImportError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print("Informe local:", args.output)
    if args.demo_synthetic:
        print("ADVERTENCIA: NO es una prueba externa real; URLs y etiquetas son ficticias.")


if __name__ == "__main__":
    main()
