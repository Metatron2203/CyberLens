"""Convierte PhiUSIIL (UCI) a un CSV de evaluación externa de CyberLens.

PhiUSIIL original: label 1=legítima, 0=phishing.
CyberLens: label 0=candidata legítima, 1=phishing.

No accede a ninguna URL, no descarga datos y no modifica el modelo.
La muestra resultante permanece local en backend/data/ (ignorado por Git).
"""

import argparse
import csv
import json
import random
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from app.ml.features import feature_vector, group_key

BACKEND_DIR = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = BACKEND_DIR / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"
DEFAULT_OUTPUT = BACKEND_DIR / "data" / "phiusiil_external.csv"
DEFAULT_MODEL = BACKEND_DIR / "models" / "cyberlens_ml.joblib"

REDIRECT_KEYS = {
    "url", "u", "link", "target", "dest", "destination", "next",
    "redirect", "redirect_url", "redirect_uri", "return", "returnto",
    "continue", "p1",
}
LOGIN_TERMS = ("login", "log-in", "sign-in", "signin", "password", "auth", "session", "account")


def classify_category(url: str) -> str:
    """Clasificación léxica de un caso (NO determina seguridad)."""
    parts = urlsplit(url)
    try:
        pairs = parse_qsl(parts.query, keep_blank_values=True, max_num_fields=256)
    except ValueError:
        pairs = []
    if any(key.lower() in REDIRECT_KEYS for key, _ in pairs):
        return "redirect"
    if any(term in parts.path.lower() for term in LOGIN_TERMS):
        return "login"
    if parts.query:
        return "query"
    return "other"


def prepare_external_csv(
    source: Path,
    output: Path,
    *,
    per_class: int = 250,
    seed: int = 2026,
    excluded_groups=None,
) -> dict:
    """Muestra hasta N de cada clase sin repetir grupos de dominio.

    Para un conjunto realmente externo se excluyen huellas de grupos del
    corpus anterior (train, validación Y test). No se usa ninguna predicción
    del modelo para decidir qué muestra entra en el conjunto.
    """
    if not 10 <= per_class <= 2500:
        raise ValueError("--per-class debe estar entre 10 y 2500")
    if source.resolve() == output.resolve():
        raise ValueError("Entrada y salida no pueden ser el mismo archivo")
    if output.exists():
        raise ValueError("El archivo de salida ya existe; no se sobrescribe sin revisión")
    if source.stat().st_size > 250_000_000:
        raise ValueError("El archivo de entrada supera el límite de 250 MB")

    excluded = set(excluded_groups or ())
    candidate_rows = []
    group_labels = {}
    seen_urls = set()
    counters = Counter()
    with source.open("r", encoding="utf-8-sig", errors="replace", newline="") as fp:
        reader = csv.DictReader(fp)
        fields = {str(field).strip().lower(): field for field in (reader.fieldnames or [])}
        if not {"url", "label"}.issubset(fields):
            raise ValueError("El CSV PhiUSIIL necesita columnas URL y label")
        for record in reader:
            counters["input_rows"] += 1
            raw = (record.get(fields["url"]) or "").strip()
            label = (record.get(fields["label"]) or "").strip()
            if label not in {"0", "1"}:
                counters["invalid_label"] += 1
                continue
            if not raw or raw in seen_urls:
                counters["duplicate_or_empty"] += 1
                continue
            seen_urls.add(raw)
            try:
                feature_vector(raw)
                group = group_key(raw)
                category = classify_category(raw)
            except (ValueError, TypeError):
                counters["invalid_url"] += 1
                continue
            # Atención: invertir etiqueta de UCI.
            cyberlens_label = 0 if label == "1" else 1
            group_labels.setdefault(group, set()).add(cyberlens_label)
            if group in excluded:
                counters["overlap_with_previous_corpus"] += 1
                continue
            candidate_rows.append((raw, cyberlens_label, category, group))

    ambiguous_groups = {group for group, labels in group_labels.items() if len(labels) > 1}
    counters["conflicting_domain_groups"] = len(ambiguous_groups)
    rng = random.Random(seed)
    selected = []
    selected_groups = set()
    for label in (0, 1):
        pool = [row for row in candidate_rows
                if row[1] == label and row[3] not in ambiguous_groups]
        rng.shuffle(pool)
        count = 0
        for url, cls, category, group in pool:
            if group in selected_groups:
                continue
            selected.append((url, cls, category))
            selected_groups.add(group)
            count += 1
            if count >= per_class:
                break
        counters[f"selected_class_{label}"] = count

    if not counters["selected_class_0"] or not counters["selected_class_1"]:
        raise ValueError("No quedan muestras válidas de ambas clases tras filtrar dominios")
    rng.shuffle(selected)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.writer(fp)
        writer.writerow(["url", "label", "category"])
        writer.writerows(selected)
    categories = Counter(row[2] for row in selected)
    return {
        "input_rows": counters["input_rows"],
        "selected": {
            "candidate_legitimate": counters["selected_class_0"],
            "phishing": counters["selected_class_1"],
            "total": len(selected),
        },
        "categories": dict(sorted(categories.items())),
        "skipped_invalid_label": counters["invalid_label"],
        "skipped_invalid_url": counters["invalid_url"],
        "skipped_duplicate_or_empty": counters["duplicate_or_empty"],
        "skipped_overlap_with_previous_corpus": counters["overlap_with_previous_corpus"],
        "conflicting_domain_groups": counters["conflicting_domain_groups"],
        "distinct_groups_selected": len(selected_groups),
        "source": "PhiUSIIL, UCI (2024), etiquetas invertidas 1->0 y 0->1",
        "warning": (
            "Solo evaluación de URL sin visitar sitios. Etiquetas heredadas del dataset "
            "UCI, no verificadas individualmente. La selección por dominio usa "
            "agrupamiento aproximado; corpus de 2024 no es prueba temporal posterior "
            "al entrenamiento de 2026."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Preparar muestra PhiUSIIL offline para evaluación externa")
    parser.add_argument("--input", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--per-class", type=int, default=250)
    parser.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args(argv)
    try:
        # Joblib deserializa código: usar solo el modelo local creado por CyberLens.
        import joblib
        bundle = joblib.load(args.model)
        fingerprints = bundle.get("dataset_group_fingerprints") if isinstance(bundle, dict) else None
        if not isinstance(fingerprints, (list, tuple)) or not fingerprints:
            raise ValueError(
                "Modelo antiguo sin huellas de dominios: primero reentrena con el "
                "código V0.5 fase 3 y conserva una copia del modelo anterior."
            )
        result = prepare_external_csv(
            args.input, args.output, per_class=args.per_class,
            seed=args.seed, excluded_groups=fingerprints,
        )
    except (OSError, ValueError, TypeError, ImportError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print("CSV externo preparado localmente en:", args.output)
    print("No se visitó ninguna URL. No uses este CSV para entrenar o ajustar umbrales.")


if __name__ == "__main__":
    main()
