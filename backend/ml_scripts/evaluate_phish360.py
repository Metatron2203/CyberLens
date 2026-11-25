"""Fase 4F: comparación externa congelada con Phish360 (solo URL y clase).

No descarga, abre ni imprime URLs; no lee HTML o imágenes, no reentrena.
Los archivos originales y los informes permanecen fuera de Git.
"""
import argparse
import hashlib
import json
import random
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit

from app.analyzer.consensus import decide, HEURISTIC_THRESHOLD, POLICY_VERSION
from app.analyzer.url_analyzer import analyze_url
from app.ml.features import FEATURE_NAMES, FEATURE_SCHEMA, feature_vector, group_key
from ml_scripts.evaluate_consensus import selective_metrics
from ml_scripts.train import OUTPUT_DIR, scores
from ml_scripts.train_balanced import DATA, MODEL, CANDIDATE, prior_groups
from ml_scripts.tune_hybrid_threshold import EXPERIMENTAL_MODEL

FOLDER = DATA / "Phish360"
REPORT = OUTPUT_DIR / "phish360_final.metrics.json"
SEED = 2026
CAP_PER_CLASS = 1000
CLASS_NAMES = {0: {"legit", "legitimate", "benign"}, 1: {"phish", "phishing"}}


def read_parquet_rows(path, label):
    import pyarrow.parquet as pq
    parquet = pq.ParquetFile(path)
    # Los archivos originales usan Class; admitir class sin ambigüedad.
    names = parquet.schema_arrow.names
    class_columns = [name for name in names if name.casefold() == "class"]
    if names.count("URL") != 1 or len(class_columns) != 1:
        raise ValueError(f"{path.name}: columnas URL y Class ausentes o ambiguas")
    class_column = class_columns[0]
    # Validar todas las etiquetas antes de procesar URLs. No mostrar valores
    # de etiquetas desconocidos, pues podrían contener contenido inesperado.
    for batch in parquet.iter_batches(batch_size=512, columns=[class_column]):
        for row in batch.to_pylist():
            if str(row[class_column]).strip().casefold() not in CLASS_NAMES[label]:
                raise ValueError(f"{path.name}: etiqueta no reconocida o contradictoria; revisa los recuentos de Class")
    # Proyección de columnas: no materializar HTML, capturas ni otros datos.
    for batch in parquet.iter_batches(batch_size=512, columns=["URL"]):
        for row in batch.to_pylist():
            yield row["URL"], label


def select_cases(rows, excluded, *, cap=CAP_PER_CLASS, seed=SEED, minimum=25):
    """Muestreo fijo, balanceado por clase, una URL por grupo."""
    counts = Counter()
    candidates = defaultdict(lambda: defaultdict(list))
    seen = set()
    group_labels = defaultdict(set)
    for url, label in rows:
        if label not in (0, 1):
            raise ValueError("Etiqueta invalida")
        counts[f"input_{label}"] += 1
        if not isinstance(url, str):
            counts["invalid"] += 1
            continue
        url = url.strip()
        try:
            vector, group = feature_vector(url), group_key(url)
            # Mismo extractor y motor para todos los modelos.
            heuristic = analyze_url(url)["risk_score"]
        except (ValueError, TypeError):
            counts["invalid"] += 1
            continue
        group_labels[group].add(label)
        if (url, label) in seen:
            counts["duplicate"] += 1
            continue
        seen.add((url, label))
        if group in excluded:
            counts["excluded_known_rows"] += 1
            continue
        candidates[label][group].append((url, label, group, vector, heuristic))
    conflicts = {g for g, labels in group_labels.items() if len(labels) > 1}
    counts["conflicting_groups"] = len(conflicts)
    rng = random.Random(seed)
    selected = {}
    for label in (0, 1):
        eligible = sorted(set(candidates[label]) - conflicts)
        counts[f"eligible_groups_{label}"] = len(eligible)
        rng.shuffle(eligible)
        selected[label] = [
            rng.choice(sorted(candidates[label][g], key=lambda r: r[0]))
            for g in eligible[:cap]
        ]
    n = min(len(selected[0]), len(selected[1]))
    if n < minimum:
        raise ValueError("Grupos insuficientes por clase para la evaluacion")
    items = selected[0][:n] + selected[1][:n]
    rng.shuffle(items)
    groups = {r[2] for r in items}
    if len(groups) != len(items) or groups & excluded or groups & conflicts:
        raise AssertionError("Fuga de grupos")
    profile = {}
    for label in (0, 1):
        subset = [r for r in items if r[1] == label]
        profile[str(label)] = {
            "count": len(subset),
            "http": sum(urlsplit(r[0]).scheme == "http" for r in subset),
            "complex": sum(bool(urlsplit(r[0]).path not in ("", "/") or urlsplit(r[0]).query) for r in subset),
            "with_query": sum(bool(urlsplit(r[0]).query) for r in subset),
        }
    return items, {
        "counts": dict(counts), "selected_per_class": n, "unique_groups": len(groups),
        "excluded_group_count": len(excluded), "seed": seed,
        "cap_per_class": cap, "profile": profile, "group_overlap_check": "passed",
    }


def compare(items, bundles):
    import numpy as np
    y = np.array([r[1] for r in items], dtype=int)
    X = np.array([r[3] for r in items], dtype=float)
    h = [r[4] for r in items]
    subset_indices = defaultdict(list)
    for i, item in enumerate(items):
        parts = urlsplit(item[0])
        subset_indices[parts.scheme].append(i)
        kind = "complex" if parts.path not in ("", "/") or parts.query else "simple"
        subset_indices[kind].append(i)
    results = {}
    for name, bundle in bundles.items():
        if bundle.get("schema") != FEATURE_SCHEMA or tuple(bundle.get("feature_names", ())) != FEATURE_NAMES:
            raise ValueError("Modelo incompatible")
        threshold = bundle.get("decision_threshold", 0.5)
        if type(threshold) not in (int, float) or not 0 < threshold <= 1:
            raise ValueError("Umbral incompatible")
        estimator = bundle["model"]
        if list(estimator.classes_) != [0, 1]:
            raise ValueError("Clases ML incompatibles")
        proba = np.asarray(estimator.predict_proba(X), dtype=float)
        if proba.shape != (len(items), 2) or not np.isfinite(proba).all() or not ((proba >= 0) & (proba <= 1)).all():
            raise ValueError("Puntuaciones ML invalidas")
        p = proba[:, 1]
        predicted = (p >= threshold).astype(int)
        results[name] = {
            "model_name": bundle["model_name"],
            "model_created_utc": bundle.get("created_utc"),
            "decision_threshold": threshold,
            "metrics": scores(y, predicted),
            "by_subset": {key: scores(y[idx], predicted[idx]) for key, idx in sorted(subset_indices.items())},
        }
        if name == "C_hybrid":
            decisions = [decide(score, float(prob), threshold)["level"] for score, prob in zip(h, p)]
            results["consensus_v1"] = {
                "policy_version": POLICY_VERSION,
                "metrics": selective_metrics(y.tolist(), decisions),
            }
    results["heuristic"] = {"decision_threshold": HEURISTIC_THRESHOLD,
                            "metrics": scores(y, [int(s >= HEURISTIC_THRESHOLD) for s in h])}
    return results


def sha256_file(path):
    with path.open("rb") as fp:
        return hashlib.file_digest(fp, "sha256").hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evalua Phish360 sin red ni reentrenamiento")
    parser.add_argument("--accept-academic-use", action="store_true",
                        help="Confirmar revision de condiciones de uso; no redistribuir archivos")
    args = parser.parse_args(argv)
    if not args.accept_academic_use:
        parser.error("Revisa condiciones de uso academico antes de ejecutar")
    if REPORT.exists():
        parser.error("Informe final existente; no repetir para seleccionar umbrales")
    try:
        import joblib
        paths = {"A_original": MODEL, "B_balanced": CANDIDATE, "C_hybrid": EXPERIMENTAL_MODEL}
        bundles = {key: joblib.load(path) for key, path in paths.items()}
        excluded, _ = prior_groups(MODEL, DATA / "phiusiil_external.csv")
        for bundle in bundles.values():
            if not isinstance(bundle, dict) or not bundle.get("dataset_group_fingerprints"):
                raise ValueError("Modelo sin huellas de grupos")
            excluded.update(bundle["dataset_group_fingerprints"])
        if not bundles["C_hybrid"].get("experimental_only") or bundles["C_hybrid"].get("decision_threshold") != 0.4:
            raise ValueError("Candidato no coincide con el umbral congelado de fase 4D")
        if any(bundles[key].get("decision_threshold", 0.5) != 0.5 for key in ("A_original", "B_balanced")):
            raise ValueError("Umbral de referencia distinto de 0.5")
        files = [(FOLDER / "Phish360_legit.parquet", 0), (FOLDER / "Phish360_phish.parquet", 1)]
        rows = (row for path, label in files for row in read_parquet_rows(path, label))
        items, audit = select_cases(rows, excluded)
        result = {
            "evaluation_kind": "external_historical_cross_source",
            "source": "Phish360 (2020-2023)",
            "source_reference": "https://doi.org/10.3390/app16020751",
            "source_file_sha256": {path.name: sha256_file(path) for path, _ in files},
            "model_file_sha256": {key: sha256_file(path) for key, path in paths.items()},
            "sampling": audit,
            "results": compare(items, bundles),
            "limitations": [
                "Etiquetas historicas del proveedor; no verifican seguridad actual.",
                "Muestreo balanceado y una URL por grupo; precision no representa prevalencia real.",
                "Grupos aproximados; independencia de campanas y fuentes originales no garantizada.",
                "HTTP incluido aunque B y C se entrenaron exclusivamente con HTTPS.",
                "Solo estructura de URL; no se visita ni analiza HTML o imagen.",
                "Umbrales congelados; no reajustar con este informe ni llamarlo validacion prospectiva.",
                "Incierto requiere revision y no equivale a deteccion confirmada.",
            ],
        }
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        with REPORT.open("x", encoding="utf-8") as fp:
            json.dump(result, fp, ensure_ascii=False, indent=2)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, ImportError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print("Informe:", REPORT)
    print("Evaluacion historica; modelos y API intactos.")


if __name__ == "__main__":
    main()
