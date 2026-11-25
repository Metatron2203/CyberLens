"""Experimento ML multidataset: HTTPS, complejidad y fuente balanceadas.

Lee exclusivamente los CSV locales. No descarga ni visita URLs. El conjunto
histórico PhiUSIIL externo y el corpus del modelo anterior quedan excluidos
por grupos aproximados de dominio. El nuevo modelo se guarda por separado.
Las etiquetas son heredadas de los datasets y no certifican seguridad actual.
"""
import argparse
import csv
import json
import random
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit

from app.ml.features import FEATURE_NAMES, FEATURE_SCHEMA, feature_vector, group_key
from ml_scripts.audit import dataset_audit
from ml_scripts.train import BACKEND_DIR, OUTPUT_DIR, train_models

DATA = BACKEND_DIR / "data"
MODEL = OUTPUT_DIR / "cyberlens_ml.joblib"
CANDIDATE = OUTPUT_DIR / "cyberlens_ml_balanced.joblib"


def collect(sources, excluded_groups, *, per_stratum=500, seed=2026):
    """Empareja clases dentro de cada fuente y complejidad; una URL por grupo."""
    if not 25 <= per_stratum <= 5000:
        raise ValueError("per_stratum debe estar entre 25 y 5000")
    counts = Counter()
    group_labels = defaultdict(set)
    pools = defaultdict(list)
    seen = set()
    for source_name, path, label_name in sources:
        with path.open(encoding="utf-8-sig", newline="") as fp:
            reader = csv.DictReader(fp)
            if not {"URL", label_name}.issubset(reader.fieldnames or []):
                raise ValueError(f"Columnas inesperadas en {source_name}")
            for row in reader:
                counts["input_rows"] += 1
                label_raw = (row.get(label_name) or "").strip()
                if label_raw not in {"0", "1"}:
                    counts["invalid_label"] += 1
                    continue
                label = 1 - int(label_raw)  # Ambas fuentes: 1 legitima, 0 phishing.
                counts[f"input_class_{label}"] += 1
                raw = (row.get("URL") or "").strip()
                try:
                    parts = urlsplit(raw)
                    if parts.scheme not in ("http", "https") or not parts.hostname:
                        raise ValueError()
                    if len(raw) > 2048 or any(c.isspace() for c in raw):
                        raise ValueError()
                    _ = parts.port
                    group = group_key(raw)
                except (ValueError, TypeError, AttributeError):
                    counts["invalid_url"] += 1
                    continue
                # Registrar contradicciones ANTES de deduplicar o filtrar HTTPS.
                group_labels[group].add(label)
                if group in excluded_groups:
                    counts["excluded_previous_group"] += 1
                    continue
                if parts.scheme != "https":
                    counts["excluded_non_https"] += 1
                    continue
                if (raw, label, source_name) in seen:
                    counts["duplicate"] += 1
                    continue
                seen.add((raw, label, source_name))
                complexity = "complex" if parts.path not in ("", "/") or parts.query else "simple"
                pools[(source_name, complexity, label)].append((group, raw))

    conflicts = {g for g, labels in group_labels.items() if len(labels) > 1}
    counts["conflicting_groups"] = len(conflicts)
    rng = random.Random(seed)
    selected = []
    used = set()
    strata = {}
    # Primero las URLs complejas: no consumir sus escasos dominios con portadas.
    for complexity in ("complex", "simple"):
        for source_name, _, _ in sources:
            eligible = {}
            for label in (0, 1):
                candidates = sorted(pools[(source_name, complexity, label)])
                rng.shuffle(candidates)
                unique = set()
                rows = []
                for group, raw in candidates:
                    if group in conflicts or group in used or group in unique:
                        continue
                    try:
                        vec = feature_vector(raw)
                    except (ValueError, TypeError):
                        counts["invalid_feature_candidate"] += 1
                        continue
                    unique.add(group)
                    rows.append((vec, label, group, raw))
                    if len(rows) >= per_stratum:
                        break
                eligible[label] = rows
            n = min(len(eligible[0]), len(eligible[1]))
            strata[f"{source_name}_{complexity}"] = {
                "available_up_to_cap_legitimate": len(eligible[0]),
                "available_up_to_cap_phishing": len(eligible[1]),
                "selected_per_class": n,
            }
            for label in (0, 1):
                for item in eligible[label][:n]:
                    selected.append(item)
                    used.add(item[2])

    if len(selected) < 100:
        raise ValueError("Menos de 100 casos emparejados; no se entrenó ningún modelo")
    complex_per_class = sum(
        stats["selected_per_class"] for name, stats in strata.items()
        if name.endswith("_complex")
    )
    if complex_per_class < 25:
        raise ValueError("Menos de 25 URLs complejas por clase; no se entrenó ningún modelo")
    rng.shuffle(selected)
    summary = {
        "counts": dict(counts),
        "matched_strata": strata,
        "complex_per_class": complex_per_class,
        "selected_per_class": len(selected) // 2,
        "selected_total": len(selected),
        "unique_groups": len(used),
        "sampling_seed": seed,
        "per_stratum_cap": per_stratum,
        "limitations": [
            "Solo HTTPS y estratos con ambas clases: no representa toda la web.",
            "Etiquetas historicas heredadas; complejidad es ruta o consulta, no seguridad.",
            "Grupo registrable aproximado; no garantiza independencia de campanas.",
            "Se excluyen dominios ambiguos y ya evaluados: puede cambiar la distribucion.",
            "El test es reservado por dominio dentro del corpus curado, no una fuente externa nueva.",
        ],
    }
    return selected, summary


def prior_groups(model_path, historical_csv):
    """Requiere modelo local confiable con huellas y el CSV de prueba historico."""
    import joblib
    bundle = joblib.load(model_path)
    if not isinstance(bundle, dict) or bundle.get("schema") != FEATURE_SCHEMA:
        raise ValueError("Modelo anterior incompatible")
    fingerprints = bundle.get("dataset_group_fingerprints")
    if not fingerprints:
        raise ValueError("El modelo anterior no registra grupos")
    groups = set(fingerprints)
    historical = set()
    with historical_csv.open(encoding="utf-8-sig", newline="") as fp:
        reader = csv.DictReader(fp)
        if "url" not in (reader.fieldnames or []):
            raise ValueError("El CSV historico requiere columna url")
        for row in reader:
            raw = row["url"]
            feature_vector(raw)
            historical.add(group_key(raw))
    if not historical:
        raise ValueError("El CSV historico esta vacio")
    return groups | historical, len(historical)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Entrenamiento multidataset equilibrado offline")
    parser.add_argument("--per-stratum", type=int, default=500)
    parser.add_argument("--output", type=Path, default=CANDIDATE)
    args = parser.parse_args(argv)
    if args.output.suffix.lower() != ".joblib" or args.output.resolve() == MODEL.resolve():
        parser.error("La salida debe ser otro archivo .joblib, no el modelo activo")
    if args.output.exists() or args.output.with_suffix(".metrics.json").exists():
        parser.error("La salida ya existe; usa otro nombre para conservar los experimentos")
    try:
        excluded, historical_count = prior_groups(MODEL, DATA / "phiusiil_external.csv")
        sources = [
            ("PhiUSIIL", DATA / "PhiUSIIL_Phishing_URL_Dataset.csv", "label"),
            ("LegitPhish", DATA / "url_features_extracted1.csv", "ClassLabel"),
        ]
        items, summary = collect(sources, excluded, per_stratum=args.per_stratum)
        summary["excluded_known_group_count"] = len(excluded)
        summary["historical_test_group_count"] = historical_count
        audit = dataset_audit(
            items,
            phishing_input_count=summary["counts"].get("input_class_1", 0),
            legitimate_input_count=summary["counts"].get("input_class_0", 0),
            conflicting_domain_groups=summary["counts"]["conflicting_groups"],
            source="PhiUSIIL y LegitPhish, muestra HTTPS emparejada",
            feature_names=FEATURE_NAMES,
        )
        audit["matched_sampling"] = summary
        print("Muestreo:", json.dumps(summary, ensure_ascii=False, indent=2))
        report, path = train_models(
            items, source="PhiUSIIL y LegitPhish, muestra HTTPS emparejada",
            model_path=args.output, audit=audit,
        )
    except (OSError, ValueError, TypeError, ImportError) as exc:
        parser.error(str(exc))
    print("Modelo elegido:", report["model_name"])
    print("Test reservado:", json.dumps(report["test_metrics"], ensure_ascii=False, indent=2))
    print("Heuristica:", json.dumps(report["baseline_metrics"], ensure_ascii=False, indent=2))
    print("Informe:", path.with_suffix(".metrics.json"))
    print("Modelo candidato separado; no se cambio el modelo activo.")
    print("No es una validacion externa ni una garantia de eficacia real.")


if __name__ == "__main__":
    main()
