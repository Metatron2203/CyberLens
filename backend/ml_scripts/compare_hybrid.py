"""Comparación exploratoria A/B/C de datos reales y sintéticos.

No accede a URLs ni sustituye modelos. Reconstruye el corpus equilibrado
anterior, comprueba sus grupos y reutiliza solo train/validación. El test
anterior ya observado y las 500 muestras históricas no se usan aquí.
La validación es de desarrollo, NO una nueva evaluación final.
"""
import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit

from ml_scripts.generate_synthetic import generate_synthetic
from ml_scripts.train import OUTPUT_DIR, grouped_split, scores
from ml_scripts.train_balanced import DATA, MODEL, CANDIDATE, collect, prior_groups


def compare_modes(items, synthetic, seed=42):
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier

    X = np.array([row[0] for row in items], dtype=float)
    y = np.array([row[1] for row in items], dtype=int)
    groups = np.array([row[2] for row in items])
    tr, val, test = grouped_split(X, y, groups, seed)
    sx = np.array([row[0] for row in synthetic], dtype=float)
    sy = np.array([row[1] for row in synthetic], dtype=int)
    sg = {row[2] for row in synthetic}
    if sg & set(groups):
        raise ValueError("Los grupos sintéticos y reales se superponen")
    if set(sy) != {0, 1}:
        raise ValueError("Se requieren ambas clases sintéticas")

    configurations = {
        "A_real": (X[tr], y[tr]),
        "B_synthetic": (sx, sy),
        "C_hybrid": (np.concatenate([X[tr], sx]), np.concatenate([y[tr], sy])),
    }
    subsets = {"simple": [], "complex": []}
    for j, i in enumerate(val):
        parts = urlsplit(items[i][3])
        kind = "complex" if parts.path not in ("", "/") or parts.query else "simple"
        subsets[kind].append(j)

    results = {}
    for name, (features, labels) in configurations.items():
        model = RandomForestClassifier(
            n_estimators=160, min_samples_leaf=2, max_depth=14,
            class_weight="balanced_subsample", n_jobs=1, random_state=seed,
        )
        model.fit(features, labels)
        predictions = model.predict(X[val])
        results[name] = {
            "training_count": len(labels),
            "validation_metrics": scores(y[val], predictions),
            "by_complexity": {
                kind: scores(y[val][indices], predictions[indices])
                for kind, indices in subsets.items() if indices
            },
        }
    return {
        "evaluation_kind": "development_validation_only",
        "real_train_count": len(tr),
        "real_validation_count": len(val),
        "previous_test_not_used_count": len(test),
        "synthetic_count": len(synthetic),
        "seed": seed,
        "algorithm": "Random Forest (mismos hiperparametros en A/B/C)",
        "experiments": results,
        "limitations": [
            "Validación de desarrollo sobre el corpus equilibrado previo, no test final nuevo.",
            "Los casos sintéticos son escenarios hipotéticos .test, no ataques verificados.",
            "Los modelos no se guardan ni se promueven; no se modifica el modelo activo.",
            "La muestra real se limita a HTTPS y a estratos emparejados; no representa Internet.",
            "Se requiere una evaluación final con datos nuevos de fuente independiente.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Compara A/B/C sin red ni reemplazo de modelos")
    parser.add_argument("--synthetic-per-class", type=int, default=160)
    parser.add_argument("--output", type=Path, default=OUTPUT_DIR / "hybrid_comparison.metrics.json")
    args = parser.parse_args(argv)
    if args.output.suffix.lower() != ".json" or args.output.exists():
        parser.error("La salida debe ser un JSON nuevo; conserva los informes anteriores")
    try:
        import joblib
        excluded, _ = prior_groups(MODEL, DATA / "phiusiil_external.csv")
        items, _ = collect([
            ("PhiUSIIL", DATA / "PhiUSIIL_Phishing_URL_Dataset.csv", "label"),
            ("LegitPhish", DATA / "url_features_extracted1.csv", "ClassLabel"),
        ], excluded, per_stratum=500)
        previous = joblib.load(CANDIDATE)
        expected = set(previous.get("dataset_group_fingerprints", []))
        if not expected or expected != {row[2] for row in items}:
            raise ValueError("No coincide el corpus equilibrado previo; no continuar sin revisar")
        synthetic = generate_synthetic(args.synthetic_per_class)
        result = compare_modes(items, synthetic)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    except (OSError, ValueError, TypeError, ImportError, AttributeError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print("Informe:", args.output)
    print("Experimento de desarrollo; modelos activos intactos.")


if __name__ == "__main__":
    main()
