"""Fase 4D: selección de umbral SOLO en validación de desarrollo.

Reconstruye la muestra previa, entrena C con real train + sintético y congela
el umbral sin consultar los resultados del test histórico. No usa red.
El candidato es local y experimental; nunca sustituye al modelo activo.
"""
import argparse
import json
import math
from datetime import datetime, timezone

from app.ml.features import FEATURE_NAMES, FEATURE_SCHEMA
from ml_scripts.generate_synthetic import generate_synthetic
from ml_scripts.train import OUTPUT_DIR, grouped_split, scores
from ml_scripts.train_balanced import DATA, MODEL, CANDIDATE, collect, prior_groups

REPORT = OUTPUT_DIR / "hybrid_threshold.metrics.json"
EXPERIMENTAL_MODEL = OUTPUT_DIR / "cyberlens_ml_hybrid_candidate.joblib"


def select_threshold(labels, probabilities, *, max_fpr=0.10):
    """Malla fija 0.05 a 1.00; maximiza TP sujeto a FP/N <= max_fpr.

    Desempate: menos falsos positivos, luego umbral mayor.
    Nunca utiliza datos de test. Puede no encontrar solución.
    """
    labels = list(labels)
    probabilities = [float(x) for x in probabilities]
    if not math.isfinite(max_fpr) or not 0 <= max_fpr < 1:
        raise ValueError("Limite FPR invalido")
    if len(labels) != len(probabilities) or set(labels) != {0, 1}:
        raise ValueError("Validacion debe contener ambas clases y puntuaciones alineadas")
    if any(not math.isfinite(p) or not 0 <= p <= 1 for p in probabilities):
        raise ValueError("Puntuaciones invalidas")
    negative_count = labels.count(0)
    curve = []
    for step in range(1, 21):
        threshold = step / 20
        metrics = scores(labels, [int(p >= threshold) for p in probabilities])
        matrix = metrics["confusion_matrix"]
        feasible = matrix["fp"] / negative_count <= max_fpr + 1e-12
        curve.append({"threshold": threshold, "feasible": feasible, "metrics": metrics})
    eligible = [row for row in curve if row["feasible"]]
    chosen = max(eligible, key=lambda row: (
        row["metrics"]["confusion_matrix"]["tp"],
        -row["metrics"]["confusion_matrix"]["fp"],
        row["threshold"],
    )) if eligible else None
    return {
        "max_validation_fpr": max_fpr,
        "selection_rule": "max TP, min FP, then highest threshold",
        "baseline_050": curve[9],
        "chosen": chosen,
        "curve": curve,
    }


def fit_hybrid(items, synthetic, excluded_groups, *, seed=42):
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier

    X = np.array([row[0] for row in items], dtype=float)
    y = np.array([row[1] for row in items], dtype=int)
    groups = np.array([row[2] for row in items])
    tr, val, test = grouped_split(X, y, groups, seed)
    sx = np.array([row[0] for row in synthetic], dtype=float)
    sy = np.array([row[1] for row in synthetic], dtype=int)
    real_groups, synth_groups = set(groups), {r[2] for r in synthetic}
    if real_groups & set(excluded_groups) or synth_groups & (real_groups | set(excluded_groups)):
        raise ValueError("Solapamiento de grupos excluidos, reales o sinteticos")
    if set(sy) != {0, 1}:
        raise ValueError("Se requieren ambas clases sinteticas")

    estimator = RandomForestClassifier(
        n_estimators=160, min_samples_leaf=2, max_depth=14,
        class_weight="balanced_subsample", n_jobs=1, random_state=seed,
    )
    estimator.fit(np.concatenate([X[tr], sx]), np.concatenate([y[tr], sy]))
    probabilities = estimator.predict_proba(X[val])[:, 1]
    selection = select_threshold(y[val].tolist(), probabilities.tolist())
    chosen = selection["chosen"]
    report = {
        "evaluation_kind": "development_threshold_selection_only",
        "model_name": "Random Forest hibrido experimental",
        "real_train_count": len(tr),
        "synthetic_train_count": len(synthetic),
        "real_validation_count": len(val),
        "previous_test_not_used_count": len(test),
        "selection": selection,
        "recall_goal": 0.90,
        "recall_goal_met": bool(chosen and chosen["metrics"]["recall"] >= 0.90),
        "limitations": [
            "Umbral elegido en la misma validacion de desarrollo ya utilizada en fase 4C.",
            "No es una probabilidad calibrada, ni una estimacion final de rendimiento.",
            "Corpus real emparejado y restringido a HTTPS; etiquetas historicas.",
            "No se reentrena sobre validacion despues de congelar el umbral.",
            "Se necesita un corpus real nuevo, independiente, antes de promover el candidato.",
        ],
    }
    if chosen is None:
        return report, None

    bundle = {
        "schema": FEATURE_SCHEMA,
        "feature_names": FEATURE_NAMES,
        "model_name": report["model_name"],
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "model": estimator,
        "decision_threshold": chosen["threshold"],
        "experimental_only": True,
        "validation_metrics": chosen["metrics"],
        # Exclusion conservadora: incluye corpus previo, validacion y test historicos.
        "dataset_group_fingerprints": sorted(str(g) for g in
            real_groups | synth_groups | set(excluded_groups)),
        "data_notes": "Candidato offline. Umbral seleccionado solo en desarrollo; sin test final.",
    }
    return report, bundle


def main(argv=None):
    parser = argparse.ArgumentParser(description="Selecciona umbral del candidato hibrido sin usar test")
    args = parser.parse_args(argv)
    if REPORT.exists() or EXPERIMENTAL_MODEL.exists():
        parser.error("Ya existe un informe o candidato de fase 4D. Conserva los archivos antes de repetir.")
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
            raise ValueError("No coincide el conjunto de grupos del corpus anterior")
        report, bundle = fit_hybrid(items, generate_synthetic(160), excluded)
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        if bundle is not None:
            joblib.dump(bundle, EXPERIMENTAL_MODEL)
        with REPORT.open("x", encoding="utf-8") as fp:
            json.dump(report, fp, ensure_ascii=False, indent=2)
    except (OSError, ValueError, TypeError, ImportError, AttributeError) as exc:
        parser.error(str(exc))
    selection = report["selection"]
    print("Umbral original 0.50:", json.dumps(selection["baseline_050"], ensure_ascii=False))
    print("Umbral seleccionado:", json.dumps(selection["chosen"], ensure_ascii=False))
    print("Meta recall >= 90% en validacion:", report["recall_goal_met"])
    print("Informe:", REPORT)
    if bundle is None:
        print("Sin umbral factible; no se guardo candidato.")
    else:
        print("Candidato experimental:", EXPERIMENTAL_MODEL)
    print("No se cambio el modelo activo. Sin validacion final.")


if __name__ == "__main__":
    main()
