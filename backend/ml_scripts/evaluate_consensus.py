"""Fase 4E: diagnóstico de decisión con abstención; no cambia la API.

No reentrena ni ajusta la política sobre el test. Por defecto reconstruye
la validación ya observada. La evaluación final externa sigue pendiente.
"""
import argparse
import json
from pathlib import Path

from app.analyzer.consensus import decide, LEVELS, POLICY_VERSION, HEURISTIC_THRESHOLD
from app.analyzer.url_analyzer import analyze_url
from app.ml.features import FEATURE_NAMES, FEATURE_SCHEMA, feature_vector, group_key
from ml_scripts.train import OUTPUT_DIR, grouped_split, scores
from ml_scripts.train_balanced import DATA, MODEL, CANDIDATE, collect, prior_groups
from ml_scripts.generate_synthetic import generate_synthetic
from ml_scripts.tune_hybrid_threshold import EXPERIMENTAL_MODEL
from ml_scripts.external_eval import load_cases

REPORT = OUTPUT_DIR / "consensus_validation.metrics.json"


def selective_metrics(labels, decisions):
    labels, decisions = list(labels), list(decisions)
    if not labels or len(labels) != len(decisions) or any(y not in (0, 1) for y in labels):
        raise ValueError("Etiquetas invalidas")
    if any(d not in LEVELS for d in decisions):
        raise ValueError("Decision invalida")
    table = {name: {level: 0 for level in LEVELS} for name in ("legitimate", "phishing")}
    for y, d in zip(labels, decisions):
        table["phishing" if y else "legitimate"][d] += 1
    neg, pos = table["legitimate"], table["phishing"]
    n, p = sum(neg.values()), sum(pos.values())
    definitive = n + p - neg["uncertain"] - pos["uncertain"]
    errors = neg["high"] + pos["low"]

    def ratio(a, b):
        return round(a / b, 4) if b else None

    return {
        "counts": table,
        "total": n + p,
        "coverage": ratio(definitive, n + p),
        "uncertain_rate": ratio(neg["uncertain"] + pos["uncertain"], n + p),
        "selective_error_rate": ratio(errors, definitive),
        "phishing_marked_high_rate": ratio(pos["high"], p),
        "phishing_marked_low_rate": ratio(pos["low"], p),
        "phishing_uncertain_rate": ratio(pos["uncertain"], p),
        "legitimate_marked_high_rate": ratio(neg["high"], n),
        "legitimate_uncertain_rate": ratio(neg["uncertain"], n),
        "phishing_alert_or_uncertain_rate": ratio(pos["high"] + pos["uncertain"], p),
        "legitimate_alert_or_uncertain_rate": ratio(neg["high"] + neg["uncertain"], n),
    }


def evaluate(items, bundle):
    if bundle.get("schema") != FEATURE_SCHEMA or tuple(bundle.get("feature_names", ())) != FEATURE_NAMES:
        raise ValueError("Esquema incompatible")
    threshold = bundle.get("decision_threshold")
    model = bundle["model"]
    if list(model.classes_) != [0, 1]:
        raise ValueError("Clases ML incompatibles")
    labels, predicted, heuristic, decisions = [], [], [], []
    for vector, label, group, url in items:
        p = float(model.predict_proba([vector])[0][1])
        h = analyze_url(url)["risk_score"]
        decision = decide(h, p, threshold)
        if decision["reason"] == "ml_unavailable":
            raise ValueError("Puntuacion ML invalida en evaluacion")
        labels.append(label)
        predicted.append(int(p >= threshold))
        heuristic.append(int(h >= HEURISTIC_THRESHOLD))
        decisions.append(decision["level"])
    return {
        "policy_version": POLICY_VERSION,
        "decision_threshold": threshold,
        "heuristic_threshold": HEURISTIC_THRESHOLD,
        "ml_binary_reference": scores(labels, predicted),
        "heuristic_binary_reference": scores(labels, heuristic),
        "consensus": selective_metrics(labels, decisions),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evalua consenso sin modificar modelos ni API")
    parser.add_argument("--external-csv", type=Path)
    parser.add_argument("--output", type=Path, default=REPORT)
    args = parser.parse_args(argv)
    if args.output.suffix.lower() != ".json" or args.output.exists():
        parser.error("Usa un archivo JSON nuevo para conservar los informes")
    if args.external_csv and args.output.resolve() == REPORT.resolve():
        parser.error("Usa --output separado para la evaluacion externa")
    try:
        import joblib
        bundle = joblib.load(EXPERIMENTAL_MODEL)
        if not bundle.get("experimental_only"):
            raise ValueError("Se requiere el candidato experimental de fase 4D")
        known = set(bundle.get("dataset_group_fingerprints", []))
        if not known:
            raise ValueError("Faltan huellas de dominio")
        if args.external_csv:
            cases = load_cases(args.external_csv)
            items = [(feature_vector(u), y, group_key(u), u) for u, y, _ in cases]
            groups = {r[2] for r in items}
            if groups & known or len(groups) != len(items):
                raise ValueError("Grupos conocidos o repetidos en el corpus externo")
            if {r[1] for r in items} != {0, 1}:
                raise ValueError("El corpus externo requiere ambas clases")
            kind = "external_group_disjoint_source_requires_review"
        else:
            excluded, _ = prior_groups(MODEL, DATA / "phiusiil_external.csv")
            items, _ = collect([
                ("PhiUSIIL", DATA / "PhiUSIIL_Phishing_URL_Dataset.csv", "label"),
                ("LegitPhish", DATA / "url_features_extracted1.csv", "ClassLabel"),
            ], excluded, per_stratum=500)
            previous = joblib.load(CANDIDATE)
            groups = {r[2] for r in items}
            synthetic_groups = {r[2] for r in generate_synthetic(160)}
            if groups != set(previous.get("dataset_group_fingerprints", [])) or known != groups | excluded | synthetic_groups:
                raise ValueError("No coincide el corpus de desarrollo anterior")
            _, val, _ = grouped_split([r[0] for r in items], [r[1] for r in items],
                                      [r[2] for r in items], 42)
            items = [items[i] for i in val]
            kind = "development_validation_only"

        result = evaluate(items, bundle)
        if not args.external_csv and result["ml_binary_reference"] != bundle["validation_metrics"]:
            raise ValueError("La referencia ML no reproduce las metricas de fase 4D")
        result["evaluation_kind"] = kind
        result["limitations"] = [
            "Riesgo bajo significa pocas senales; nunca seguridad verificada.",
            "Incierto requiere revision; no cuenta como deteccion confirmada.",
            "Los dos motores comparten datos lexicos y no son evidencia independiente.",
            "Sin red, contenido HTML, reputacion ni verificacion actual del destino.",
            "La validacion de desarrollo ya fue utilizada; la procedencia externa requiere revision humana.",
        ]
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as fp:
            json.dump(result, fp, ensure_ascii=False, indent=2)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, ImportError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print("Informe:", args.output)
    print("Politica experimental offline. API y modelos sin cambios.")


if __name__ == "__main__":
    main()
