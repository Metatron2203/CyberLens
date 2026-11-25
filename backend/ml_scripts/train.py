"""Entrenamiento reproducible de CyberLens ML, separado de la API.

Ejemplos (ejecutar desde backend):
  python -m ml_scripts.train --phishing data/phishing.csv --legitimate data/legitimate.csv
  python -m ml_scripts.train --academic-feeds --accept-academic-terms

Nunca se consultan URLs del dataset; solo se analizan como texto.
"""

import argparse
import csv
import hashlib
import io
import json
from math import sqrt
import random
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from app.analyzer.url_analyzer import analyze_url
from ml_scripts.audit import dataset_audit
from app.ml.features import FEATURE_NAMES, FEATURE_SCHEMA, feature_vector, group_key

BACKEND_DIR = Path(__file__).resolve().parents[1]
OUTPUT_DIR = BACKEND_DIR / "models"


def read_urls(path: Path, max_count: int) -> list[str]:
    """Formatos: CSV con columna url, TXT una URL por línea o TSV simple."""
    rows: list[str] = []
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fp:
        if path.suffix.lower() == ".csv":
            reader = csv.DictReader(fp)
            fields = {key.lower().strip(): key for key in (reader.fieldnames or [])}
            if "url" not in fields:
                raise ValueError(f"{path.name}: el CSV requiere columna 'url'")
            for record in reader:
                if (value := record.get(fields["url"], "").strip()):
                    rows.append(value)
                if len(rows) >= max_count:
                    break
        else:
            for line in fp:
                if (value := line.strip()):
                    rows.append(value)
                if len(rows) >= max_count:
                    break
    return rows


def _get(url: str, max_bytes: int) -> bytes:
    """Solicita únicamente URLs FIJAS de proveedores del dataset, nunca URLs listadas."""
    req = urllib.request.Request(url, headers={"User-Agent": "CyberLens-academic-research/0.3 (offline URL features; no link visits)"})
    with urllib.request.urlopen(req, timeout=35) as response:
        data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise RuntimeError("El feed supera el tamaño permitido")
    return data


def academic_feeds(max_per_class: int) -> tuple[list[str], list[str], str]:
    """OpenPhish Community + Tranco: uso solo académico y sujeto a sus términos.

    Nunca sigue enlaces incluidos en el feed; Tranco se utiliza únicamente
    como *proxy* de sitios legítimos, con sesgo de distribución reconocido.
    """
    phish_bytes = _get("https://openphish.com/feed.txt", max_bytes=8_000_000)
    phishing = [line.strip() for line in phish_bytes.decode("utf-8-sig", errors="replace").splitlines() if line.strip()][:max_per_class]
    meta = json.loads(_get("https://tranco-list.eu/api/lists/date/latest", max_bytes=100_000))
    list_id = meta.get("list_id")
    if not isinstance(list_id, str) or not list_id.isalnum():
        raise RuntimeError("No se obtuvo un ID válido de Tranco; descarga el CSV manualmente")
    # Solo descargamos las primeras filas, sin acceder a los dominios.
    text = _get(f"https://tranco-list.eu/download/{list_id}/{max_per_class*2}", max_bytes=1_500_000).decode("utf-8-sig", errors="replace")
    legitimate = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 2 and row[0].isdigit():
            legitimate.append("https://" + row[1].strip() + "/")
        if len(legitimate) >= max_per_class:
            break
    return phishing, legitimate, f"OpenPhish Community y Tranco {list_id} (candidatos legítimos; no verificados)"


def prepare(phishing: list[str], legitimate: list[str], limit: int = 10000):
    """Elimina duplicados, hosts conflictivos y entradas mal formadas; no guarda URLs."""
    rng = random.Random(2026)
    items = []
    seen = set()
    for label, urls in ((1, phishing), (0, legitimate)):
        shuffled = list(urls)
        rng.shuffle(shuffled)
        count = 0
        for raw in shuffled:
            url = raw.strip()
            # Un dominio aislado de Tranco se convierte en URL HTTPS de portada.
            if label == 0 and "://" not in url:
                url = "https://" + url + "/"
            if url in seen or len(url) > 2048:
                continue
            try:
                vec, group = feature_vector(url), group_key(url)
            except (ValueError, TypeError):
                continue
            seen.add(url)
            items.append((vec, label, group, url))
            count += 1
            if count >= limit:
                break
    group_labels: dict[str, set[int]] = {}
    for _, label, group, _ in items:
        group_labels.setdefault(group, set()).add(label)
    conflict = {group for group, labels in group_labels.items() if len(labels) > 1}
    # Evita que el mismo dominio aparezca en clases opuestas.
    filtered = [(vec, label, group, url) for vec, label, group, url in items if group not in conflict]
    if any(sum(label == cls for _, label, _, _ in filtered) < 20 for cls in (0, 1)):
        raise ValueError("Se necesitan al menos 20 URLs válidas de cada clase; verifica los CSV/feeds")
    if any(len({group for _, label, group, _ in filtered if label == cls}) < 12 for cls in (0, 1)):
        raise ValueError("Se necesitan al menos 12 grupos de dominio distintos por clase para evaluar sin fuga directa")
    return filtered, len(conflict)


def wilson_interval(successes: int, total: int) -> dict[str, float] | None:
    """Intervalo aproximado de Wilson al 95 %, por observaciones.

    No considera dependencia entre muestras ni errores de etiquetado;
    es optimista cuando existen URLs correlacionadas por campañas o fuentes.
    """
    if total < 0 or successes < 0 or successes > total:
        raise ValueError("Recuentos inválidos para el intervalo de Wilson")
    if total == 0:
        return None
    z = 1.959963984540054
    p = successes / total
    denom = 1.0 + z * z / total
    center = (p + z * z / (2.0 * total)) / denom
    margin = (z / denom) * sqrt(p * (1.0 - p) / total + z * z / (4.0 * total * total))
    return {"lower": round(max(0.0, center - margin), 4),
            "upper": round(min(1.0, center + margin), 4)}


def scores(y_true, y_pred) -> dict:
    from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
    tn, fp, fn, tp = (int(v) for v in confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel())
    positive_count = tp + fn
    negative_count = tn + fp
    predicted_positive = tp + fp
    tpr = tp / positive_count if positive_count else None
    tnr = tn / negative_count if negative_count else None
    return {
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "support": {
            "total": positive_count + negative_count,
            "phishing": positive_count,
            "candidate_legitimate": negative_count,
            "predicted_phishing": predicted_positive,
        },
        "error_rates": {
            "false_negative_rate": round(fn / positive_count, 4) if positive_count else None,
            "false_positive_rate": round(fp / negative_count, 4) if negative_count else None,
            "balanced_accuracy": round((tpr + tnr) / 2, 4) if tpr is not None and tnr is not None else None,
        },
        "confidence_intervals_95_wilson": {
            "recall": wilson_interval(tp, positive_count),
            "precision": wilson_interval(tp, predicted_positive),
            "false_positive_rate": wilson_interval(fp, negative_count),
        },
    }


def grouped_split(X, y, groups, seed):
    """3 particiones disjuntas por dominio, nunca por fila aleatoria."""
    import numpy as np
    from sklearn.model_selection import StratifiedGroupKFold
    y = np.array(y, dtype=int)
    X = np.array(X, dtype=float)
    groups = np.array(groups)
    outer = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
    trv, test = next(outer.split(X, y, groups))
    inner = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed + 1)
    itr, iva = next(inner.split(X[trv], y[trv], groups[trv]))
    train, val = trv[itr], trv[iva]
    for idx in (train, val, test):
        if len(set(y[idx])) != 2:
            raise ValueError("Una partición de validación carece de una clase; añade muestras de más dominios")
    if set(groups[train]) & set(groups[val]) or set(groups[train]) & set(groups[test]) or set(groups[val]) & set(groups[test]):
        raise AssertionError("Fuga de dominios entre las particiones")
    return train, val, test


def train_models(items, *, seed=42, source="CSV etiquetados localmente", model_path=None, audit=None):
    """Compara dos modelos en validación; evalúa el elegido UNA VEZ en test."""
    import joblib
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    X = np.array([r[0] for r in items], dtype=float)
    y = np.array([r[1] for r in items], dtype=int)
    groups = np.array([r[2] for r in items])
    tr, val, test = grouped_split(X, y, groups, seed)
    models = {
        "Regresión logística": lambda: make_pipeline(StandardScaler(), LogisticRegression(max_iter=1500, class_weight="balanced", random_state=seed)),
        "Random Forest": lambda: RandomForestClassifier(n_estimators=160, min_samples_leaf=2, max_depth=14, class_weight="balanced_subsample", n_jobs=1, random_state=seed),
    }
    validations = {}
    for name, factory in models.items():
        estimator = factory()
        estimator.fit(X[tr], y[tr])
        validations[name] = scores(y[val], estimator.predict(X[val]))
    winner = max(models.keys(), key=lambda key: (validations[key]["f1"], validations[key]["recall"], validations[key]["precision"]))
    model = models[winner]()
    trainval = np.concatenate([tr, val])
    model.fit(X[trainval], y[trainval])
    test_metrics = scores(y[test], model.predict(X[test]))
    # Línea base sobre la misma partición de test, sin visitar ninguna URL.
    baseline = scores(y[test], [int(analyze_url(items[i][3])["risk_score"] >= 25) for i in test])
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result = {
        "schema": FEATURE_SCHEMA,
        "feature_names": FEATURE_NAMES,
        "created_utc": created,
        "model_name": winner,
        "model": model,
        # Solo en el archivo local .joblib: SHA-256 de TODOS los grupos del corpus,
        # incluido el test original. No publicar: hash no equivale a anonimato.
        "dataset_group_fingerprints": sorted(str(item) for item in set(groups)),
        "validation_metrics": validations,
        "test_metrics": test_metrics,
        "baseline_metrics": baseline,
        "samples": {"total": len(y), "phishing": int(sum(y)), "candidate_legitimate": int(sum(1-y)), "train": len(tr), "validation": len(val), "test": len(test), "unique_domains": len(set(groups))},
        "data_notes": f"{source}; evaluar con corpus externo. Las etiquetas heredadas no verifican seguridad actual. Split agrupado aproximado; no implica validez en producción." + (" Tranco es una fuente de candidatos legítimos, no una verificación de seguridad." if "tranco" in source.casefold() else ""),
    }
    if audit is not None:
        result["dataset_audit"] = audit
    path = Path(model_path or OUTPUT_DIR / "cyberlens_ml.joblib")
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(result, path)
    report = {key: val for key, val in result.items()
              if key not in {"model", "feature_names", "dataset_group_fingerprints"}}
    report["external_evaluation_ready"] = True
    report["feature_names"] = list(FEATURE_NAMES)
    report["methodology"] = "División por grupos de dominio (aproximación), entrenamiento/validación/test sin superposición, selección sobre validación y una sola evaluación final en test. No se usaron URLs de test para entrenar."
    report_path = path.with_suffix(".metrics.json")
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report, path


def main(argv=None):
    parser = argparse.ArgumentParser(description="Entrena ML local CyberLens. NO visita URLs del dataset.")
    parser.add_argument("--phishing", type=Path, help="CSV con columna url, o TXT una URL por línea")
    parser.add_argument("--legitimate", type=Path, help="CSV con columna url, o TXT una URL por línea")
    parser.add_argument("--academic-feeds", action="store_true", help="Descargar OpenPhish Community + Tranco (solo investigación)")
    parser.add_argument("--accept-academic-terms", action="store_true", help="Confirmas revisar términos, no distribuir ni usar comercialmente")
    parser.add_argument("--max-per-class", type=int, default=800)
    args = parser.parse_args(argv)
    if not 25 <= args.max_per_class <= 10000:
        parser.error("--max-per-class debe estar entre 25 y 10000")
    if args.academic_feeds:
        if not args.accept_academic_terms:
            parser.error("Para datos OpenPhish debes usar --accept-academic-terms tras revisar sus condiciones")
        print("Descargando SOLO feeds de proveedores; NO se visitan las URLs listadas.")
        phishing, legitimate, source = academic_feeds(args.max_per_class)
    else:
        if not args.phishing or not args.legitimate:
            parser.error("Indica --phishing y --legitimate, o --academic-feeds --accept-academic-terms")
        phishing = read_urls(args.phishing, args.max_per_class)
        legitimate = read_urls(args.legitimate, args.max_per_class)
        source = "Archivos locales etiquetados por el investigador"
    items, conflicts = prepare(phishing, legitimate, args.max_per_class)
    audit = dataset_audit(
        items,
        phishing_input_count=len(phishing),
        legitimate_input_count=len(legitimate),
        conflicting_domain_groups=conflicts,
        source=source,
        feature_names=FEATURE_NAMES,
    )
    report, path = train_models(items, source=source, audit=audit)
    print("Modelos comparados:")
    for name, metrics in report["validation_metrics"].items():
        print(f"  {name}: precision={metrics['precision']:.3f} recall={metrics['recall']:.3f} F1={metrics['f1']:.3f} (validación)")
    print(f"Modelo elegido: {report['model_name']}")
    print(f"Prueba independiente: {report['test_metrics']}")
    print("Intervalos de Wilson 95 %: describen incertidumbre muestral aproximada; NO corrigen sesgo ni correlaciones por dominio.")
    print(f"Heurística en el mismo test: {report['baseline_metrics']}")
    print(f"Grupos conflictivos descartados: {conflicts}")
    print(f"Auditoría de datos: {audit['accepted_counts']}")
    for warning in audit["warnings"]:
        print(f"AVISO DE DATOS: {warning}")
    print(f"Informe: {path.with_suffix('.metrics.json')}")
    print("NOTA: estas métricas describen este dataset; no certifican detección general de phishing.")


if __name__ == "__main__":
    main()
