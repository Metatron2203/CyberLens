"""Auditoría agregada de datasets para experimentos ML de CyberLens.

No contiene URLs originales ni evalúa sitios de red. Las cifras describen
los archivos utilizados; NO miden exactitud de phishing en Internet.
"""

from collections import Counter


def feature_bias_profile(items: list[tuple], feature_names) -> dict:
    """Resume características seleccionadas por clase, sin URLs individuales.

    Una diferencia marcada puede ser sesgo de procedencia, NO prueba de phishing.
    """
    indices = {str(name): i for i, name in enumerate(feature_names)}
    selected = (
        "uses_http", "url_length", "path_depth",
        "query_parameter_count", "sensitive_path_terms",
        "redirect_named_parameter", "external_embedded_host",
    )
    result = {}
    for name in selected:
        if name not in indices:
            continue
        idx = indices[name]
        positive = [float(item[0][idx]) for item in items if int(item[1]) == 1]
        negative = [float(item[0][idx]) for item in items if int(item[1]) == 0]
        if not positive or not negative:
            continue
        result[name] = {
            "phishing_mean": round(sum(positive) / len(positive), 4),
            "candidate_legitimate_mean": round(sum(negative) / len(negative), 4),
        }
    return result


def dataset_audit(
    items: list[tuple],
    *,
    phishing_input_count: int,
    legitimate_input_count: int,
    conflicting_domain_groups: int,
    source: str,
    feature_names=None,
) -> dict:
    """Resume cantidad, balance y posibles sesgos, sin divulgar muestras.

    items contiene (features, label, hashed_domain_group, raw_url);
    solamente se consultan label y grupo. La URL se ignora por privacidad.
    """
    if phishing_input_count < 0 or legitimate_input_count < 0 or conflicting_domain_groups < 0:
        raise ValueError("Los recuentos no pueden ser negativos")

    labels = Counter(int(item[1]) for item in items)
    if set(labels) - {0, 1}:
        raise ValueError("Etiquetas inválidas: solo 0 (candidata legítima) y 1 (phishing)")
    positive = labels[1]
    negative = labels[0]
    if positive > phishing_input_count or negative > legitimate_input_count:
        raise ValueError("Las muestras aceptadas no pueden superar las de entrada")

    groups_phishing = {item[2] for item in items if int(item[1]) == 1}
    groups_legitimate = {item[2] for item in items if int(item[1]) == 0}
    if groups_phishing & groups_legitimate:
        raise ValueError("Un grupo de dominio aparece en ambas clases")

    warnings: list[str] = []
    if min(positive, negative) < 100:
        warnings.append(
            "Muestras insuficientes para conclusiones sólidas; ampliar datos de ambas clases."
        )
    if min(positive, negative) and max(positive, negative) / min(positive, negative) > 2:
        warnings.append(
            "Las clases están desbalanceadas; usar métricas por clase y revisar el muestreo."
        )
    if min(len(groups_phishing), len(groups_legitimate)) < 30:
        warnings.append(
            "Hay pocos grupos de dominio; las estimaciones pueden ser inestables."
        )
    if "tranco" in source.casefold():
        warnings.append(
            "Tranco contiene dominios populares, NO etiquetas verificadas de sitios seguros."
        )
        warnings.append(
            "Comparar portadas Tranco con URLs de feeds de phishing introduce sesgo de procedencia."
        )
    if conflicting_domain_groups:
        warnings.append(
            "Se descartaron grupos con etiquetas contradictorias; revisar calidad de etiquetado."
        )

    profile = feature_bias_profile(items, feature_names) if feature_names is not None else {}
    http_stats = profile.get("uses_http")
    if http_stats and abs(
        http_stats["phishing_mean"] - http_stats["candidate_legitimate_mean"]
    ) >= 0.5:
        warnings.append(
            "El uso de HTTP difiere mucho entre las clases; posible sesgo de origen del dataset."
        )
    depth_stats = profile.get("path_depth")
    if depth_stats and abs(
        depth_stats["phishing_mean"] - depth_stats["candidate_legitimate_mean"]
    ) >= 2:
        warnings.append(
            "La profundidad de ruta difiere mucho entre las clases; comparar con URLs legítimas más variadas."
        )

    return {
        "source_description": source,
        "input_counts": {
            "phishing": phishing_input_count,
            "candidate_legitimate": legitimate_input_count,
        },
        "accepted_counts": {
            "phishing": positive,
            "candidate_legitimate": negative,
            "total": positive + negative,
        },
        "excluded_counts": {
            "phishing": phishing_input_count - positive,
            "candidate_legitimate": legitimate_input_count - negative,
        },
        "unique_domain_groups": {
            "phishing": len(groups_phishing),
            "candidate_legitimate": len(groups_legitimate),
        },
        "conflicting_domain_groups": conflicting_domain_groups,
        "feature_profile_by_class": profile,
        "warnings": warnings,
        "limitations": (
            "Auditoría de estructura y procedencia, no validación de etiquetas. "
            "La división por dominio no implica prueba temporal ni despliegue seguro."
        ),
    }
