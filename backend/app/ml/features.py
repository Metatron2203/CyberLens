"""Extracción determinista de características léxicas sin conexiones de red.

Solo se leen cadenas en memoria: NUNCA se consulta un host ni se abre una URL.
El conjunto de características tiene versión explícita para compatibilidad de modelos.
"""

import ipaddress
import re
from urllib.parse import parse_qsl, unquote, urlsplit

from app.analyzer.url_analyzer import KNOWN_BRANDS, SUSPICIOUS_TERMS

FEATURE_SCHEMA = "lexical-v1"
FEATURE_NAMES = (
    "url_length", "host_length", "host_dot_count", "host_hyphen_count",
    "host_digit_count", "host_has_ip", "uses_http", "uses_punycode",
    "subdomain_count", "nonstandard_port", "credentials_at",
    "path_length", "path_depth", "query_length", "query_parameter_count",
    "percent_encoded_count", "sensitive_host_terms", "sensitive_path_terms",
    "brand_outside_official", "looks_like_brand_typo", "url_has_at",
    "redirect_named_parameter", "embedded_url_candidate", "external_embedded_host",
    "shortener_host",
)
REDIRECT_KEYS = {"url", "u", "link", "target", "dest", "destination", "next", "redirect", "redirect_url", "redirect_uri", "return", "returnto", "continue", "p1"}
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "cutt.ly", "is.gd", "ow.ly", "rebrand.ly"}
LEET_TRANSLATION = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t"})


def _ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _brand_signals(host: str) -> tuple[int, int]:
    labels = re.split(r"[.\-]", host)
    mention, typo = 0, 0
    for brand, official in KNOWN_BRANDS.items():
        if any(host == d or host.endswith("." + d) for d in official):
            continue
        if any(brand in label for label in labels):
            mention = 1
        if any(label != brand and label.translate(LEET_TRANSLATION) == brand for label in labels):
            typo = 1
    return mention, typo


def extract_features(url: str) -> dict[str, float]:
    """Devuelve únicamente números; no retiene ni expone la URL original."""
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError("URL demasiado larga o inválida")
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Puerto o dominio inválido") from exc
    if parsed.scheme not in {"http", "https"} or not host or any(c.isspace() for c in url):
        raise ValueError("Se necesita una URL HTTP/HTTPS válida")
    is_ip = _ip(host)
    labels = host.split(".") if not is_ip else []
    host_terms = sum(term in host for term in SUSPICIOUS_TERMS)
    other = (unquote(parsed.path) + "?" + unquote(parsed.query)).lower()
    path_terms = sum(term in other for term in SUSPICIOUS_TERMS)
    brand, typo = _brand_signals(host) if not is_ip else (0, 0)

    pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=256) if parsed.query else []
    redirect_named = any(key.lower() in REDIRECT_KEYS for key, _ in pairs)
    candidate = False
    external = False
    for key, raw in pairs[:64]:
        if key.lower() not in REDIRECT_KEYS:
            continue
        value = raw
        for _ in range(2):
            value = unquote(value)
        # Consulta únicamente cadenas locales; NO sigue redirecciones.
        found = re.search(r"(?i)https?://([^/\s?#]+)", value)
        if found:
            candidate = True
            target_host = found.group(1).split("@")[-1].split(":")[0].lower()
            if target_host != host and not target_host.endswith("." + host):
                external = True
    return dict(zip(FEATURE_NAMES, map(float, (
        len(url), len(host), host.count("."), host.count("-"),
        sum(c.isdigit() for c in host), is_ip, parsed.scheme == "http",
        "xn--" in host, max(len(labels) - 2, 0),
        port is not None and port not in {80, 443},
        parsed.username is not None or parsed.password is not None,
        len(parsed.path), len([p for p in parsed.path.split("/") if p]),
        len(parsed.query), len(pairs), len(re.findall(r"%[0-9a-fA-F]{2}", url)),
        host_terms, path_terms, brand, typo, "@" in url,
        redirect_named, candidate, external, host in SHORTENERS,
    ))))


def feature_vector(url: str) -> list[float]:
    features = extract_features(url)
    return [features[name] for name in FEATURE_NAMES]


def group_key(url: str) -> str:
    """Agrupación aproximada por dominio registrable, sin resolver DNS.

    No es una implementación completa de Public Suffix List: para un estudio
    definitivo conviene sustituirla por PSL versionada y documentada.
    """
    from hashlib import sha256
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    if _ip(host):
        candidate = host
    else:
        bits = host.split(".")
        multipart = {"co.uk", "org.uk", "ac.uk", "com.au", "com.br", "com.mx", "com.ar", "com.co", "com.pe", "co.jp", "co.nz", "com.tr", "com.cn", "co.kr"}
        suffix = ".".join(bits[-2:])
        count = 3 if suffix in multipart else 2
        candidate = ".".join(bits[-count:])
    return sha256(candidate.encode("utf-8")).hexdigest()
