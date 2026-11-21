"""Análisis estructural de URLs. No realiza conexiones con los destinos.

Las señales son heurísticas: NO equivalen a una prueba de que exista phishing.
"""

import ipaddress
import re
from urllib.parse import parse_qsl, unquote, urlparse

from app.analyzer.redirect_analysis import inspect_redirect_parameters

SUSPICIOUS_TERMS = {
    "login", "verify", "verification", "secure", "account", "update",
    "password", "signin", "confirm", "wallet", "recover", "unlock",
    "billing", "invoice", "payment",
}

SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly",
}

# Conjunto pequeño y explícito para un MVP educativo. No es una lista exhaustiva
# de dominios oficiales ni un motor fiable de brand impersonation.
KNOWN_BRANDS = {
    "google": ("google.com", "google.cl", "googleusercontent.com", "gstatic.com"),
    "paypal": ("paypal.com", "paypalobjects.com"),
    "microsoft": ("microsoft.com", "microsoftonline.com", "live.com"),
    "amazon": ("amazon.com", "amazon.cl"),
    "apple": ("apple.com", "icloud.com"),
    "netflix": ("netflix.com",),
    "facebook": ("facebook.com", "fb.com"),
    "bancoestado": ("bancoestado.cl",),
    "mercadopago": ("mercadopago.cl", "mercadopago.com"),
}

# Solo para detectar sustituciones evidentes, nunca para decidir si un dominio
# pertenece legalmente a una marca. Es susceptible a falsos positivos.
LEET_REPLACEMENTS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t"})


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _is_official_host(hostname: str, official_domains: tuple[str, ...]) -> bool:
    return any(hostname == name or hostname.endswith("." + name) for name in official_domains)


def safe_url_for_storage(url: str) -> str:
    """Devuelve solo esquema/host/puerto y marca de contenido omitido.

    Nunca persiste usuario, contraseña, rutas, consultas o fragmentos. Una ruta
    puede contener tokens, por lo que no basta con ocultar solo ?token=... .
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname or parsed.scheme not in {"http", "https"}:
            return "[URL omitida]"
        if re.search(r"[^a-zA-Z0-9.:-]", hostname):
            return "[URL omitida]"
        safe_host = f"[{hostname}]" if ":" in hostname else hostname
        port = parsed.port
        authority = safe_host + (f":{port}" if port is not None else "")
        # Solo el origen: no revelar partes de ruta/query/fragmento.
        return f"{parsed.scheme}://{authority}/" + (
            "[contenido omitido]" if (parsed.path not in {"", "/"} or parsed.query or parsed.fragment) else ""
        )
    except (ValueError, TypeError):
        return "[URL omitida]"


def analyze_url(url: str) -> dict:
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError as exc:
        raise ValueError("La URL tiene un formato o puerto inválido.") from exc

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Solo se permiten URLs HTTP o HTTPS.")
    if not hostname:
        raise ValueError("La URL no contiene un dominio válido.")

    redirect_signals = inspect_redirect_parameters(url)

    indicators: list[dict] = []
    score = 0

    def add(name: str, description: str, points: int, severity: str) -> None:
        nonlocal score
        indicators.append({
            "name": name,
            "description": description,
            "points": points,
            "severity": severity,
        })
        score += points

    if parsed.scheme == "http":
        add("Conexión HTTP", "La URL no utiliza HTTPS, por lo que el tráfico no tiene cifrado de transporte.", 12, "medium")

    is_ip = _is_ip(hostname)
    if is_ip:
        add("Uso de dirección IP", "El destino utiliza una dirección IP en lugar de un nombre de dominio.", 26, "high")

    if parsed.username is not None or parsed.password is not None:
        add("Credenciales en la URL", "La URL incluye contenido antes del símbolo @, que puede ocultar el destino real.", 27, "high")

    if hostname.startswith("xn--") or ".xn--" in hostname:
        add("Dominio internacionalizado (Punycode)", "El dominio usa Punycode, que puede ser legítimo o emplearse para suplantación visual.", 18, "medium")

    # Una IPv4 contiene puntos, pero no subdominios. IPv6 tampoco debe contarse.
    host_parts = [part for part in hostname.split(".") if part] if not is_ip else []
    if len(host_parts) >= 5:
        add("Exceso de subdominios", "El dominio contiene muchos niveles y dificulta identificar el dominio principal.", 12, "medium")
    elif len(host_parts) == 4:
        add("Múltiples subdominios", "El dominio contiene varios niveles; revisa cuidadosamente el dominio principal.", 7, "low")

    if hostname.count("-") >= 3:
        add("Muchos guiones en el dominio", "El nombre del servidor contiene varios guiones.", 8, "low")

    if hostname in SHORTENER_HOSTS:
        add("Acortador de URL", "La URL usa un acortador y no muestra el destino final.", 12, "medium")

    if port is not None and port not in {80, 443}:
        add("Puerto no estándar", f"La URL utiliza el puerto {port}, distinto de los habituales 80/443.", 8, "low")

    if len(url) > 180:
        add("URL muy extensa", "La URL supera los 180 caracteres.", 14, "medium")
    elif len(url) > 100:
        add("URL extensa", "La URL supera los 100 caracteres.", 7, "low")

    if len([part for part in parsed.path.split("/") if part]) >= 6:
        add("Ruta profunda", "La URL contiene muchas secciones de ruta.", 6, "low")

    if len(parse_qsl(parsed.query, keep_blank_values=True)) >= 8:
        add("Muchos parámetros", "La URL contiene una cantidad elevada de parámetros.", 6, "low")

    if len(re.findall(r"%[0-9a-fA-F]{2}", url)) >= 5:
        add("Contenido codificado", "La URL contiene varias secuencias porcentualmente codificadas.", 8, "medium")

    found_host = sorted(term for term in SUSPICIOUS_TERMS if term in hostname)
    found_other = sorted(
        term for term in SUSPICIOUS_TERMS
        if term in (unquote(parsed.path) + "?" + unquote(parsed.query)).lower() and term not in found_host
    )
    if found_host:
        add("Términos sensibles en el dominio", "El dominio contiene términos asociados a acceso, pagos o verificación: " + ", ".join(found_host), 14, "medium")
    elif found_other:
        add("Términos sensibles en la URL", "La ruta o consulta contienen términos asociados a acceso, pagos o verificación: " + ", ".join(found_other), 7, "low")

    # Advertencias informativas: sin pesos calibrados con datos reales.
    # Mostrar estas señales NO implica haber seguido una redirección.
    if redirect_signals.embedded_url:
        add("URL anidada en parámetro", "Un parámetro habitual de redirección contiene otra URL HTTP/HTTPS. No se ha visitado el destino.", 0, "low")
    if redirect_signals.external_host:
        add("Destino en otro host", "La URL anidada apunta fuera del host inicial y sus subdominios. Esto también puede ocurrir en sitios legítimos.", 0, "medium")

    # Regla de alerta adicional; las marcas se usan como patrones ilustrativos.
    # Se excluyen dominios reconocidos de cada marca y sus subdominios.
    if not is_ip:
        for brand, official_domains in KNOWN_BRANDS.items():
            if _is_official_host(hostname, official_domains):
                continue
            labels = re.split(r"[.-]", hostname)
            possible_typo = any(label.translate(LEET_REPLACEMENTS) == brand and label != brand for label in labels)
            brand_mention = any(brand in label for label in labels)
            if possible_typo:
                add("Posible imitación visual de marca", f"Un segmento del dominio se parece a '{brand}' mediante sustituciones de caracteres; no demuestra fraude.", 30, "high")
            elif brand_mention:
                add("Marca conocida fuera de sus dominios habituales", f"El dominio menciona '{brand}' pero no coincide con la lista limitada de dominios habituales; puede ser legítimo.", 20, "medium")
            if possible_typo or brand_mention:
                break

    if re.search(r"[^a-z0-9.:-]", hostname):
        add("Caracteres inusuales en el dominio", "El nombre del servidor contiene caracteres fuera del conjunto habitual.", 12, "medium")

    score = min(score, 100)
    if score <= 24:
        level = "low"
        message = "Se detectaron pocos indicadores estructurales. Esto NO garantiza que el sitio sea seguro."
    elif score <= 54:
        level = "medium"
        message = "Se detectaron indicadores de precaución; verifica el dominio por otra vía antes de introducir datos."
    else:
        level = "high"
        message = "Se detectó una combinación relevante de señales; evita introducir datos hasta verificar el destino."

    if redirect_signals.external_host:
        message += " Se observó una posible redirección hacia otro host sin visitar el destino; verifica el enlace antes de continuar."

    return {
        "url": safe_url_for_storage(url),
        "risk_score": score,
        "risk_level": level,
        "indicators": indicators,
        "message": message,
    }
