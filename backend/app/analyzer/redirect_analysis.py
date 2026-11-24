"""Detección léxica de destinos de redirección en parámetros.

Solo procesa texto en memoria. No resuelve DNS, no sigue enlaces y no realiza
peticiones de red. Nunca devuelve la URL anidada ni posibles tokens secretos.
"""

import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlsplit

REDIRECT_KEYS = frozenset({
    "url", "u", "link", "target", "dest", "destination", "next",
    "redirect", "redirect_url", "redirect_uri", "return", "returnto",
    "continue", "p1",
})

# La extracción es orientativa: no implica una redirección HTTP comprobada.
_EMBEDDED_HTTP = re.compile(r"""(?i)https?://[^\s<>"']+""")


@dataclass(frozen=True)
class RedirectSignals:
    named_parameter: bool = False
    embedded_url: bool = False
    external_host: bool = False


def inspect_redirect_parameters(url: str) -> RedirectSignals:
    """Detecta URLs HTTP(S) anidadas en parámetros habituales de redirección.

    parse_qsl ya decodifica una capa de codificación porcentual. Se permiten
    como máximo dos capas adicionales para evitar decodificación ilimitada.
    'external_host' significa host distinto del origen o sus subdominios,
    NO un dominio malicioso ni un redirect realmente ejecutado.
    """
    try:
        parsed = urlsplit(url)
        origin_host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return RedirectSignals()

    if parsed.scheme not in {"http", "https"} or not origin_host:
        return RedirectSignals()

    named = embedded = external = False
    for key, raw_value in parse_qsl(parsed.query, keep_blank_values=True):
        if key.lower() not in REDIRECT_KEYS:
            continue
        named = True
        value = raw_value
        for _ in range(3):
            match = _EMBEDDED_HTTP.search(value)
            if match:
                try:
                    nested = urlsplit(match.group(0))
                    nested_host = (nested.hostname or "").lower().rstrip(".")
                except ValueError:
                    nested_host = ""
                if nested_host and nested.scheme.lower() in {"http", "https"}:
                    embedded = True
                    if nested_host != origin_host and not nested_host.endswith("." + origin_host):
                        external = True
                    break
            decoded = unquote(value)
            if decoded == value:
                break
            value = decoded
        if embedded and external:
            break

    return RedirectSignals(named, embedded, external)
