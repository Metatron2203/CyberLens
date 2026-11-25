"""Casos sintéticos de investigación. No son sitios ni phishing verificado.

Los hosts son reservados .test y las etiquetas son hipótesis de un guion.
No crea páginas, registra dominios, usa marcas reales ni realiza conexiones.
"""
import random
from urllib.parse import quote

from app.ml.features import feature_vector, group_key


def generate_synthetic(per_class=160, seed=2026):
    if not 20 <= per_class <= 1000:
        raise ValueError("per_class debe estar entre 20 y 1000")
    rng = random.Random(seed)
    rows = []
    # Ambas clases comparten HTTPS, rutas, longitud y contextos similares.
    # Algunas señales aparecen en ambas clases: son indicios, no certezas.
    paths = ("/", "/account/login", "/catalog/search", "/profile", "/mail/inbox")
    for i in range(per_class):
        path = paths[i % len(paths)]
        for label in (0, 1):
            host = f"demo-{rng.getrandbits(48):012x}.test"
            variant = i % 8
            port = ":8443" if variant in ({1, 4} if label else {1}) else ""
            query = ""
            if variant in (2, 5):
                query = "?lang=es&page=2"
            elif variant in (3, 6):
                # Destino ficticio; no se sigue ni se visita.
                target = (f"https://otro-{rng.getrandbits(48):012x}.test/home"
                          if label and variant == 6 else "/home")
                query = "?next=" + quote(target, safe="")
            raw = f"https://{host}{port}{path}{query}"
            rows.append((feature_vector(raw), label, group_key(raw), raw))
    rng.shuffle(rows)
    return rows
