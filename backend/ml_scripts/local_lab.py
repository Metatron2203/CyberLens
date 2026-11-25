"""CyberLens: laboratorio educativo local, sin red ni autenticación.

Genera HTML local con un catálogo fijo de casos de dominios .example.
Los nombres comerciales son referencias de contexto, no páginas oficiales.
No contiene formularios de envío, almacenamiento de credenciales ni clones.
Las etiquetas son escenarios inventados, NO evidencia de phishing real.
"""
import argparse
import html
import json
from pathlib import Path
from urllib.parse import urlsplit

from app.ml.features import feature_vector
from ml_scripts.external_eval import evaluate_cases

BACKEND = Path(__file__).resolve().parents[1]
OUTPUT = BACKEND / "data" / "cyberlens_lab.html"

# Un conjunto pequeño y fijo, independiente del entrenamiento.
# Cada par usa rutas similares: ni HTTPS ni login determinan por sí solos la clase.
CASES = (
    ("Red social de fotos (referencia: Instagram)", "https://foto-lab.example/accounts/login/", 0, "login"),
    ("Red social de fotos (referencia: Instagram)", "https://foto-aviso-lab.example/accounts/login/", 1, "login"),
    ("Plataforma de videos (referencia: TikTok)", "https://video-lab.example/profile?lang=es", 0, "query"),
    ("Plataforma de videos (referencia: TikTok)", "https://video-aviso-lab.example/profile?lang=es", 1, "query"),
    ("Servicio creativo (referencia: Adobe)", "https://diseno-lab.example/account/signin", 0, "login"),
    ("Servicio creativo (referencia: Adobe)", "https://diseno-aviso-lab.example/account/signin", 1, "login"),
    ("Correo electrónico", "https://correo-lab.example/mail/login", 0, "login"),
    ("Correo electrónico", "https://correo-aviso-lab.example/mail/login", 1, "login"),
    ("Redirección de demostración", "https://portal-lab.example/continue?next=%2Faccount", 0, "redirect"),
    ("Redirección de demostración", "https://portal-aviso-lab.example/continue?next=https%3A%2F%2Fdestino-lab.example%2Faccount", 1, "redirect"),
    ("Consulta con parámetros", "https://catalogo-lab.example/search?q=demo&page=2", 0, "query"),
    ("Consulta con parámetros", "https://catalogo-aviso-lab.example/search?q=demo&page=2", 1, "query"),
)


def validate_cases():
    """No permitir URLs de sitios reales en el catálogo de simulación."""
    seen = set()
    for context, url, label, category in CASES:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not (parsed.hostname or "").endswith(".example"):
            raise ValueError("El laboratorio solo admite dominios reservados .example")
        if parsed.username or parsed.password or url in seen or label not in (0, 1):
            raise ValueError("Caso inválido")
        feature_vector(url)
        seen.add(url)


def render_lab():
    validate_cases()
    options = "\n".join(
        f'<option value="{i}">{html.escape(context)} — caso {i + 1}</option>'
        for i, (context, _, _, _) in enumerate(CASES)
    )
    # Las cadenas provienen exclusivamente del catálogo interno.
    rows = json.dumps(CASES, ensure_ascii=True).replace("<", "\\u003c")
    return """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none'">
<title>CyberLens Lab - simulacion educativa</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#101827;color:#e5e7eb;font:16px system-ui,sans-serif}
main{max-width:760px;margin:40px auto;padding:24px}
section{background:#1e293b;border:1px solid #475569;padding:22px;border-radius:12px;margin:18px 0}
label{display:block;margin-top:16px}input,select,button{font:inherit;border-radius:6px;padding:12px;width:100%;margin-top:6px}
input,select{background:#0f172a;color:#f8fafc;border:1px solid #64748b}
button{background:#cbd5e1;color:#111827;border:0;cursor:pointer;font-weight:600}
small,p{line-height:1.55}h1,h2{margin-top:0}.warning{color:#fde68a}#result{min-height:3em}
</style>
</head>
<body>
<main>
<h1>CyberLens Lab</h1>
<p class="warning"><strong>SIMULACION EDUCATIVA — NO ES UN SITIO OFICIAL.</strong> Sin marcas visuales, sin autenticacion real y sin comunicaciones de red.</p>
<section>
<h2>1. Selecciona un escenario</h2>
<label for="scenario">Contexto del caso</label>
<select id="scenario">""" + options + """</select>
<label for="url">URL ficticia para analizar como texto</label>
<input id="url" type="text" readonly>
<button id="select-url" type="button">Seleccionar URL (Ctrl+C para copiar)</button>
<p>Selecciona y copia la URL a CyberLens. No la abras en el navegador.</p>
<button id="reveal" type="button">Revelar etiqueta del escenario</button>
<p id="expected" aria-live="polite"></p>
</section>
<section>
<h2>2. Ensayo de interaccion</h2>
<p>No existe inicio de sesion. Solo hay una accion visual de practica. Usa exclusivamente valores de demostracion.</p>
<p>Usuario de prueba: <strong>Juanito_777</strong><br>Codigo de practica: <strong>DEMO_123</strong></p>
<label for="demo-user">Usuario ficticio</label>
<input id="demo-user" type="text" autocomplete="off" maxlength="32" placeholder="Juanito_777">
<label for="demo-code">Codigo ficticio (no escribas una clave real)</label>
<input id="demo-code" type="text" autocomplete="off" maxlength="32" placeholder="DEMO_123">
<button id="simulate" type="button">Simular interaccion local</button>
<p id="result" aria-live="polite"></p>
<p>Los campos se limpian inmediatamente. No se transmiten, guardan ni muestran los valores introducidos.</p>
</section>
<section>
<h2>3. Interpretacion</h2>
<p>El motor actual analiza la estructura de la URL, no la pantalla ni los campos escritos. Dos URLs similares pueden pertenecer a clases diferentes segun el contexto. Los casos son ficticios y sus etiquetas no acreditan eficacia real.</p>
</section>
</main>
<script>
"use strict";
const cases = """ + rows + """;
const scenario = document.getElementById("scenario");
const urlField = document.getElementById("url");
const expected = document.getElementById("expected");
const userField = document.getElementById("demo-user");
const codeField = document.getElementById("demo-code");
const result = document.getElementById("result");
function reset() {
  urlField.value = cases[Number(scenario.value)][1];
  expected.textContent = "";
  userField.value = "";
  codeField.value = "";
  result.textContent = "";
}
scenario.addEventListener("change", reset);
document.getElementById("select-url").addEventListener("click", () => {
  urlField.focus();
  urlField.select();
});
document.getElementById("reveal").addEventListener("click", () => {
  expected.textContent = cases[Number(scenario.value)][2] === 1
    ? "Etiqueta del guion: phishing simulado."
    : "Etiqueta del guion: legitima simulada.";
});
document.getElementById("simulate").addEventListener("click", () => {
  const ok = userField.value === "Juanito_777" && codeField.value === "DEMO_123";
  userField.value = "";
  codeField.value = "";
  result.textContent = ok
    ? "Ensayo local completado. No se envio ni guardo ningun dato."
    : "Usa los valores ficticios indicados. Los campos fueron limpiados.";
});
window.addEventListener("pagehide", reset);
reset();
</script>
</body>
</html>
"""


def main(argv=None):
    parser = argparse.ArgumentParser(description="Genera CyberLens Lab offline")
    parser.add_argument("--evaluate", action="store_true", help="Evalúa los casos ficticios con el modelo local")
    args = parser.parse_args(argv)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(render_lab(), encoding="utf-8")
    print("Laboratorio local:", OUTPUT)
    print("Casos ficticios:", len(CASES))
    print("Sin navegación, autenticación, captura de datos ni servicios de red.")
    if args.evaluate:
        # Solo modelo propio generado localmente; joblib puede ejecutar código.
        import joblib
        model_path = BACKEND / "models" / "cyberlens_ml.joblib"
        bundle = joblib.load(model_path)
        cases = [(url, label, category) for _, url, label, category in CASES]
        report = evaluate_cases(cases, bundle, source="CyberLens Lab ficticio", strict=False)
        report_path = BACKEND / "models" / "local_lab.metrics.json"
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False, indent=2))
        print("Informe diagnóstico:", report_path)
        print("No representa eficacia real; no usar estos casos para ajustar el modelo.")


if __name__ == "__main__":
    main()
