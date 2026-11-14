# CyberLens V0.2.1 — etapa 1: estabilización (10-11-2026)

## Objetivo
Corregir fallos detectados en el análisis del ZIP V0.2, aumentar privacidad del historial y ampliar la cobertura de pruebas **sin incorporar aún funciones remotas**.

## Implementado y comprobado

| Área | Cambio | Evidencia |
|---|---|---|
| Validación | IPv4 e IPv6 dejan de contarse como subdominios | Tests `test_ip_http_*` y `test_ipv6_*` |
| Riesgo | Uso de IP y credenciales ahora producen al menos nivel MEDIO; Punycode mantiene advertencia cautelosa | Tests de URL |
| Detector | Heurísticas de sustituciones de caracteres y menciones de marcas fuera de una lista limitada | Tests con `g00gle.com` y URL ficticia de PayPal |
| Privacidad | URL almacenada y devuelta sin credenciales, ruta, consulta ni fragmento | Test `test_only_session_hash_is_saved` |
| Sesión | Cookie aleatoria `HttpOnly` / `SameSite=Lax`, hash en BD y consulta filtrada | Test `test_empty_history_for_other_browser` |
| Derecho de borrado | `DELETE /api/history` y botón de interfaz | Test `test_delete_only_own_history` |
| Migración | Ajuste de BD anterior, anonimización y ocultamiento de historial heredado | Test `test_migrate_legacy_history...` |
| Validación API | Error 422 no refleja el valor enviado | Test `test_invalid_request_does_not_echo_secret` |
| Configuración | `.env` para DB/CORS/cookies/retención; puerto local para desarrollo | Revisión de archivos |
| Frontend | Actualizado Next.js 15.5.29 y React 19.1.10 (versiones corregidas de seguridad) | Paquetes publicados/verificados; build local pendiente |
| Tests | 25 casos en `unittest`, todos aprobados | `python -m unittest discover -s tests -v` |

## Decisiones técnicas importantes

- Una puntuación no equivale a una probabilidad. El detector es una línea base heurística que requiere validación con datos de phishing y legítimos.
- Análisis de URLs sigue siendo **léxico sin hacer solicitudes HTTP al destino**, evitando la exposición a SSRF por fetch remoto en esta etapa.
- El historial usa sesiones anónimas por navegador y no cuentas de usuario; su objetivo es una demo local y privada, no uso multiusuario empresarial.
- La migración conserva métricas históricas, pero anonimiza sus URLs y **no reasigna el historial anterior** a la nueva cookie.
- Se separó `scikit-learn` en `requirements-ml.txt` porque no forma parte de la V0.2.1: evita instalaciones innecesarias mientras se estabiliza el MVP.
- PostgreSQL/Docker siguen **planificados**. SQLite continúa como BD real del proyecto local.

## Estado de verificación

- Backend y tests: **ejecutados y aprobados** en entorno de desarrollo con Python 3.13, FastAPI, SQLAlchemy y TestClient disponibles.
- Frontend: **editado pero no compilado**; el entorno no permite conectar con el registro de npm. Se debe realizar `npm install`, `npm run build` y una inspección manual en Windows.
- Seguridad: solo se verificaron controles implementados y casos de prueba definidos; **no se realizó pentest ni validación de producción**.
- Precision/recall: **sin medir**, pendiente de dataset y etapa ML.

## Pendiente para V0.3

1. Construir dataset reproducible y separar entrenamiento/prueba.
2. Entrenar y comparar **al menos dos clasificadores** (por ejemplo Regresión Logística y Random Forest).
3. Medir matriz de confusión, precision, recall, F1-score, falsos positivos/negativos.
4. Integrar el clasificador más adecuado a través de FastAPI con una opción de fallback heurístico.
5. Ejecutar pruebas frontend y sistema completo con evidencia capturada en el entorno de presentación.
