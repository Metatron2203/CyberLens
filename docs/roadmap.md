# CyberLens: estado de las entregas

- **V0.2.1 — entregada**: backend, heurística, SQLite, privacidad por sesión y 25 pruebas; frontend compilado en Windows el 10-11-2026 según el registro del desarrollador.
- **V0.3 — entregada académicamente**: 25 características léxicas, entrenamiento supervisado (Regresión Logística vs Random Forest), separación aproximada por dominio, métricas precision/recall/F1 y matriz de confusión para validación y test, comparación heurística, inferencia opcional en API/Next.js y 35 pruebas. **No incluye un modelo entrenado y validado con datos reales**.
- **V0.4 — integrada en main**: inspección textual de URLs anidadas y destinos externos con indicadores informativos de +0 puntos. 44 pruebas de backend confirmadas. Sin navegación ni DNS.
- **V0.5 — investigación ML completada; integración pendiente**: auditoría, comparación de datasets, laboratorio sintético, entrenamiento híbrido, umbral de desarrollo y consenso experimental. 104/104 pruebas de backend confirmadas en Windows; comparación externa histórica Phish360 de 2000 grupos completada. Ningún modelo cumple las metas simultáneas: no promover ML ni consenso como detectores validados. Ver [resultados y limitaciones](ml-evaluation-v0.5.md). Instalación limpia, build frontend y npm audit (0 hallazgos) confirmados en Windows tras corregir PostCSS. Pendientes: verificación de versión 0.5.0 y fusión del PR #2. Main permanece en V0.4 hasta integración.
- **Etapa posterior — AWS y entrega final**: despliegue seguro, HTTPS, protección de API, observabilidad, pruebas de carga, documentación de continuidad y defensa académica.

## Principios y límites

- Un indicador de redirección no prueba phishing; muchas redirecciones a dominios externos son legítimas.
- El motor **no sigue ni abre** las URLs proporcionadas y no garantiza detectar redirecciones efectivas del servidor.
- El puntaje heurístico **no es una probabilidad**. Un resultado BAJO no certifica seguridad.
- No se deben presentar métricas de datasets sintéticos como rendimiento real en Internet; el ML sigue siendo experimental.
