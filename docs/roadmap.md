# CyberLens: estado de las entregas

- **V0.2.1**: backend, heurística, SQLite, privacidad por sesión y 25 pruebas; el frontend fue compilado correctamente en Windows el 10-11-2026 según el registro del desarrollador.
- **V0.3 — implementada en código**: 25 características léxicas, entrenamiento supervisado (Regresión Logística vs Random Forest), separación aproximada por dominio, métricas precision/recall/F1/matriz de confusión en validación y test, baseline heurística, integración opcional a API/Next.js, 35 pruebas. **Sin modelo entrenado real incluido**: requiere feeds/datasets autorizados y evaluación externa antes de declarar desempeño.
- **V0.4 — pendiente**: ajuste de umbrales, validación externa y temporal, reglas de redirección más completas, rendimiento/carga, seguridad, usabilidad, pruebas sobre datasets representativos y análisis de vulnerabilidades npm.
- **V1.0 — pendiente**: autenticación robusta (o mantener demo local), despliegue seguro, auditoría, documentación final, entrega y defensa.

Nunca afirmar que la probabilidad del modelo certifica que una URL es segura. El proceso no visita URLs aportadas por el usuario ni por el dataset.
