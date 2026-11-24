# CyberLens: estado de las entregas

- **V0.2.1 — entregada**: backend, heurística, SQLite, privacidad por sesión y 25 pruebas; frontend compilado en Windows el 10-11-2026 según el registro del desarrollador.
- **V0.3 — entregada académicamente**: 25 características léxicas, entrenamiento supervisado (Regresión Logística vs Random Forest), separación aproximada por dominio, métricas precision/recall/F1 y matriz de confusión para validación y test, comparación heurística, inferencia opcional en API/Next.js y 35 pruebas. **No incluye un modelo entrenado y validado con datos reales**.
- **V0.4 — implementada en rama de desarrollo**: detecta URLs HTTP(S) anidadas en parámetros habituales de redirección y si su host difiere del host inicial; muestra dos indicadores **informativos de +0 puntos**, sin visitar destinos ni resolver DNS. Nueve pruebas nuevas; **44/44 pruebas de backend** aprobadas en Windows y verificación visual del caso ficticio de redirección. El frontend también compiló antes de las actualizaciones finales de versión; comprobarlo nuevamente antes de fusionar. **Pendiente**: revisión del Pull Request e integración a `main`.
- **V0.5 — en desarrollo**: rama de auditoría de datos y protocolo de evaluación creada; pendiente ejecutar pruebas y entrenamiento local bajo permisos revisados. Próximos objetivos: dataset con procedencia y condiciones de uso documentadas, entrenamiento reproducible sobre datos representativos, separación temporal/por dominio, evaluación externa, falsos positivos/negativos y calibración de cualquier nuevo peso de riesgo; análisis de vulnerabilidades npm.
- **Etapa posterior — AWS y entrega final**: despliegue seguro, HTTPS, protección de API, observabilidad, pruebas de carga, documentación de continuidad y defensa académica.

## Principios y límites

- Un indicador de redirección no prueba phishing; muchas redirecciones a dominios externos son legítimas.
- El motor **no sigue ni abre** las URLs proporcionadas y no garantiza detectar redirecciones efectivas del servidor.
- El puntaje heurístico **no es una probabilidad**. Un resultado BAJO no certifica seguridad.
- No se deben presentar métricas de datasets sintéticos como rendimiento real en Internet; el ML sigue siendo experimental.
