# Informe de avance V0.3 — Machine Learning experimental

## Estado técnico
La V0.3 implementa extracción de 25 características léxicas, entrenamiento local de dos clasificadores, particiones por dominio, selección usando validación y evaluación final sobre holdout; comparación con la línea base heurística. La inferencia de un modelo local se expone por `/api/analyze` con campo `ml` y `/api/ml/status`. Las salidas ML se registran de forma opcional en SQLite; no se persisten URLs completas.

## Evidencias de calidad disponibles
- La suite automatizada consta de 35 pruebas y pasó en el entorno de desarrollo de esta entrega; las pruebas de ML usan ejemplos artificiales exclusivamente para comprobar el código y el guardado/carga de modelos.
- Se conservaron las 25 pruebas de V0.2.1 (tras actualizar el número de versión) y se añadieron 10 más.
- El usuario ya verificó en Windows que V0.2.1 compila con Next.js 15.5.29. El build V0.3 debe confirmarse en el mismo equipo (el registro de npm no respondió a la instalación en el entorno de construcción del ZIP).

## Limitaciones que NO deben presentarse como logros alcanzados
- No hay dataset académico de URLs verificadas ni métricas reales incluidas en el ZIP.
- La calidad de fuentes y representatividad requieren evaluación externa y revisión de términos de uso.
- Split por dominio es aproximado (sin Public Suffix List completa).
- Probabilidad del modelo NO calibrada; la clase «legítimo» de Tranco es solo un proxy.
- No hay seguimiento de redirecciones, DNS/TLS, inspección remota ni uso productivo.

## Cómo generar evidencia académica real
Ejecutar `train_ml_windows.ps1` con CSV etiquetados verificables o, previa lectura de licencias, feeds académicos; conservar archivo `.metrics.json` en repositorio de evidencia PRIVADO, sin copiar URLs peligrosas al informe. Documentar número de muestras, fecha, clases, grupos y origen; comparar matrices de confusión con la línea base de CyberLens. Repetir evaluación con conjunto externo temporal independiente en V0.4.
