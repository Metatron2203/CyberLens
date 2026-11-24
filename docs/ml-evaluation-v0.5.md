# CyberLens V0.5 — protocolo de evaluación ML

**Estado:** fase de preparación y auditoría de datos, no resultados validados.

## Objetivo

Comparar Regresión Logística, Random Forest y la heurística de CyberLens
con un experimento reproducible. Evaluar por clase (precision, recall, F1, TN/FP/FN/TP)
y documentar procedencia, fechas, sesgos y límites. El porcentaje de predicción
del modelo **no es una garantía ni una probabilidad calibrada de phishing**.

## Fuentes y permisos

- **OpenPhish Academic Use:** https://www.openphish.com/academic_use.html
- **Condiciones OpenPhish:** https://www.openphish.com/terms.html
- **OpenPhish Community Feed:** https://openphish.com/phishing_feeds.html
- **Tranco:** https://tranco-list.eu/
- **PhishTank (alternativa):** https://phishtank.org/developer_info.php

**No descargar ni redistribuir datos antes de revisar los permisos.**
El uso de OpenPhish está sujeto a términos de investigación no comercial y
restricciones de distribución. No publicar URLs de phishing, tokens ni modelos
derivados de datos con licencias restrictivas sin verificar autorización.

**Nota sobre etiquetas:** que un dominio esté en Tranco solo refleja
popularidad relativa; NO verifica que el sitio o cada URL sea seguro.
La comparación «phishing de feed» vs «portadas de Tranco» puede separar
las clases por procedencia y estructura, en vez de aprender phishing.

## Procedimiento Windows

1. Actualizar desde GitHub la rama feature/ml-dataset-audit-v0.5.
2. Activar el entorno Python local ya instalado en backend.
3. Ejecutar las pruebas:
   
   PowerShell:
   
       cd backend
       .\.venv\Scripts\python.exe -m unittest discover -s tests -v
       cd ..

4. Recomendado: preparar archivos locales bajo backend/data/ (carpeta
   ignorada en Git) con un CSV por clase, encabezado exacto url.
   Documentar en privado origen, fecha de obtención, definición de
   etiqueta, tamaño, errores observados y condiciones de uso.
5. Si se verificaron y aceptaron personalmente los términos pertinentes,
   se puede usar el ejemplo académico optativo para obtener feeds:
   
       Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
       .\scripts\train_ml_windows.ps1 -AcademicFeeds -AcceptAcademicTerms

   **No usar -AcceptAcademicTerms sin revisar antes esas condiciones.**
   El script descarga solo feeds y no visita los enlaces que contienen.
   Si el proveedor no responde, utilizar CSV locales; no evadir límites.

   Alternativa con archivos locales:

       .\scripts\train_ml_windows.ps1 -PhishingCsv "C:\datos\phishing.csv" -LegitimateCsv "C:\datos\legitimas.csv"

6. Revisar backend/models/cyberlens_ml.metrics.json. El informe incluye:
   - dataset_audit: recuentos aceptados/excluidos, grupos y advertencias
   - validation_metrics: comparación de modelos
   - test_metrics: evaluación final del modelo seleccionado
   - baseline_metrics: línea base heurística sobre el mismo test
   - samples y data_notes: tamaño y límites de procedencia

   El archivo .joblib es un objeto ejecutable deserializado por Python.
   Cargar exclusivamente archivos generados por el propio proyecto.

## Lectura de los resultados

- **TP:** phishing etiquetado y detectado.
- **FN:** phishing etiquetado que el modelo deja pasar; especialmente
  importante porque puede dar falsa confianza.
- **FP:** candidato legítimo marcado como phishing.
- **TN:** candidato legítimo no marcado como phishing.
- **Precision:** de lo marcado como phishing, cuántos casos eran de esa clase.
- **Recall:** de los phishing etiquetados, cuántos detectó.
- **F1:** media armónica entre precision y recall.

No comparar cifras de datasets distintos como si fueran la misma prueba.
La distribución 50/50 tampoco representa la proporción real de phishing
en navegación. Una prueba sin fuga de dominios sigue sin demostrar
generalización temporal ni desempeño en Internet abierto.

## Requisitos antes de cerrar V0.5

- [ ] Procedencia, permisos, corte temporal y tipo de etiquetas documentados.
- [ ] Pruebas automatizadas y compilación aprobadas después de los cambios.
- [ ] Modelo entrenado sobre datos permitidos y guardado solo localmente.
- [ ] Auditar calidad, balance y grupos de dominios.
- [ ] Reportar conteos de FP/FN, precision, recall y F1 por conjunto.
- [ ] Realizar una prueba externa/temporal separada, si los datos lo permiten.
- [ ] Indicar explícitamente la falta de calibración y sesgos conocidos.
- [ ] No publicar ni desplegar un modelo hasta revisar permisos y seguridad.

## Fase 2 — incertidumbre y sesgo de fuente

El primer entrenamiento local (con un máximo solicitado de 300 URL por clase)
informó 390 muestras aceptadas (96 phishing, 294 candidatas legítimas). El test
contó 49 TN, 0 FP, 2 FN y 15 TP. **Estos resultados son solo del dataset**
OpenPhish Community + Tranco en esa ejecución; no se publican las URLs.

Antes de descargar feeds nuevos, inspecciona el reporte existente desde backend:

    .\.venv\Scripts\python.exe -m ml_scripts.inspect_report

Este comando **no descarga, no entrena y no modifica modelos**. Calcula
intervalos aproximados Wilson 95 % de recall y tasa de falsos positivos a
partir de la matriz de confusión. Un 0/49 de falsos positivos no garantiza una
tasa real de 0 %. El supuesto de observaciones independientes puede fallar
para campañas y dominios relacionados; el intervalo no corrige sesgos de
origen, fechas ni errores de etiquetado.

Los próximos entrenamientos incluyen en el informe JSON:
- test_metrics.support: tamaño del test por clase y predicciones positivas
- test_metrics.error_rates: tasa de falsos negativos, falsos positivos y exactitud balanceada
- test_metrics.confidence_intervals_95_wilson: intervalos aproximados
- dataset_audit.feature_profile_by_class: medias por clase de rasgos léxicos
  como HTTP, longitud, profundidad de rutas y parámetros de redirección

Un contraste marcado entre clases puede revelar **sesgo de procedencia**:
por ejemplo, casi todos los phishing en HTTP frente a portadas Tranco en HTTPS.
No demuestra la capacidad de identificar ataques nuevos.

La evaluación externa y/o temporal sigue pendiente. Se necesita un conjunto
independiente, con fechas/procedencia y permisos documentados, no reutilizado
para entrenar ni ajustar umbrales. No escoger el umbral usando el test final.
