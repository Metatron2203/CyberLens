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


## Fase 3 — evaluación externa y URLs complejas

**Estado:** implementada la herramienta; falta un corpus externo real y etiquetado.
Se añade `backend/ml_scripts/external_eval.py`, ejecutable desde `backend`.

### A. Diagnóstico de ingeniería con URLs ficticias (sin descargar datos)

    .\.venv\Scripts\python.exe -m ml_scripts.external_eval --demo-synthetic

Utiliza 18 ejemplos con dominios reservados `.example`: páginas ficticias de
inicio de sesión, parámetros, redirecciones, y supuestos ataques ficticios.
Compara el modelo local con la heurística y desglosa los resultados por
categoría. **Es una prueba de estrés didáctica, NO una evaluación externa
de calidad real del modelo.** No requiere huellas del modelo antiguo y no
toca URLs en Internet.

Guarda exclusivamente recuentos y métricas agregadas en
`backend/models/external_eval.metrics.json` (ignorados por Git).
El informe no incluye URLs originales ni ejemplos de falsos negativos.

### B. Evaluación externa con datos reales y etiquetas auditadas

El CSV local debe tener columnas `url,label,category`. Etiquetas: `0` o
`legitimate` (candidata legítima validada documentalmente); `1` o
`phishing`. Categorías permitidas: `login`, `query`, `redirect`, `other`.
Una fuente externa válida debe registrar fecha, definición de etiqueta,
procedencia, permisos y relación temporal con el entrenamiento. **No
visitar URLs peligrosas para verificar sus etiquetas.** Las URL legítimas
complejas deben provenir de fuentes documentadas; no se debe asumir que
una URL es segura por estar en Tranco. No reutilizar datos para ajustar
el modelo después de ver las métricas finales.

Ejemplo de ejecución con un CSV local preparado (NO incluido en Git):

    .\.venv\Scripts\python.exe -m ml_scripts.external_eval --csv data/external.csv --source "Corpus externo auditado"

El script:
1. Extrae características sin acceder a hosts.
2. Exige que el modelo haya guardado huellas SHA-256 del **corpus
   original completo** (incluyendo train, validación y test).
3. Compara grupos aproximados de dominio y **rechaza todo el lote** si
   detecta cualquiera compartido; no filtra muestras silenciosamente.
4. Emite métricas agregadas globales, de la heurística y por categoría.
   Nunca imprime URLs individuales ni tokens.

**Limitación crucial:** el modelo entrenado antes de esta fase **no incluye
esas huellas**. El CSV externo será rechazado por seguridad metodológica.
Primero debes entrenar un modelo nuevo con la versión actualizada de
`ml_scripts.train` y un dataset cuyos términos de uso hayas revisado.

Antes de reemplazar un modelo local, guarda una copia **privada** de tus
métricas y del modelo original si necesitas reproducir ese experimento.
El formato `.joblib` deserializa código: jamás cargues uno ajeno o dudoso.
Las huellas SHA-256 en el modelo **no son anonimización perfecta**:
el modelo nunca debe distribuirse como archivo público y las URLs
tampoco deben subirse a GitHub.

### C. Qué todavía no demuestra la fase 3

- Los 18 ejemplos inventados no acreditan rendimiento en sitios reales.
- Un CSV externo solo es válido si sus etiquetas, procedencia y fechas
  son independientes y confiables. La revisión es responsabilidad humana.
- El agrupamiento de dominios es aproximado (no hay lista PSL completa);
  puede no identificar campañas compartidas entre múltiples dominios.
- Los intervalos Wilson no corrigen sesgo de fuente, de campaña o temporal.
- El puntaje heurístico no es una probabilidad y el ML no está calibrado.

## Preparación PhiUSIIL UCI 2024 (fase 3B)

Fuente: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
(Prasad y Chandra, 2024; licencia CC BY 4.0).
Archivo local original en `backend/data/PhiUSIIL_Phishing_URL_Dataset.csv`.

**Nunca se usa PhiUSIIL para entrenar el modelo que se probará con
PhiUSIIL.** La evaluación debe ser independiente de selección de modelo,
ajustes de hiperparámetros y umbrales. El dataset de 2024 es anterior al
entrenamiento de feeds de 2026; no puede presentarse como prueba temporal
futura. Su etiqueta representa la anotación del dataset y no es una
verificación actual del contenido del sitio.

La convención de etiquetas se invierte obligatoriamente:
- UCI: 1 = legítima -> CyberLens 0
- UCI: 0 = phishing -> CyberLens 1

La muestra se extrae localmente con una semilla fija (2026),
sin navegar ni descargar URLs. Selección aleatoria por clase y grupo
aproximado de dominio, como máximo una URL por grupo. Se descartan
grupos ambiguos con ambas etiquetas y grupos compartidos con el
corpus del entrenamiento anterior. La selección **no consulta**
las predicciones para incluir o excluir filas.

### Comandos en PowerShell (desde backend)

**1. Antes de cualquier reentrenamiento, respaldar el modelo y JSON:**

    $fecha = Get-Date -Format "yyyyMMdd-HHmmss"
    New-Item -ItemType Directory -Force "models\backup" | Out-Null
    Copy-Item "models\cyberlens_ml.joblib" "models\backup\cyberlens_ml-$fecha.joblib"
    Copy-Item "models\cyberlens_ml.metrics.json" "models\backup\cyberlens_ml-$fecha.metrics.json"

**2. Ejecutar pruebas y entrenar un modelo nuevo con el mismo tipo de
fuentes anteriores (OpenPhish/Tranco), solo tras revisar sus términos:**

    .\.venv\Scripts\python.exe -m unittest discover -s tests -q
    .\.venv\Scripts\python.exe -m ml_scripts.train --academic-feeds --accept-academic-terms --max-per-class 300

El modelo resultante guarda `dataset_group_fingerprints` solo dentro
del `.joblib` local; esas huellas no aparecen en el reporte JSON ni
se deben publicar (los hashes no son anonimización completa).

**3. Preparar la muestra de PhiUSIIL por fuera de entrenamiento:**

    .\.venv\Scripts\python.exe -m ml_scripts.prepare_phiusiil --per-class 250

Produce `backend/data/phiusiil_external.csv` con
`url,label,category`. No sobrescribe archivos existentes:
si se repite el proceso, respalda o renombra el anterior primero.

**4. Evaluar sin visitar los sitios:**

    .\.venv\Scripts\python.exe -m ml_scripts.external_eval --csv data/phiusiil_external.csv --source "PhiUSIIL UCI 2024 independiente"

Produce `backend/models/external_eval.metrics.json`.
Revisar `model_metrics`, `heuristic_baseline_metrics`, matriz de
confusión, falsos negativos y categorías. Si detecta grupos de dominio
reutilizados, el evaluador aborta.

**Condición para un informe académico honesto:** PhiUSIIL tiene muchas
URLs etiquetadas, pero eso no significa que los sitios sigan activos
ni que las etiquetas se puedan verificar visitándolos. No abrir URLs
maliciosas ni tratar 250 ejemplos por clase como evidencia de Internet
completo. Reportar siempre licencia, año, extracción, versión del modelo,
definición de clases y sesgos entre corpus.

## Fase 4 — CyberLens Lab (diagnóstico sintético)

Laboratorio educativo independiente de la interfaz pública. Se genera como
HTML local en backend/data (ignorado por Git). No instalar ni publicar como
parte de un sitio web. No reproduce interfaces oficiales ni autentica usuarios.

Desde backend:

    .\.venv\Scripts\python.exe -m unittest discover -s tests -q
    .\.venv\Scripts\python.exe -m ml_scripts.local_lab
    Start-Process "data\cyberlens_lab.html"

Contiene 12 casos ficticios (6 positivos y 6 negativos), con contextos
de redes sociales, diseño, correo, consultas y redirecciones. Todos los
hosts usan el dominio reservado .example y HTTPS. Las etiquetas provienen
del guion, no del contenido de un sitio real. Copiar las URLs como texto
a CyberLens, sin navegar a ellas.

La práctica de interacción utiliza únicamente Juanito_777 y DEMO_123.
No hay formularios de envío, autenticación, almacenamiento, logos oficiales
ni comunicaciones de red en la página. Los campos de demostración se
limpian al pulsar el botón. No introducir credenciales reales.

Para evaluar el catálogo con el modelo propio local:

    .\.venv\Scripts\python.exe -m ml_scripts.local_lab --evaluate

Se genera models/local_lab.metrics.json, separado del informe externo
PhiUSIIL. No reentrena ni modifica el modelo. No usar los resultados
sintéticos como estimación de eficacia real ni los casos ya revisados
para seleccionar hiperparámetros y reportar después una prueba final
sobre esos mismos ejemplos.

El laboratorio solo prueba el flujo de análisis léxico y la interacción
didáctica. No detecta formularios, HTML, robo de credenciales o ataques
en tiempo real. El entrenamiento multidataset y una evaluación real
reservada continúan pendientes.

## Fase 4B — modelo candidato con muestreo multidataset

Tras observar 247 falsos positivos de 250 negativos en PhiUSIIL y
6 de 6 en CyberLens Lab, se añadió un experimento controlado con las
fuentes locales PhiUSIIL y LegitPhish. Ambas usan la convención
1=legítima y 0=phishing, que se invierte al preparar los datos.

Desde backend, con los CSV originales, el modelo previo generado por
la fase 3 y data/phiusiil_external.csv:

    .\.venv\Scripts\python.exe -m unittest discover -s tests -q
    .\.venv\Scripts\python.exe -m ml_scripts.train_balanced --per-stratum 500

Muestreo reproducible por fuente y complejidad (ruta adicional o query),
mismo número de cada clase por estrato, únicamente HTTPS. Primero se
seleccionan estratos complejos. Se descartan grupos conflictivos, grupos
del corpus previo y los del test histórico PhiUSIIL, y se limita a una
URL por grupo. Si no hay al menos 25 casos complejos de cada clase y
100 muestras totales, el programa aborta. No inventa ejemplos para
completar cuotas. ISCX-URL2016 no se usa por falta de URLs originales.

El resultado se guarda en models/cyberlens_ml_balanced.joblib y
models/cyberlens_ml_balanced.metrics.json. El archivo activo
cyberlens_ml.joblib permanece intacto. El informe incluye la auditoría
matched_sampling con cantidades por fuente y complejidad.

El test reservado pertenece al mismo corpus curado, NO es una prueba
externa nueva. Restringir HTTPS y emparejar clases son decisiones de
control experimental, no una política de seguridad ni un reflejo de
la prevalencia real. Se necesita una fuente externa independiente
antes de promover el candidato. No entrenar con los casos de CyberLens
Lab ya observados; conservarlos como diagnóstico, no evidencia final.
Todos los archivos de datos y modelos permanecen locales.

## Fase 4C — comparación de datos reales, sintéticos e híbridos

El candidato Random Forest obtuvo 95 % de precision, 88,37 % de recall
y 4,84 % de falsos positivos en su test interno de 253 muestras.
En los 500 casos históricos PhiUSIIL (grupos excluidos) obtuvo 95,38 %
de precision, 49,6 % de recall y 2,4 % de falsos positivos.
El diagnóstico ficticio de 18 casos permaneció con 100 % de falsos positivos.
Estos resultados proceden de la consola aportada por el desarrollador.

El módulo generate_synthetic.py genera 160 escenarios hipotéticos por clase
por defecto, con dominios reservados .test, sin marcas reales, páginas,
autenticación, datos personales ni conexiones de red. Las etiquetas son
supuestos experimentales, no evidencia de que una URL sea phishing.

Desde backend:

    .\.venv\Scripts\python.exe -m unittest discover -s tests -q
    .\.venv\Scripts\python.exe -m ml_scripts.compare_hybrid --synthetic-per-class 160

El comparador reconstruye la muestra HTTPS emparejada de 1264 registros
y verifica que coincida el conjunto de grupos del candidato anterior
(esta verificación no garantiza igualdad de todas las filas originales).
Entrena tres Random Forest con hiperparámetros idénticos:
A, solo entrenamiento real; B, solo sintético; C, ambos.
Evalúa exclusivamente en la misma validación real de desarrollo,
incluyendo desglose simple/complejo. No consulta el test interno ya
reportado, ni los 500 registros históricos, ni las etiquetas del laboratorio.
No modifica o publica los modelos. Guarda models/hybrid_comparison.metrics.json.

La comparación es exploratoria: el tamaño de entrenamiento difiere entre
A/B/C y las plantillas ficticias tienen su propio sesgo. No confundir una
mejora en validación con eficacia externa. No se selecciona el modelo final
ni se elige un umbral con los tests históricos; se necesita un corpus
nuevo, independiente y reservado antes de promover un modelo.

## Fase 4D — selección del umbral en validación

La fase 4C fue comprobada con 81 pruebas. En 203 casos de validación
(109 positivos, 94 negativos), el entrenamiento híbrido obtuvo
precision 94 %, recall 86,24 %, F1 89,95 % y FPR 6,38 %.
El modelo solo real obtuvo FPR 8,51 % con el mismo recall.
En el subconjunto complejo (17 negativos, 20 positivos), las falsas
alarmas pasaron de 5 a 3. Es evidencia exploratoria, no una estimación
final ni una comparación que aísle el efecto de tamaño del entrenamiento.

Desde backend, después de actualizar la rama:

    .\.venv\Scripts\python.exe -m unittest discover -s tests -q
    .\.venv\Scripts\python.exe -m ml_scripts.tune_hybrid_threshold

Reconstruye los 1264 grupos del corpus real y los 320 casos sintéticos
de la fase 4C. Entrena Random Forest con la misma partición real de
entrenamiento y sintéticos, sin ajustar con el test de 253 casos ni
los 500 casos históricos. Explora una malla fija de umbrales de 0.05
a 1.00 con paso 0.05 únicamente sobre la validación de desarrollo.
Maximiza verdaderos positivos sujeto a FPR <= 10 % observado; en empate
minimiza falsos positivos y luego elige el umbral mayor.
Reporta por separado si alcanza recall >= 90 %. No fuerza una solución
cuando no hay umbral factible, y no reentrena tras congelar el umbral.

Produce models/hybrid_threshold.metrics.json con la curva y, si hay
umbral factible, models/cyberlens_ml_hybrid_candidate.joblib. Los dos
archivos permanecen locales. No sobrescribe resultados anteriores,
ni modifica el modelo activo. El candidato contiene experimental_only
y la API rechaza su activación accidental. El evaluador offline usa
decision_threshold (por defecto 0.5 en modelos anteriores).
El candidato registra conservadoramente todos los grupos conocidos,
incluidos los históricos excluidos, para rechazar su reutilización
como nueva prueba externa.

El informe es de desarrollo y se selecciona en la misma validación ya
observada: no estima eficacia final ni garantiza el límite FPR fuera
del conjunto. Un umbral factible no implica que el modelo alcance la
meta de recall ni que deba desplegarse. La evaluación independiente
y el motor de decisión con opción incierta siguen pendientes.
