# CyberLens V0.4 — heurísticas, redirecciones y ML experimental

**Proyecto de título, Ingeniería en Informática.** Evalúa características estructurales de una URL para advertir sobre señales asociadas al phishing **sin visitar la dirección**. Conserva el análisis heurístico, el historial aislado por navegador y el módulo ML opcional de V0.3. En V0.4 incorpora señales explicativas sobre URLs anidadas en parámetros de redirección.

> **ADVERTENCIA:** BAJO no significa SEGURO. Los indicadores son heurísticos y la probabilidad ML es una estimación **no calibrada** que requiere validación sobre datos representativos. CyberLens no certifica sitios, no analiza su contenido, no sigue redirecciones y no está listo para una operación comercial o de seguridad empresarial.

## Resumen de la V0.4

- Backend: Python 3.11+, FastAPI, Pydantic, SQLAlchemy y SQLite.
- Redirecciones: inspección **solo de texto** de parámetros frecuentes (`next`, `redirect`, `target`, etc.) para reconocer URLs HTTP(S) anidadas y destinos fuera del host original. **No se siguen enlaces ni se hace DNS/HTTP**. Se muestran dos indicadores informativos de **+0 puntos**: `URL anidada en parámetro` y `Destino en otro host`. Un destino externo puede ser legítimo; estas señales no certifican phishing.
- Frontend: Next.js 15.5.29, React 19.1.10, TypeScript y Tailwind CSS 4.
- ML: scikit-learn y joblib; **25 características numéricas** de una URL (longitud, estructura, signos, tokens, marcas, indicios de URLs anidadas, etc.).
- Entrenamiento: **Regresión Logística y Random Forest**; elección usando validación, evaluación final aislada, comparación con el detector heurístico y matriz de confusión. Los grupos de dominio no se comparten entre entrenamiento, validación y test.
- API: `/api/analyze` incluye sección `ml`; `GET /api/ml/status` comunica si hay modelo y, cuando existe, métricas agregadas.
- Persistencia: URL reducida al origen y contenido omitido, historial por cookie de sesión y resultado ML opcional. Migración automática desde versiones anteriores.
- **44 pruebas automatizadas** aprobadas en Windows por el desarrollador en la rama V0.4 (API, heurísticas, redirecciones, privacidad y ML con datos ficticios). **No equivalen a una medición real de eficacia ante phishing.**

**Importante:** el repositorio **NO contiene modelos entrenados con datos reales ni feeds de phishing**. El modelo de inferencia solo se activa después de que entrenes uno localmente con fuentes autorizadas. Nunca presentaremos las métricas de un dataset sintético como precisión real.

## Windows: instalar, comprobar y arrancar

Requisitos: Python 3.11+ (recomendado 3.12) y Node.js LTS (probado Node 24 en el equipo del desarrollador). Cuando utilices `fnm`, activa Node en cada PowerShell que lo necesite:

```powershell
fnm env --use-on-cd --shell powershell | Out-String | Invoke-Expression
fnm use 24
```

Abre tu copia local del repositorio **CyberLens**. Ejecuta PowerShell en **la carpeta raíz** (debe contener `backend`, `frontend` y `scripts`):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\install_windows.ps1
.\scripts\check_windows.ps1
.\scripts\run_dev_windows.ps1
```

Los scripts `install_windows.ps1` y `check_windows.ps1` **regresan a la carpeta desde donde se lanzaron**. Si llegas a quedar en `frontend`, ejecuta `cd ..` antes de invocar `scripts`, o ejecuta `..\scripts\check_windows.ps1` directamente.

Interfaz: http://localhost:3000 — API: http://localhost:8000 — Swagger: http://localhost:8000/docs — salud: http://localhost:8000/health — ML: http://localhost:8000/api/ml/status

El sistema funciona en **modo heurístico** aunque no hayas entrenado ML; en ese caso aparece *SIN ENTRENAR* y `"trained": false`.

### Entrenar ML con datasets propios (opción preferida)

Prepara **dos archivos locales** TXT (una URL por línea) o CSV (con encabezado `url`): uno con URLs de phishing **etiquetadas y verificadas** y otro con URLs candidatas legítimas que puedas justificar. No abras las URLs peligrosas para comprobarlas; usa datasets de origen confiable.

```powershell
.\scripts\train_ml_windows.ps1 -PhishingCsv "C:\datos\phishing.csv" -LegitimateCsv "C:\datos\legitimas.csv"
```

Se requieren al menos 20 URLs válidas y 12 grupos de dominio distintos por clase. Puedes usar `-MaxPerClass 800` (hasta 10.000). Los archivos y modelos permanecen locales y nunca se suben automáticamente a servicios externos. El entrenamiento guarda:

- `backend/models/cyberlens_ml.joblib` — modelo seleccionado + metadatos; **cárgalo solo si fue generado localmente por CyberLens**. Los archivos `joblib` de terceros no son seguros de deserializar.
- `backend/models/cyberlens_ml.metrics.json` — comparación de modelos y test final; no contiene URLs de ejemplo.

**No compartas los datos originales** ni distribuyas modelos entrenados sobre fuentes sujetas a restricciones de licencia.

### Obtención opcional de feeds académicos

Para una **prueba de investigación educativa no comercial**, existe un comando optativo que descarga exclusivamente los feeds **OpenPhish Community** (muestras reportadas como phishing) y **Tranco** (dominios populares usados como *proxy* de candidatos legítimos). **No visita ninguna URL de la lista**:

```powershell
.\scripts\train_ml_windows.ps1 -AcademicFeeds -AcceptAcademicTerms
```

Solo ejecútalo tras revisar y aceptar las condiciones de cada fuente:

- OpenPhish: https://openphish.com/terms.html y https://openphish.com/phishing_feeds.html. Uso académico/personal no comercial; **prohíbe redistribuir los datos** sin autorización, y sus términos pueden imponer restricciones a productos derivados. https://openphish.com/academic_use.html para el programa académico.
- Tranco: https://tranco-list.eu/ y https://tranco-list.eu/methodology.
- Alternativa: PhishTank publica feeds verificados, pero para descargas automatizadas recomienda **clave de aplicación** y `User-Agent` descriptivo: https://www.phishtank.org/developer_info.php. Este script **no** descarga PhishTank automáticamente.

**Limitación metodológica fundamental:** el conjunto *phishing de un feed activo vs portadas de dominios Tranco* tiene sesgo fuerte. Por ejemplo, un modelo podría aprender que tener ruta larga significa phishing, cuando multitud de sitios legítimos también tienen rutas largas. Por ello, sus métricas **no se pueden extrapolar a Internet real**, aunque el test esté separado por dominio. No utilizar el modelo para bloquear navegación ni afirmar exactitud general.

El script requiere conexión a Internet para descargar **solo los feeds**. Si falla por acceso, licencia o cambios en endpoints, utiliza archivos CSV locales. No uses reintentos agresivos para esquivar límites de proveedor.

### Qué ver después del entrenamiento

En el navegador, vuelve a analizar una URL y aparecerá la sección **Machine Learning experimental** con estimación de la clase phishing, modelo y aviso de incertidumbre. El **puntaje heurístico 0–100 NO se modifica ni se combina** con esa estimación hasta que calibremos modelos sobre datos representativos en una etapa posterior. La API carga un modelo local actualizado automáticamente al cambiar su archivo.

Los análisis guardan exclusivamente origen y metadatos sanitizados. Para no introducir rupturas, se añadió `ml_result_json` de manera compatible con SQLite anterior.

## Pruebas y verificación

```powershell
.\scripts\check_windows.ps1
cd frontend
npm run build
cd ..
```

El desarrollador verificó **44/44 pruebas de backend**, la compilación de producción del frontend y el ejemplo visual de redirección en Windows. Tras modificar la versión, repite estas comprobaciones antes de integrar la rama a `main`.

Puedes probar manualmente `https://example.com/` y `https://g00gle.example.com/login` como casos orientativos. Para una prueba de URL anidada usa un **destino ficticio**:

```text
https://redirector.example.org/r?next=https%3A%2F%2Fotra.example.net%2Flogin
```

En V0.4 el motor heurístico muestra `URL anidada en parámetro` y `Destino en otro host` como indicadores informativos **sin puntos adicionales**. Con el ejemplo ficticio anterior se espera **7/100, BAJO** por el término `login`; **BAJO no garantiza seguridad**. El extractor ML también marca características de redirección, pero sin un modelo entrenado no ofrece una predicción ML. Se inspecciona el texto, **no** se verifica un salto de redirección real. Rechazar una cadena pegada de Reddit con Markdown, espacios o `http\://` es **correcto**; esa prueba evalúa el validador, no la detección real de phishing. La cadena reportada en el caso Reddit no debe abrirse en tu navegador.

## Diseño de ML y limitaciones de evaluación

1. Extrae características de las URLs como texto. Nunca solicita el destino ni ejecuta HTML/JS.
2. Descarta duplicados y grupos de dominio que aparecen en ambas clases.
3. Separa grupos aproximadamente por dominio registrable (reglas simplificadas; sustituir por Public Suffix List completa si se necesita rigor académico mayor).
4. Separa conjuntos `train`, `validation` y `test` usando grupos disjuntos. Compara Regresión Logística y Random Forest sobre `validation` y reentrena el ganador en `train+validation`.
5. Evalúa **una única vez** sobre `test` e informa **precision**, **recall**, **F1** y `TN/FP/FN/TP`. Calcula el mismo conjunto test para la heurística (umbral de precaución ≥25).
6. El modelo generado no está calibrado para probabilidades fiables y las clases pueden estar sesgadas. La evaluación externa, temporal, robustez, falsos negativos y ensayos de usabilidad quedan para las siguientes etapas.

El reportado *accuracy* sobre ejemplos ficticios no es evidencia de desempeño de ciberseguridad. Solo se incluirán métricas verdaderas del dataset que tú entrenes, con fecha y procedencia.

## Seguridad y configuración

- `backend/.env.example` configura SQLite, CORS, cookies y retención; no publiques un `.env` real.
- `frontend/.env.local` puede configurar `NEXT_PUBLIC_API_URL` (por defecto `http://localhost:8000`).
- Las cookies del historial son `HttpOnly; SameSite=Lax`; no constituyen autenticación empresarial.
- El modelo se almacena localmente en carpeta ignorada por Git; no cargues `.joblib` desconocidos.
- Ejecuta `cd frontend; npm audit` para investigar las dos advertencias de dependencias vistas en Windows; **no** uses `npm audit fix --force` sin revisar cambios. Es una tarea pendiente antes del despliegue.
- No habilites acceso público ni envíes URLs reales con tokens a servicios externos. No hay DNS, TLS, reputación, crawling ni detección de redirecciones efectivas.

## Historial y migraciones

Antes de cambiar una instalación existente, respalda `backend/cyberlens.db` (si tienes datos que debas conservar). La migración agrega la columna opcional `ml_result_json`, conserva el historial que ya pertenece a tu navegador y mantiene el saneamiento de URLs. La cookie de sesión no identifica usuarios entre equipos o instalaciones.

## Archivos importantes

- `backend/app/analyzer/url_analyzer.py`: motor heurístico e integración de indicadores de redirección de V0.4.
- `backend/app/analyzer/redirect_analysis.py`: inspección léxica, sin conexiones de red, de destinos anidados y externos.
- `backend/app/ml/features.py`: características de la URL (25 valores).
- `backend/ml_scripts/train.py`: entrenamiento, separación agrupada, comparación y métricas.
- `backend/app/ml/model.py`: inferencia opcional desde modelo local confiable.
- `backend/app/api/routes.py`: API, historial y ML.
- `frontend/app/page.tsx`: interfaz con bloque ML experimental.
- `backend/tests/test_ml.py`: pruebas de entrenamiento e inferencia con datos sintéticos exclusivamente para comprobar ingeniería.
- `backend/tests/test_redirect_analysis.py`: nueve pruebas de redirección, codificación, dominios internos y privacidad.
- `docs/roadmap.md`: próximas etapas de validación y entrega.

**CyberLens V0.4 es un prototipo académico con detección léxica de posibles redirecciones y ML implementado en código, NO un detector comercial validado.**
