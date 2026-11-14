# CyberLens — V0.2.1 (etapa 1: corrección y estabilización)

Plataforma web académica para **evaluar señales estructurales de riesgo en URLs** antes de visitarlas. Devuelve una puntuación heurística orientativa, indicadores comprensibles e historial **privado para cada navegador**. No consulta el contenido remoto.

> **Advertencia:** un resultado BAJO **no demuestra que un sitio sea seguro**. La detección aún requiere validación con datos etiquetados, pruebas de usabilidad y, en otra etapa, Machine Learning. No publicar V0.2.1 como servicio empresarial o verificador garantizado.

## Tecnologías

- Interfaz: Next.js **15.5.29**, React **19.1.10**, TypeScript y Tailwind CSS 4.
- API: Python 3.11+, FastAPI, Pydantic.
- Persistencia: SQLite y SQLAlchemy.
- Pruebas: `unittest` y `fastapi.testclient` (necesita `httpx`).
- Machine Learning: pendiente, fuera de V0.2.1. Cuando corresponda, instalar `backend/requirements-ml.txt`.

## Ejecución en Windows

Necesitas **Python 3.11+** y **Node.js LTS** (recomendado Node 22), ambos accesibles desde PowerShell.

1. Descomprime el ZIP y abre la carpeta `CyberLens` en VS Code.
2. Abre PowerShell en esa carpeta y ejecuta una sola vez:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\install_windows.ps1
```

3. Para arrancar las dos aplicaciones:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\run_dev_windows.ps1
```

4. Abre **http://localhost:3000** (usa *localhost*, no 127.0.0.1, para evitar diferencias de cookies si mantienes la configuración predeterminada).

Otros enlaces: API http://localhost:8000, Swagger http://localhost:8000/docs y prueba de salud http://localhost:8000/health.

### Ejecución manual (si prefieres dos terminales)

En la primera terminal, desde `backend`:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

En la segunda, desde `frontend`:

```powershell
npm run dev
```

## Configuración opcional

Copia `backend/.env.example` a `backend/.env` para personalizar variables. El archivo **no** está incluido en Git.

| Variable | Uso | Predeterminada |
|---|---|---|
| `DATABASE_URL` | SQLite, relativa al directorio de ejecución o con ruta absoluta | `sqlite:///.../backend/cyberlens.db` |
| `ALLOWED_ORIGINS` | Orígenes frontend aceptados por CORS, separados por comas | `http://localhost:3000,http://127.0.0.1:3000` |
| `COOKIE_SECURE` | `true` obliga a cookies solo bajo HTTPS | `false` para localhost |
| `HISTORY_RETENTION_DAYS` | Caducidad de registros; limpieza al analizar/consultar historial | `30` |
| `NEXT_PUBLIC_API_URL` | URL de la API para el navegador (en `frontend/.env.local`) | `http://localhost:8000` |

**No habilites `COOKIE_SECURE=true` si pruebas por HTTP local**; se necesita HTTPS. Para un despliegue exterior, HTTPS y cookie segura son obligatorios, pero por sí solos no convierten a V0.2.1 en una aplicación lista para producción.

## Qué cambió de V0.2 a V0.2.1

1. El motor ya no confunde IPv4/IPv6 con subdominios. Las señales de IP y credenciales tienen un peso suficiente para producir al menos MEDIO cuando aparecen solas.
2. Se añaden **reglas experimentales y limitadas** para ciertos nombres de marcas y sustituciones obvias (ejemplo `g00gle`). No certifican suplantación ni sustituyen consultas de reputación.
3. El servidor procesa la URL completa solo durante el análisis en memoria; en el **resultado HTTP y la base de datos** conserva únicamente el esquema/dominio/puerto y una indicación de contenido omitido. No persiste usuario, contraseña, ruta, parámetros, fragmento ni token de sesión en claro.
4. El historial ahora se aísla mediante una cookie aleatoria `HttpOnly`, `SameSite=Lax`. La base de datos conserva solo el hash SHA-256 del token de sesión. Dos navegadores distintos no ven los análisis del otro.
5. Nuevo endpoint `DELETE /api/history` y botón «Borrar mis análisis».
6. Entradas no válidas devuelven un mensaje limpio (422), sin repetir los datos originales del formulario.
7. `DATABASE_URL`, CORS, cookie segura y retención ya son configurables. Se agregan cabeceras `no-store` y `nosniff`.
8. Dependencias de frontend actualizadas a versiones corregidas de seguridad, manteniendo Next.js 15.
9. Suite ampliada de **5 a 25 casos**, incluyendo pruebas API, migración de BD, cookies y privacidad.

## Migración de datos desde V0.2

Si tienes una base `backend/cyberlens.db` creada por V0.2, **haz una copia local antes de cambiar de versión**. La primera ejecución actualiza el esquema y **anonimiza las URLs antiguas** (solo conserva el origen y una marca del contenido omitido). Por privacidad, estos registros anteriores quedan **fuera de los historiales nuevos** y no pueden vincularse automáticamente a un navegador. Los nuevos análisis sí aparecerán en el historial de ese navegador. Si quieres eliminar por completo rastros históricos, elimina la base anterior y deja que se cree una nueva (después de conservar solo lo que estés autorizado a guardar).

## Pruebas

Desde la carpeta `backend`, con Python y dependencias instaladas:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Si usas la terminal del entorno donde ejecutas Python directamente:

```bash
cd backend
python -m unittest discover -s tests -v
```

Antes de entregar, ejecuta además **`.\scripts\check_windows.ps1`** desde la raíz: valida las pruebas del backend y la compilación real del frontend.

Prueba manual: analiza `https://example.com/` (BAJO), `https://g00gle.com/` (MEDIO) y una URL ficticia con ruta/parámetros. Abre una ventana incógnito: el historial debe empezar vacío. Prueba después el botón «Borrar mis análisis».

## API

- `GET /health`: estado de la API.
- `POST /api/analyze`: cuerpo JSON `{ "url": "https://example.com/login" }`; devuelve URL redactada, puntaje, nivel, indicadores y mensaje. Establece cookie de sesión en el navegador.
- `GET /api/history?limit=10`: historial de esa cookie, máximo 50 registros, no público/global.
- `DELETE /api/history`: elimina solo los registros de esa cookie.

El frontend utiliza `credentials: 'include'` para conservar la sesión entre peticiones. Se recomienda **no** usar Swagger como única prueba de historial, porque las cookies de Swagger y las del frontend pueden comportarse como sesiones diferentes.

## Limitaciones conocidas y siguientes entregas

- No existe aún dataset etiquetado ni medición real de precision, recall, F1 o falsos positivos. Los pesos son **heurísticos, no probabilidades calibradas**.
- El conjunto de marcas es reducido; puede alertar sobre dominios legítimos, por ejemplo sitios de terceros que mencionan una marca.
- No existe aún ML, DNS, TLS, reputación externa, análisis de correos, autenticación persistente ni despliegue público protegido.
- La cookie ofrece aislamiento de historiales en un **prototipo local**, no un sistema de cuentas y permisos empresariales. Si se publica, será necesario añadir autenticación, protección contra abuso, despliegue HTTPS, monitoreo, pruebas de seguridad y políticas de datos.
- El frontend **no pudo compilarse en el entorno de preparación** porque no había acceso al registro npm para descargar los paquetes. El backend se ejecutó y pasó 25 pruebas. Ejecuta `npm install` y `npm run build` en tu Windows con conexión a Internet antes de considerarlo validado.

Consulta `docs/avance_v0.2.1.md` para los cambios verificados y `docs/roadmap.md` para las próximas etapas.


## caso caja negra (link del reddit)

https://www.reddit.com/r/sysadmin/comments/d9ndnf/heres_a_phishing_url_to_give_you_nightmares/?solution=8cc6324d1f8ebb408cc6324d1f8ebb40&js_challenge=1&jsc_token=2824be10929bdc604753c70a67a1c3312b5feb76663bab9c236038861f1beb7e&jsc_orig_r=&_x_tr_sl=en&_x_tr_tl=es&_x_tr_hl=es&_x_tr_pto=tc