# CyberLens V0.2 — Avance técnico

## Objetivo del avance
Transformar el prototipo V0.1 en un MVP demostrable que no solo calcule un puntaje, sino que conserve evidencia de los análisis y utilice un conjunto más amplio de indicadores estructurales.

## Cambios implementados

### 1. Motor heurístico ampliado
Se añadieron señales de riesgo sin visitar la URL:
- HTTP sin cifrado de transporte.
- Uso de dirección IP.
- Usuario/contraseña antes de `@`.
- Punycode y posibles dominios visualmente engañosos.
- Exceso de subdominios.
- Varios guiones en el hostname.
- Acortadores conocidos.
- Puertos web no estándar.
- Longitud excesiva.
- Profundidad de la ruta.
- Cantidad elevada de parámetros.
- Codificación porcentual abundante.
- Términos sensibles de acceso, verificación y pagos.

El resultado sigue siendo heurístico y no se presenta como una certeza de phishing.

### 2. Persistencia con SQLite
Cada análisis exitoso se almacena localmente con:
- URL.
- Puntaje.
- Nivel de riesgo.
- Indicadores.
- Mensaje explicativo.
- Fecha y hora.

### 3. API de historial
Se incorporó:

`GET /api/history?limit=10`

Permite recuperar los análisis más recientes para mostrarlos en el frontend.

### 4. Interfaz V0.2
La página principal ahora incluye:
- Resultado visual por nivel de riesgo.
- Barra de puntaje.
- Cantidad de señales encontradas.
- Severidad por indicador.
- Historial reciente persistente.
- Aviso explícito de que el MVP no visita la URL.

### 5. Pruebas
Se agregaron pruebas unitarias para comprobar:
- URL HTTPS simple.
- URL HTTP con IP y términos sensibles.
- Punycode.
- Credenciales antes de `@`.
- Rechazo de protocolos distintos de HTTP/HTTPS.

## Decisión de seguridad
La V0.2 continúa sin hacer solicitudes a URLs introducidas por el usuario. Esto evita introducir prematuramente riesgos de SSRF. La consulta remota de DNS/TLS/HTML quedará para una fase posterior con validación y aislamiento específicos.

## Próximo avance recomendado — V0.3
Implementar análisis de reputación y dominio de forma controlada. Orden sugerido:
1. Normalización y extracción robusta del dominio registrable.
2. Resolución DNS con bloqueo de direcciones privadas/locales.
3. Consulta de antigüedad/metadatos del dominio mediante una fuente controlada.
4. Información básica del certificado TLS.
5. Dashboard con estadísticas del historial.

Esto prepara las features que después pueden utilizarse para el modelo de Machine Learning.
