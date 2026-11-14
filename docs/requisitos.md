# Requisitos

## Funcionales
RF01. Ingresar una URL.
RF02. Validar que use HTTP o HTTPS.
RF03. Calcular un puntaje de riesgo entre 0 y 100.
RF04. Mostrar los indicadores encontrados y su aporte al puntaje.
RF05. Clasificar el riesgo como bajo, medio o alto.
RF06. Guardar cada análisis en una base de datos local.
RF07. Consultar los análisis recientes desde la interfaz.
RF08. Detectar indicadores estructurales como IP, HTTP, Punycode, credenciales en URL, exceso de subdominios, términos sensibles, codificación y puertos no estándar.

## No funcionales
RNF01. Validación de entradas.
RNF02. Separación frontend/backend.
RNF03. Secretos fuera del código.
RNF04. Protección anti-SSRF obligatoria antes de implementar fetching remoto.
RNF05. Diseño responsive.
RNF06. El MVP no debe visitar ni descargar contenido de las URLs analizadas.
RNF07. La API debe exponer un endpoint de salud para diagnóstico.
