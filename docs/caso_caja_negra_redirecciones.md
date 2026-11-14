# Caso de caja negra: enlace de seguimiento y redirecciones (CyberLens)

## Fuente y contexto
Un caso documentado públicamente en Reddit (r/sysadmin, publicación «Here's a phishing URL to give you nightmares») describe una URL que comienza con un dominio de seguimiento legítimo y, según su autor, contiene varias redirecciones hasta una falsa página de inicio de sesión.

Referencia de la publicación: https://www.reddit.com/r/sysadmin/comments/d9ndnf/heres_a_phishing_url_to_give_you_nightmares/

> No se reproduce la URL original potencialmente activa ni se intenta abrirla, seguir redirecciones o descargar su contenido. El relato de terceros no equivale a una verificación independiente.

## Prueba V0.2.1 realizada en Windows
Al pegar la cadena copiada del texto en formato Markdown, la interfaz devolvió **422: URL HTTP/HTTPS inválida**. Esa entrada incluía caracteres propios de Markdown y espacios, por lo que no era una URL válida como cadena única. La prueba valida el comportamiento de entrada, **no** confirma que el sistema detecte un phishing.

## Aporte de la V0.3
En el extractor ML `features.py` se añadieron tres variables relacionadas con redirección aparente: `redirect_named_parameter`, `embedded_url_candidate` y `external_embedded_host`. Para una URL **ficticia** como:

```text
https://redirector.example.org/r?next=https%3A%2F%2Fotra.example.net%2Flogin
```

se detecta la presencia de `next`, una URL anidada y que su host difiere del principal, **sin realizar peticiones a los dominios**. Esas variables solo influyen en el modelo si el usuario lo entrena con ejemplos etiquetados que permitan aprender su relevancia.

## Limitaciones y siguiente experimento
Ni la V0.2.1 ni la V0.3 resuelven redirecciones efectivas. Una URL embebida puede ser un recurso legítimo, y un enlace malicioso puede redirigir desde el servidor sin contener ningún parámetro reconocible. La V0.4 debe ampliar pruebas offline de parametrización, probar falsos positivos y estudiar redirecciones reales **únicamente** con aislamiento de red y controles contra SSRF documentados; no es una función habilitada actualmente.
