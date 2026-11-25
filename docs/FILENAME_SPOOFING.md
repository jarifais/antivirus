# Bloque 2 — nombres engañosos y dobles extensiones

La inspección se realiza sobre el **nombre literal del archivo**, sin ejecutar,
extraer ni cambiar de nombre el fichero. Su normalización es exclusivamente
para **detectar** posibles engaños; jamás se usa para abrir/mover rutas.

## Cobertura de esta iteración

- Extensiones visibles de documento seguidas de ejecutables o scripts,
  incluidas mayúsculas y formatos como PDF, DOCX, JPG, CSV.
- Separadores con apariencia de punto (Unicode) y compatibilidad NFKC.
- Caracteres de formato invisibles, marcas bidireccionales e indicadores
  de extensión activa formada con caracteres Unicode confusables comunes.
- Puntos o espacios finales ambiguos en Windows; separaciones largas
  diseñadas para ocultar parte de un nombre.
- Nombres que recuerdan a flujos alternativos NTFS usando dos puntos.

El hallazgo de doble extensión, controles bidireccionales o extensión activa
visualmente camuflada se **bloquea preventivamente**, pero **NO prueba malware**.
Nombres neutrales con letras Unicode (p. ej. un título en otro idioma) no se
penalizan por sí mismos. Los indicios menos fiables se mantienen como señales
de revisión. La decisión depende también del motor de contenido: un PE disfrazado
no debe liberarse por aparecer su hash en una lista de aprobados.

## Restricciones y pendientes

- No se implementa aquí el análisis de los miembros internos de ZIP: pertenece
  al punto 10 del plan.
- El mapa de caracteres confusables es **deliberadamente parcial**. No equivale
  a una implementación integral de Unicode UTS #39 ni resuelve todas las
  diferencias de sistemas de ficheros y aplicaciones.
- La presencia de un carácter sospechoso no es un diagnóstico de virus.
- Es necesaria validación con nombres reales benignos, pruebas en Windows
  y mediciones de falsos positivos antes de dar el punto por cerrado.
- No se modifica la autorización de ejecutables/scripts desconocidos.
- La inspección del nombre **no sustituye** al análisis binario ni a
  comprobaciones de firmas y parsers.

Referencia: issue #6 y hoja de ruta #9 del repositorio.
