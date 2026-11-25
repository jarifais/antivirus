# Primer bloque — clasificación inicial de ejecutables PE

El análisis estático inspecciona sin ejecutar: cabeceras PE32/PE32+,
secciones y permisos RWX, imports, tamaño del overlay y anomalías.
La presencia de firma Authenticode se **registra**, pero NO se valida
ni se trata como garantía de seguridad.

**Política conservadora:**
- PE malformado o análisis incompleto: ERROR (archivo no liberado).
- Sección RWX u otra evidencia de bloqueo: QUARANTINED.
- PE desconocido: QUARANTINED para revisión, **sin afirmar malware**.
- PE con SHA-256 aprobado explícitamente: CLEAN únicamente si el análisis
  ha finalizado sin errores, bloqueos ni hallazgos de riesgo.

Para aprobar archivos revisados por el propietario existe el campo opcional
de monitor_config.json: "trusted_executable_sha256": [].
Se añaden únicamente hashes SHA-256 completos de archivos previamente
verificados por un método independiente. Una modificación de un byte
cambia el hash y anula la aprobación. La firma digital presente o un
nombre convincente no conceden confianza.

Esta política no acredita que MiniAntivirus detecte todas las amenazas PE
ni que pueda decidir automáticamente qué ejecutables son benignos.
Los scripts conservan su bloqueo preventivo hasta implementar un parser propio.
Las pruebas sintéticas no miden recall ni tasa de falsos positivos.
Antes de ampliar la liberación automática harán falta corpus benignos,
muestras maliciosas controladas y validación real en Windows.

Documento Maestro v1.4: sigue pendiente de recuperación/importación.

## Scripts (primera cobertura estructurada)

El analizador de scripts inspecciona contenido (UTF-8, Windows-1252 y
UTF-16 LE/BE) sin ejecutar comandos. Comprueba indicadores como PowerShell
codificado, descarga combinada con ejecución y mecanismos de persistencia.
El tamaño inspeccionado está limitado por max_script_bytes (por defecto 1 MiB);
si el contenido no es inspeccionable, ERROR.

El propietario puede autorizar **una versión exacta** de un script verificado
mediante trusted_script_sha256 en la configuración. Los hallazgos y errores
tienen prioridad sobre esta autorización. Los scripts desconocidos continúan
retenidos para revisión, sin afirmarse que contienen malware.

No existe aún comprobación completa de código dinámico, ofuscación arbitraria,
firmas criptográficas ni garantía de detección de scripts maliciosos desconocidos.
Las pruebas son sintéticas y no sustituyen el benchmark con corpus de referencia.

## Catálogo ampliable de indicadores estáticos

El catálogo versionado `miniav/rules/indicators.json` contiene **48**
reglas curatoriales: 30 sobre texto de
scripts y 18 sobre imports de PE.
Cada regla indica ID, descripción, grupos literales, score, bloqueo y técnica
ATT&CK orientativa. Los grupos se combinan mediante AND y las alternativas
dentro de cada grupo mediante OR. La coincidencia NO demuestra infección.

No se interpreta código, expresiones regulares arbitrarias ni condiciones
dinámicas del fichero JSON. El validador rechaza reglas de estructura inesperada,
duplicadas y catálogos excesivamente grandes. Un error de carga de catálogo
marca el análisis como incompleto y deniega `CLEAN`.

**Limitaciones:** Es una ampliación concreta de cobertura, no «todos los
indicadores existentes». Un PE puede resolver APIs dinámicamente, y los scripts
pueden construir cadenas en tiempo de ejecución; ambas técnicas evaden las
búsquedas estáticas. También pueden existir falsos positivos. La asignación
de ATT&CK documenta la hipótesis de detección y no certifica la técnica
utilizada por el archivo. El fichero de catálogo debe revisarse y versionarse;
no se activa una descarga automática de reglas no verificadas.

Fuentes técnicas: https://attack.mitre.org/techniques/,
https://yara.readthedocs.io/en/stable/ y
https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html .
