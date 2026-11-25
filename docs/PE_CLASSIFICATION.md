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
