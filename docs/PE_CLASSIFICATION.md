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
