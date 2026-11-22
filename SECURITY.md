# Seguridad de MiniAntivirus

MiniAntivirus es software experimental en desarrollo. **No debe anunciarse ni utilizarse como sustituto de una solución antimalware integral**.

## Divulgación responsable

No publiques vulnerabilidades explotables, secretos, rutas privadas, informes con datos sensibles ni muestras reales de malware en incidencias públicas. Contacta de forma privada al propietario del repositorio para coordinar el informe antes de divulgar detalles técnicos.

## Contenido prohibido en este repositorio público

- Malware real o histórico ejecutable.
- Cuarentena, datos de `Incoming` y archivos de usuarios.
- Bases de datos SQLite reales, logs, volcados, paquetes de diagnóstico o telemetría identificable.
- Tokens, credenciales, claves privadas y certificados de firma privados.

El laboratorio de malware real y su corpus deben permanecer fuera del repositorio, fuera de carpetas sincronizadas y de cualquier publicación de GitHub Actions.

## Principios

- Analizar sin ejecutar.
- Fail-closed si no se obtiene una decisión fiable.
- Registrar versiones y pruebas de cada release.
- Tratar como no confiables todos los archivos y formatos examinados.
