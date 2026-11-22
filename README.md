# MiniAntivirus

Proyecto de análisis estático de archivos para la carpeta **Incoming de eMule**. El objetivo actual es actuar como **gatekeeper** antes de que otros programas consuman los archivos.

**Estado de la migración:** preparación del repositorio GitHub. El código fuente histórico v0.3.0 se está importando por etapas; el árbol de `main` todavía no debe considerarse una distribución instalable.

## Referencias del proyecto

- Última versión funcional verificada fuera de GitHub: **MiniAntivirus v0.3.0**.
- Documento Maestro normativo vigente: **v1.4**. Se incorporará a `docs/master/current/` una vez recuperado el archivo original.
- Próximo objetivo: **v0.3.1** (diagnóstico/logs); posteriormente **v0.4.0** (arquitectura del motor y benchmarks).

## Invariantes de seguridad

- Solo los archivos clasificados como `CLEAN` pueden pasar a `AV_Clean`.
- `ERROR` nunca significa `CLEAN`.
- Las muestras se analizan sin ejecutarse.
- La cuarentena preserva el archivo; no hay borrado automático.
- El organizador NAS debe vigilar `AV_Clean`, no `Incoming`.
- La ruta de operación completa exige carpetas del mismo volumen en v0.3.0.

## Migración y validación

Consultar [estado de migración](docs/MIGRATION_STATUS.md). El archivo ZIP original v0.3.0 ha superado localmente `python -m compileall` y `python -m unittest discover -s tests -v` (**16/16 PASS**); este resultado no acredita aún una ejecución en GitHub Actions ni una validación nativa en Windows.

## Código, licencia y muestras

**Repositorio público no equivale a software de código abierto.** No se ha definido una licencia de redistribución/modificación; cualquier elección de licencia requiere aprobación expresa del titular.

No subir malware real, muestras históricas ejecutables, datos de usuarios, diagnósticos reales, archivos de cuarentena ni secretos. Ver [SECURITY.md](SECURITY.md).
