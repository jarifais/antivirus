# MiniAntivirus

Proyecto de análisis estático de archivos para la carpeta **Incoming de eMule**. El objetivo actual es actuar como **gatekeeper** antes de que otros programas consuman los archivos.

**Estado de la migración:** preparación del repositorio GitHub. El código fuente histórico v0.3.0 se está importando por etapas; el árbol de `main` todavía no debe considerarse una distribución instalable.

## Desarrollo y colaboración

- [Hoja de ruta de los 16 puntos](ROADMAP.md) y [lista pública y actualizable en GitHub Issues](https://github.com/jarifais/antivirus/issues/9).
- [Tareas accesibles para nuevos colaboradores](https://github.com/jarifais/antivirus/issues/7) y [cómo contribuir](CONTRIBUTING.md).
- Estado: **bloque 1 (ejecutables y scripts) implementado provisionalmente**, pero pendiente validar sensibilidad y falsos positivos con corpus representativo. Siguiente punto: **bloque 2, dobles extensiones** ([issue #6](https://github.com/jarifais/antivirus/issues/6)).
- **Licencia propietaria: todos los derechos reservados** ([LICENSE](LICENSE)). Prohibida la redistribución y comercialización sin autorización escrita, con las excepciones legales y los usos permitidos por GitHub. Quienes contribuyan código deberán firmar un acuerdo individual de cesión antes de que se integre ([CONTRIBUTING.md](CONTRIBUTING.md)). Revisión jurídica formal pendiente en [#8](https://github.com/jarifais/antivirus/issues/8).

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

**MiniAntivirus es propietario y no tiene licencia de código abierto.** El titular se reserva los derechos de explotación del material que legítimamente le pertenezca o se le haya cedido. Ninguna persona adquiere derechos de redistribución o comercialización por acceder al repositorio, salvo autorización escrita, derechos legalmente reconocidos y usos permitidos por GitHub. Ver [LICENSE](LICENSE), [CONTRIBUTING.md](CONTRIBUTING.md) y [plantilla de cesión por aportación](CONTRIBUTOR_AGREEMENT_TEMPLATE.md).

No subir malware real, muestras históricas ejecutables, datos de usuarios, diagnósticos reales, archivos de cuarentena ni secretos. Ver [SECURITY.md](SECURITY.md).
