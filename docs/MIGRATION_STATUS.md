# Migración a GitHub — registro inicial

Fecha de la comprobación: **2026-11-22**.

## Origen verificado

| Artefacto | SHA-256 | Estado |
| --- | --- | --- |
| MiniAntivirus_v0.3.0.zip | `70c0a9a50e6e3110efeb9ad0fc54ef53e2395abf1de4f5245c07dece5ec8d5cb` | ZIP íntegro, 46 archivos |
| Documento Maestro v1.0 | `ff6b493a9bbbb4026d07ccba6b377e1e40d60368bde4da8d1a6f0df1471f0a95` | Archivo local disponible |
| Documento Maestro v1.1 | `abcc47b847573a85c28a97fdb58c5a922c3fad5fa1d57f5d19c55b66df76bf00` | Archivo local disponible |
| Documento Maestro v1.2 | `004478ccb837178f553c4fa8cc95f12c630f0617b39b42d10685ddee69e2600a` | Archivo local disponible |
| Documento Maestro v1.3 | `76831f425ddc6336e10591487773920f9ed3e1643e03f56e1a6e73ad9c5648f6` | Archivo local disponible |
| Documento Maestro v1.4 | `0fbb1692be63228f07cd3f020ba959d3a779dd2e16c0846bff1580f6322a41ef` | Referenciado como vigente; archivo no disponible en el contenedor de esta revisión |

## Validación inicial del software v0.3.0

- `ZipFile.testzip(): PASS`.
- `python -m compileall -q .: PASS`.
- `python -m unittest discover -s tests -v: 16/16 PASS`, en entorno Linux de validación.
- No se han realizado cambios funcionales en el código original.
- Las pruebas anteriores **no** sustituyen a la ejecución real de la capa Windows.

## Estado de importación

- [x] Localizar el repositorio y confirmar permisos de escritura.
- [x] Comprobar integridad del ZIP v0.3.0 y su batería de tests.
- [x] Definir exclusiones de seguridad del repositorio.
- [ ] Importar íntegramente código fuente/configuración/tests/scripts de v0.3.0.
- [ ] Importar el Documento Maestro vigente v1.4 y los documentos históricos.
- [ ] Añadir y verificar GitHub Actions Linux/Windows.
- [ ] Publicar el tag de baseline, una vez verificada equivalencia del árbol importado.
- [ ] Revisar la diferencia completa entre el ZIP de origen y GitHub.

**Regla:** la rama `main` no debe tratarse como baseline funcional importada hasta cerrar esta lista.
