# Contribuir a MiniAntivirus

MiniAntivirus es un proyecto experimental con repositorio público y
**licencia propietaria**: [LICENSE](LICENSE). **No es open source**.

## Colaboración voluntaria

Las aportaciones pueden ser gratuitas, pero el código original que escriba
otra persona no pasa automáticamente a ser propiedad del mantenedor.
El titular reserva la explotación y comercialización de MiniAntivirus.
No se ofrece pago, salario, regalías, participación empresarial ni derecho
de explotación por colaborar, **sin perjuicio de derechos irrenunciables**.

Puedes abrir **issues** con propuestas, informes de errores o resultados
sintéticos de tests. La recepción de código, documentación original u
otros materiales protegidos de terceros solo se hará tras cumplir la
política de derechos.

### Requisito ANTES de fusionar una aportación externa

1. Abrir una issue con el alcance propuesto. No subir material de terceros
   sin permiso.
2. Identificar los archivos y commits de la aportación concreta.
3. Formalizar **por escrito** un acuerdo individual de cesión exclusiva de
   los derechos patrimoniales de explotación de esa aportación al titular
   legítimo del proyecto, **a título gratuito y dentro de los límites
   legales**. Modelo: [CONTRIBUTOR_AGREEMENT_TEMPLATE.md](CONTRIBUTOR_AGREEMENT_TEMPLATE.md).
4. Conservar el acuerdo firmado **fuera del repositorio público**. El
   propietario verificará la firma y la cadena de titularidad **antes de
   fusionar el PR**. La mera entrega del PR o aceptación del aviso de
   licencia no equivale por sí sola a la firma de una cesión.
5. Si no existe acuerdo válido, no se integrará el código propuesto.
   Los derechos morales y otros derechos irrenunciables del autor se
   respetan siempre.

**Nota:** el modelo debe ser revisado por asesoramiento legal cualificado
antes de emplearlo como contrato vinculante.

## Tareas para quienes quieran participar

- [Hoja de ruta — 16 puntos](https://github.com/jarifais/antivirus/issues/9).
- [Pruebas benignas/sintéticas y documentación](https://github.com/jarifais/antivirus/issues/7).
- [Bloque 2: extensiones engañosas](https://github.com/jarifais/antivirus/issues/6).
- [Validación del bloque 1](https://github.com/jarifais/antivirus/issues/4).

## Requisitos de seguridad y calidad

- No subir **malware real**, archivos de cuarentena, datos personales,
  secretos, informes sensibles ni credenciales.
- No ejecutar muestras sospechosas en pruebas públicas.
- Mantener la política `ERROR != CLEAN`.
- Justificar indicadores, probar falsos positivos y documentar límites.
- Cuando una aportación de código esté autorizada y documentada, incluir
  tests y comprobar `python -m compileall -q .`,
  `python -m unittest discover -s tests -v` y CI en Windows y Linux.
- Seguir [SECURITY.md](SECURITY.md) para divulgación responsable.

La lectura, visualización y forks dentro de GitHub siguen sujetos a
los términos de GitHub, y no confieren licencia general de
redistribución o comercialización fuera de la plataforma.
