# Contribuir a MiniAntivirus

Gracias por interesarte en la seguridad y calidad del proyecto.

## Estado y derechos

MiniAntivirus es un proyecto de seguridad **experimental** y el repositorio es público, pero **aún no hay licencia expresa para reutilizar o redistribuir el código**. La política sobre recepción de contribuciones de código está pendiente de decisión del propietario en [#8](https://github.com/jarifais/antivirus/issues/8).

Puedes colaborar desde ahora con **incidencias, observaciones técnicas, propuestas de arquitectura, revisión y resultados reproducibles con datos inofensivos**. Antes de preparar o enviar cambios de código, consulta las condiciones con el mantenedor mediante una issue; no debe inferirse que publicar un repositorio lo convierte en software de código abierto.

## Por dónde empezar

- [Seguimiento de los 16 puntos](https://github.com/jarifais/antivirus/issues/9).
- [Tareas de tests y documentación](https://github.com/jarifais/antivirus/issues/7).
- [Próximo bloque: dobles extensiones](https://github.com/jarifais/antivirus/issues/6).
- [Validación de la eficacia del primer bloque](https://github.com/jarifais/antivirus/issues/4).

Abre una issue para proponer un caso concreto, con entrada **sintética**, resultado esperado, sistema operativo y criterios de aceptación. Si te autorizan a enviar un cambio de código, enlaza la issue desde el PR y añade tests de regresión.

## Normas obligatorias

1. **No subir malware real**, muestras peligrosas, ejecutables de cuarentena, dumps, bases de datos de usuario, capturas de datos sensibles ni credenciales.
2. No ejecutar archivos sospechosos ni pedir a otros que los ejecuten para validar un PR. Las pruebas públicas deben ser inofensivas y reproducibles.
3. Mantener `ERROR != CLEAN`. Un archivo no inspeccionable no debe liberarse por defecto.
4. Distinguir detección de **indicadores** de confirmación de infección. Documentar límites y falsos positivos.
5. Ejecutar `python -m compileall -q .` y `python -m unittest discover -s tests -v`, y comprobar GitHub Actions en Windows y Linux.
6. Evitar nuevas dependencias, servicios externos, telemetría o cambios de política de seguridad sin discusión previa.
7. Para divulgación responsable, seguir [SECURITY.md](SECURITY.md) y no publicar detalles explotables en issues abiertas.

## Cómo se gestionará el avance

La [issue #9](https://github.com/jarifais/antivirus/issues/9) es la lista de tareas **editable**. Un punto se considera terminado solo si hay pruebas relevantes, revisión y evidencias en una issue o PR. El responsable del repositorio actualizará la hoja de ruta y podrá dividir los puntos en tareas menores según avance el proyecto.
