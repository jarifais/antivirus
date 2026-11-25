# Hoja de ruta de MiniAntivirus

**Lista de seguimiento editable:** [Issue #9 — los 16 puntos](https://github.com/jarifais/antivirus/issues/9). Esta es la fuente operativa para el avance de los bloques; las casillas únicamente se cerrarán tras validación.

**Advertencia:** MiniAntivirus sigue siendo experimental. Los resultados de tests con muestras sintéticas no demuestran tasa de detección ni permiten sustituir a un antivirus comercial. El Documento Maestro normativo v1.4 original no está disponible para comprobación; esta lista procede de los 16 puntos tratados en la conversación.

## Los 16 puntos originales (4 categorías)

**Ejecutables y scripts (1–5)**

1. **Ejecutables y scripts activos.** Implementación inicial realizada, **cerrado provisionalmente**. Validación de precisión pendiente: [#4](https://github.com/jarifais/antivirus/issues/4).
2. **Dobles extensiones engañosas.** Implementación inicial integrada y probada en Linux/Windows (**cierre funcional provisional**); pendiente corpus de falsos positivos y cobertura Unicode [#6](https://github.com/jarifais/antivirus/issues/6), PR #10.
3. **Discrepancias entre extensión y formato ejecutable real.** **Próximo punto:** ampliar análisis y pruebas para formatos ejecutables ocultos bajo extensiones inocuas [#11](https://github.com/jarifais/antivirus/issues/11).
4. **Entropía elevada en ejecutables.** Heurística preliminar; pendiente calibración y falsos positivos.
5. **PowerShell codificado.** Heurísticas y catálogo parcial; pendiente evaluación de variantes.

**YARA opcional (6–8)**

6. Indicadores YARA de PowerShell codificado.
7. Combinaciones YARA de posibles técnicas de inyección en procesos.
8. Combinaciones YARA relacionadas con herramientas legítimas de Windows usadas durante ataques (LOLBins).

**Comprimidos y contenedores (9–15)**

9. Archivos ejecutables/activos dentro de ZIP.
10. Dobles extensiones dentro de ZIP.
11. Rutas peligrosas dentro de ZIP (traversal y rutas absolutas).
12. Archivos ZIP cifrados que no se pueden inspeccionar.
13. Archivos ZIP corruptos o ilegibles.
14. Límites de descompresión que previenen bombas ZIP y consumo excesivo.
15. Formatos sin parser completo: RAR, 7z, TAR, GZIP, BZIP2 y XZ.

**Errores de análisis (16)**

16. Archivos inaccesibles, modificados durante escaneo, tiempos agotados y errores de parser/motor: nunca declarar `CLEAN` un análisis incompleto.

> Tener código para un punto no significa que se haya probado exhaustivamente. El progreso verificable está en la [issue #9](https://github.com/jarifais/antivirus/issues/9) y sus incidencias/PR vinculados. No hay una lista finita que garantice detección del 100 % de malware.

## Para participar

- [#7 — Tests benignos/sintéticos y documentación](https://github.com/jarifais/antivirus/issues/7).
- [#11 — Extensión no acorde al contenido activo, siguiente punto](https://github.com/jarifais/antivirus/issues/11).
- [#8 — Aviso propietario publicado; revisión jurídica del acuerdo de contribución pendiente](https://github.com/jarifais/antivirus/issues/8).
- [LICENSE](LICENSE), [CONTRIBUTING.md](CONTRIBUTING.md), [plantilla de cesión](CONTRIBUTOR_AGREEMENT_TEMPLATE.md) y [SECURITY.md](SECURITY.md).

Los tests existentes cubren casos técnicos, pero **faltan corpus representativos benignos y maliciosos, métricas de falsos positivos y auditoría independiente** antes del cierre del primer bloque a nivel de producto.
