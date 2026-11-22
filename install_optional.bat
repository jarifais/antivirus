@echo off
cd /d "%~dp0"
echo Instalando motores opcionales: YARA, 7z y RAR...
call _python.bat -m pip install --upgrade yara-python py7zr rarfile
if errorlevel 1 (
  echo ERROR: alguna dependencia no pudo instalarse.
  exit /b 1
)
echo Instalacion terminada.
echo NOTA: rarfile puede requerir ademas un backend RAR compatible instalado en Windows.
