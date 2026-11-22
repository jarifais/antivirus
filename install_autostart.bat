@echo off
setlocal
cd /d "%~dp0"
call _python.bat doctor.py
if errorlevel 1 (
  echo ERROR: no se instala autostart porque la configuracion no es valida.
  exit /b 1
)
set "STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
set "VBS=%STARTUP%\MiniAntivirus_Incoming.vbs"
> "%VBS%" echo Set WshShell = CreateObject("WScript.Shell")
>>"%VBS%" echo WshShell.Run chr(34) ^& "%~dp0run_monitor.bat" ^& chr(34), 0
>>"%VBS%" echo Set WshShell = Nothing
echo Inicio automatico instalado:
echo %VBS%
endlocal
