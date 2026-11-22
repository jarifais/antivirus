@echo off
setlocal
set "VBS=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\MiniAntivirus_Incoming.vbs"
if exist "%VBS%" del /q "%VBS%"
echo Inicio automatico retirado.
endlocal
