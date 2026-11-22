@echo off
cd /d "%~dp0"
call _python.bat -m unittest discover -s tests -v
pause
