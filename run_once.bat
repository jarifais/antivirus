@echo off
cd /d "%~dp0"
call _python.bat watch_incoming.py --once
