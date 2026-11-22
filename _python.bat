@echo off
setlocal
where py >nul 2>nul
if not errorlevel 1 goto USE_PY
where python >nul 2>nul
if not errorlevel 1 goto USE_PYTHON
echo ERROR: no se ha encontrado Python 3 en PATH ni el launcher py.exe.
exit /b 9009

:USE_PY
py -3 %*
exit /b %errorlevel%

:USE_PYTHON
python %*
exit /b %errorlevel%
