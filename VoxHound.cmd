@echo off
setlocal
cd /d "%~dp0"

rem Prefer the project-local virtualenv: it is independent of PATH and of which
rem Python Explorer happens to see.
if exist "%~dp0.venv\Scripts\pythonw.exe" goto :venv

rem Otherwise use the first python on PATH that can actually import the project.
set "PYW="
for /f "delims=" %%P in ('where python 2^>nul') do (
  if not defined PYW (
    "%%P" -c "import voxhound, PySide6" >nul 2>nul
    if not errorlevel 1 set "PYW=%%P"
  )
)
if not defined PYW goto :noenv
for %%D in ("%PYW%") do if exist "%%~dpDpythonw.exe" set "PYW=%%~dpDpythonw.exe"
goto :run

:venv
set "PYW=%~dp0.venv\Scripts\pythonw.exe"

:run
if "%~1"=="" goto :run_plain
start "" "%PYW%" -m voxhound gui "%~1"
exit /b 0

:run_plain
start "" "%PYW%" -m voxhound gui
exit /b 0

:noenv
echo.
echo VoxHound runtime not found.
echo One-time setup:
echo   python -m venv .venv
echo   .venv\Scripts\python -m pip install -e ".[gui]"
echo.
pause
exit /b 1
