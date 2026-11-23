@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title Cisco Port Mapper

rem =====================================================================
rem  Cisco Port Mapper launcher
rem    1. finds Python 3 (installs it with winget when it is missing)
rem    2. makes sure an SSH client exists (downloads plink.exe once)
rem    3. starts the GUI
rem  No Python packages are needed at runtime.
rem =====================================================================

set "PY="

py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>nul
if not errorlevel 1 set "PY=py -3"
if defined PY goto have_python

rem A plain "python" can be the broken Microsoft Store alias; test it first.
python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>nul
if not errorlevel 1 set "PY=python"
if defined PY goto have_python

call :find_installed_python
if defined PY goto have_python

echo.
echo Python 3 was not found on this PC.
where winget >nul 2>nul
if errorlevel 1 goto no_python

echo Installing Python 3 with winget (internet access is required)...
winget install --id Python.Python.3.13 -e --source winget --accept-package-agreements --accept-source-agreements
if errorlevel 1 winget install --id Python.Python.3.12 -e --source winget --accept-package-agreements --accept-source-agreements
if errorlevel 1 winget install --id Python.Python.3.11 -e --source winget --accept-package-agreements --accept-source-agreements

rem winget installs into the user profile; PATH is not refreshed in this
rem window, so look for python.exe directly.
call :find_installed_python
if not defined PY goto no_python
goto have_python

:no_python
echo.
echo Install Python 3.9 or newer from:
echo     https://www.python.org/downloads/windows/
echo Tick "Add python.exe to PATH" during setup, then run this file again.
echo.
pause
exit /b 1

:have_python
echo Using Python: %PY%
%PY% -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>nul
if errorlevel 1 (
    echo Python 3.9 or newer is required.
    echo Update Python from https://www.python.org/downloads/windows/
    pause
    exit /b 1
)

rem ---- SSH client: plink.exe next to the program, or Windows OpenSSH ----
%PY% prereq.py --check >nul 2>nul
if errorlevel 1 (
    echo.
    echo No SSH client found. Downloading the official plink.exe ...
    %PY% prereq.py --install-plink
    if errorlevel 1 (
        echo.
        echo plink.exe could not be downloaded automatically.
        echo The program still starts - use the "Setup..." button.
        echo.
    )
)

%PY% app.py
if errorlevel 1 pause
exit /b 0

rem ---------------------------------------------------------------------
rem Look for a Python installed by winget / the official installer even
rem when the current PATH does not know about it yet.
:find_installed_python
for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
    if not defined PY (
        "%%~fD\python.exe" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>nul
        if not errorlevel 1 set "PY="%%~fD\python.exe""
    )
)
if defined PY exit /b 0
for /d %%D in ("%ProgramFiles%\Python3*") do (
    if not defined PY (
        "%%~fD\python.exe" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>nul
        if not errorlevel 1 set "PY="%%~fD\python.exe""
    )
)
exit /b 0
