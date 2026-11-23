@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (set "PY=py") else (set "PY=python")

rem PyInstaller is the only package needed, and only for building the exe.
%PY% -c "import PyInstaller" >nul 2>nul
if %errorlevel%==0 goto build

echo Installing PyInstaller (internet access is required)...
%PY% -m pip install --default-timeout=60 --retries 3 --prefer-binary pyinstaller
if not errorlevel 1 goto build
echo.
echo Default index failed, trying mirror-pypi.runflare.com (https) ...
%PY% -m pip install --default-timeout=60 --retries 3 --prefer-binary -i https://mirror-pypi.runflare.com/simple pyinstaller
if not errorlevel 1 goto build
echo.
echo Trying mirror-pypi.runflare.com (http) ...
%PY% -m pip install --default-timeout=60 --retries 3 --prefer-binary --trusted-host mirror-pypi.runflare.com -i http://mirror-pypi.runflare.com/simple pyinstaller
if not errorlevel 1 goto build
echo.
echo Trying pypi.tuna.tsinghua.edu.cn (http) ...
%PY% -m pip install --default-timeout=60 --retries 3 --prefer-binary --trusted-host pypi.tuna.tsinghua.edu.cn -i http://pypi.tuna.tsinghua.edu.cn/simple pyinstaller
if not errorlevel 1 goto build
echo.
echo Trying mirrors.aliyun.com (http) ...
%PY% -m pip install --default-timeout=60 --retries 3 --prefer-binary --trusted-host mirrors.aliyun.com -i http://mirrors.aliyun.com/pypi/simple/ pyinstaller
if errorlevel 1 (
    echo.
    echo Could not install PyInstaller. See README.md troubleshooting.
    pause
    exit /b 1
)

:build
%PY% -m PyInstaller --noconfirm --onefile --windowed --name CiscoPortMapper app.py
if errorlevel 1 (
    echo.
    echo The build failed. See the PyInstaller output above.
    pause
    exit /b 1
)

rem ---- runtime files that live next to the exe -------------------------
rem plink.exe is not bundled inside the exe: it must sit beside it so the
rem program can use it for password logins.  Download it once if needed.
if not exist plink.exe (
    echo.
    echo Downloading plink.exe for the dist folder ...
    %PY% prereq.py --install-plink
)
if exist plink.exe copy /y plink.exe "dist\plink.exe" >nul
if exist inventory.json copy /y inventory.json "dist\inventory.json" >nul

echo.
echo Built: dist\CiscoPortMapper.exe
if exist "dist\plink.exe" (
    echo plink.exe copied next to the exe.
) else (
    echo WARNING: plink.exe is missing. Put it next to the exe or use the
    echo          "Setup..." button inside the program.
)
echo You can edit dist\inventory.json to preset your switches.
pause
endlocal
