@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if not errorlevel 1 (
  set "PY=py -3"
) else (
  where python >nul 2>nul
  if errorlevel 1 (
    echo Python 3 is required. Install it from https://www.python.org/downloads/windows/ and enable Tcl/Tk.
    pause
    exit /b 1
  )
  set "PY=python"
)

%PY% -m pip install --upgrade pyinstaller
if errorlevel 1 goto failed
%PY% -m PyInstaller --noconfirm --clean --onefile --windowed --name Guardian guardian_ui.py
if errorlevel 1 goto failed

echo.
echo Built: %CD%\dist\Guardian.exe
pause
exit /b 0

:failed
echo.
echo Build failed. Check the messages above.
pause
exit /b 1

