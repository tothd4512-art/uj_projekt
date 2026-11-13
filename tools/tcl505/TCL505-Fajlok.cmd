@echo off
setlocal
chcp 65001 >nul 2>&1
cd /d "%~dp0"
set "PY="
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)" >nul 2>&1
if not errorlevel 1 set "PY=py -3"
if not defined PY (
    python -c "import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)" >nul 2>&1
    if not errorlevel 1 set "PY=python"
)
if not defined PY (
    echo Python 3.9 vagy ujabb szukseges. Lasd: README.hu.md
    echo Nem tortent automatikus telepitees vagy letoltes.
    pause
    exit /b 2
)
echo TCL 505 / T509K - CELZOTT, CSAK OLVASO FAJLMASOLAS
echo Csak engedelylistas rendszerfajlokat masol a gepre. Nem tolt fel.
echo Nem ker rootot, nem ir a telefonra, nem olvas nyers particiot.
echo.
%PY% "%~dp0tcl505_files.py" %*
set "RESULT=%ERRORLEVEL%"
echo.
pause
exit /b %RESULT%
