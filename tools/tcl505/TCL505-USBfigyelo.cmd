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
echo TCL 505 / T509K - PASSZIV USB/PNP FIGYELO
echo Csak Windows PnP esemenyeket es VID/PID adatot figyel. Nem tolt fel.
echo Nem nyit meg eszkozt, nem telepit drivert, nem ir es nem inditja ujra a telefont.
echo A telefon modjat kezzel allitsd; a program nem probal gombkombinaciot.
echo.
%PY% "%~dp0tcl505_usb_watch.py" %*
set "RESULT=%ERRORLEVEL%"
echo.
pause
exit /b %RESULT%
