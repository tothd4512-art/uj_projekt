@echo off
setlocal
echo Akkor hasznald, ha a telefon MAR bootloader-fastboot modban van.
echo Ez a program NEM inditja ujra a telefont. A fastbootd nem ugyanaz.
echo.
call "%~dp0TCL505-Diagnosztika.cmd" --mode fastboot %*
set "RESULT=%ERRORLEVEL%"
endlocal & exit /b %RESULT%
