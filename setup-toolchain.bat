@echo off
REM ---------------------------------------------------------------------------
REM  One-time Windows toolchain setup for esp32s3-adblock.
REM
REM  What this installs:
REM    1. PlatformIO Core (pip)
REM    2. The esptool "contrib" deps from a China-friendly PyPI mirror
REM       (cryptography etc.) - PlatformIO's own post-install step pulls these
REM       from pypi.org and routinely stalls on mainland networks.
REM
REM  Everything else (xtensa toolchain, Arduino core, esptool) is downloaded by
REM  PlatformIO from dl.registry.platformio.org on the first `pio run`.
REM
REM  Usage:  setup-toolchain.bat            (defaults to the Tsinghua PyPI mirror)
REM          setup-toolchain.bat https://pypi.org/simple
REM ---------------------------------------------------------------------------

setlocal
set MIRROR=%~1
if "%MIRROR%"=="" set MIRROR=https://pypi.tuna.tsinghua.edu.cn/simple

where python >nul 2>nul
if errorlevel 1 (
  echo [!] Python not found on PATH. Install Python 3.10+ first.
  exit /b 1
)

echo [1/3] Installing PlatformIO Core ...
python -m pip install -U platformio -i %MIRROR%
if errorlevel 1 goto :fail

echo [2/3] Checking the esptool contrib deps ...
set CONTRIB=%USERPROFILE%\.platformio\packages\tool-esptoolpy\_contrib
python -m pip install -t "%CONTRIB%" -i %MIRROR% ^
  "cryptography~=45.0.3" "ecdsa~=0.19.1" "bitstring~=4.3.1" ^
  "reedsolo~=1.7.0" "intelhex~=2.3.0"
if errorlevel 1 goto :fail

echo [3/3] Verifying PlatformIO ...
python -m platformio --version
if errorlevel 1 goto :fail

echo.
echo Done. Next steps:
echo   copy src\secrets.example.h src\secrets.h   ^&^& edit it
echo   python tools\build_blocklist.py data\blocklist.bin
echo   python -m platformio run -e s3_16mb -t upload
echo   python -m platformio run -e s3_16mb -t uploadfs
exit /b 0

:fail
echo [!] A step failed. If the mirror is unreachable, try:
echo     setup-toolchain.bat https://pypi.org/simple
exit /b 1
