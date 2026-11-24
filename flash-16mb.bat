@echo off
REM Flash firmware + LittleFS to a 16 MB ESP32-S3 over USB.
REM Optional first argument = COM port (e.g. flash-16mb.bat COM5).
setlocal
set PORTARG=
if not "%~1"=="" set PORTARG=--upload-port %~1

if not exist src\secrets.h (
  echo [!] src\secrets.h missing. Run: copy src\secrets.example.h src\secrets.h
  exit /b 1
)
if not exist data\blocklist.bin (
  echo [*] No data\blocklist.bin - building one from CN sources...
  python tools\build_cn_blocklist.py || exit /b 1
)

echo [1/2] Flashing firmware ...
python -m platformio run -e s3_16mb -t upload %PORTARG% || exit /b 1
echo [2/2] Flashing blocklist filesystem ...
python -m platformio run -e s3_16mb -t uploadfs %PORTARG% || exit /b 1
echo.
echo Done. Opening the serial monitor (Ctrl+C to quit) ...
python -m platformio device monitor %PORTARG%
