@echo off
echo Installing requirements...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo Failed to install requirements.
    pause
    exit /b
)

echo Building executable...
pyinstaller --clean QuickITAsset.spec
if %errorlevel% neq 0 (
    echo Failed to build executable.
    pause
    exit /b
)

echo Build complete. The executable is in the 'dist' folder.
pause
