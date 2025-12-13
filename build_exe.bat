@echo off
echo Installing requirements...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo Failed to install requirements.
    pause
    exit /b
)

echo Building executable...
if exist app.ico (
    echo Found app.ico, using it as icon.
    pyinstaller --onefile --noconsole --name QuickAsset --icon=app.ico --add-data "app.ico;." main.py
) else (
    echo app.ico not found, building with default icon.
    pyinstaller --onefile --noconsole --name QuickAsset main.py
)
if %errorlevel% neq 0 (
    echo Failed to build executable.
    pause
    exit /b
)

echo Build complete. The executable is in the 'dist' folder.
pause
