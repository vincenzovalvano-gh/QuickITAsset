function Get-RealPythonPath {
    # 1. Try 'py' launcher
    if (Get-Command py -ErrorAction SilentlyContinue) {
        $pyPath = py -c "import sys; print(sys.executable)" 2>$null
        if ($pyPath -and (Test-Path $pyPath)) {
            return $pyPath
        }
    }

    # 2. Check standard install locations
    $commonPaths = @(
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python39\python.exe",
        "C:\Python312\python.exe",
        "C:\Python311\python.exe",
        "C:\Python310\python.exe"
    )

    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            return $path
        }
    }

    # 3. Check PATH but filter out WindowsApps (Store shim)
    $pythonCommands = Get-Command python -ErrorAction SilentlyContinue -All
    foreach ($cmd in $pythonCommands) {
        if ($cmd.Source -notmatch "WindowsApps") {
            return $cmd.Source
        }
    }

    return $null
}

Write-Host "Checking for Python..."
$pythonExe = Get-RealPythonPath

if (-not $pythonExe) {
    Write-Host "Python not found or only Windows Store shim detected."
    Write-Host "Attempting to install via Winget..."
    winget install -e --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Python installed successfully."
        # Try to find it again in the default location
        $pythonExe = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
    } else {
        Write-Host "Failed to install Python via Winget."
        Write-Host "Please install Python manually from https://www.python.org/downloads/"
        Write-Host "IMPORTANT: Check 'Add Python to PATH' during installation."
        exit
    }
}

if (-not $pythonExe -or -not (Test-Path $pythonExe)) {
    Write-Host "Could not locate Python executable."
    Write-Host "Please install Python manually from https://www.python.org/downloads/"
    Write-Host "IMPORTANT: Check 'Add Python to PATH' during installation."
    exit
}

Write-Host "Using Python at: $pythonExe"

Write-Host "Installing dependencies..."
& $pythonExe -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to install dependencies."
    exit
}

Write-Host "Building executable..."
if (Test-Path "app.ico") {
    Write-Host "Found app.ico, using it as icon."
    & $pythonExe -m PyInstaller --onefile --noconsole --name QuickAsset --icon=app.ico --add-data "app.ico;." main.py
} else {
    Write-Host "app.ico not found, building with default icon."
    & $pythonExe -m PyInstaller --onefile --noconsole --name QuickAsset main.py
}
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to build executable."
    exit
}

Write-Host "Build complete! The executable is in the 'dist' folder."
Write-Host "You can now run dist\QuickAsset.exe"
Pause
