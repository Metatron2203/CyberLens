$ErrorActionPreference = "Stop"
$root = (Resolve-Path "$PSScriptRoot\..").Path

Write-Host "=== CyberLens V0.3 - Instalacion completa ===" -ForegroundColor Cyan
Push-Location "$root\backend"
try {
    python --version
    if ($LASTEXITCODE -ne 0) { throw "Python 3.11+ no disponible." }
    if (-not (Test-Path ".venv\Scripts\python.exe")) {
        python -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw "No se pudo crear el entorno virtual." }
    }
    & ".\.venv\Scripts\python.exe" -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) { throw "Error actualizando pip." }
    & ".\.venv\Scripts\python.exe" -m pip install -r requirements-ml.txt
    if ($LASTEXITCODE -ne 0) { throw "No se instalaron las dependencias de Machine Learning." }
} finally { Pop-Location }

Push-Location "$root\frontend"
try {
    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
        if (Get-Command fnm -ErrorAction SilentlyContinue) {
            fnm env --use-on-cd --shell powershell | Out-String | Invoke-Expression
            fnm use 24
        }
    }
    npm --version
    if ($LASTEXITCODE -ne 0) { throw "npm no disponible. Activa fnm use 24." }
    npm install
    if ($LASTEXITCODE -ne 0) { throw "Fallo npm install." }
} finally { Pop-Location }
Write-Host "=== Instalacion V0.3 finalizada. Continúas en la carpeta original. ===" -ForegroundColor Green
Write-Host "Prueba .\scripts\check_windows.ps1, luego .\scripts\run_dev_windows.ps1" -ForegroundColor Cyan
