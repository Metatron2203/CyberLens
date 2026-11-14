$ErrorActionPreference = "Stop"
$root = (Resolve-Path "$PSScriptRoot\..").Path
if (-not (Test-Path "$root\backend\.venv\Scripts\python.exe")) { throw "Falta el entorno virtual de Python." }
if (-not (Test-Path "$root\frontend\node_modules")) { throw "Falta npm install en frontend." }

Write-Host "=== 1/2: tests backend + Machine Learning ===" -ForegroundColor Cyan
Push-Location "$root\backend"
try {
    & ".\.venv\Scripts\python.exe" -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw "Fallo la suite de Python." }
} finally { Pop-Location }

Write-Host "=== 2/2: build Next.js ===" -ForegroundColor Cyan
Push-Location "$root\frontend"
try {
    if (-not (Get-Command npm -ErrorAction SilentlyContinue) -and (Get-Command fnm -ErrorAction SilentlyContinue)) {
        fnm env --use-on-cd --shell powershell | Out-String | Invoke-Expression
        fnm use 24
    }
    npm run build
    if ($LASTEXITCODE -ne 0) { throw "Fallo la compilacion de Next.js." }
} finally { Pop-Location }
Write-Host "=== Verificacion V0.3 completada; carpeta original conservada ===" -ForegroundColor Green
