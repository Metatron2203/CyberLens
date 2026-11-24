$ErrorActionPreference = "Stop"
$root = (Resolve-Path "$PSScriptRoot\..").Path
if (-not (Test-Path "$root\backend\.venv\Scripts\python.exe")) { throw "Ejecuta primero install_windows.ps1" }
if (-not (Test-Path "$root\frontend\node_modules")) { throw "Falta frontend/node_modules" }

$backendCommand = "Set-Location -LiteralPath '$root\backend'; & '.\.venv\Scripts\python.exe' -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000"
$frontendCommand = "Set-Location -LiteralPath '$root\frontend'; if (Get-Command fnm -ErrorAction SilentlyContinue) { fnm env --use-on-cd --shell powershell | Out-String | Invoke-Expression; fnm use 24 | Out-Null }; npm run dev"
Start-Process powershell -ArgumentList @("-NoExit", "-Command", $backendCommand)
Start-Process powershell -ArgumentList @("-NoExit", "-Command", $frontendCommand)
Write-Host "CyberLens V0.4: http://localhost:3000 | API: http://localhost:8000 | ML: http://localhost:8000/api/ml/status" -ForegroundColor Green
