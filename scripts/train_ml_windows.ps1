param(
    [switch]$AcademicFeeds,
    [switch]$AcceptAcademicTerms,
    [string]$PhishingCsv,
    [string]$LegitimateCsv,
    [ValidateRange(25,10000)][int]$MaxPerClass = 800
)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path "$PSScriptRoot\..").Path
Push-Location "$root\backend"
try {
    if (-not (Test-Path ".venv\Scripts\python.exe")) { throw "Primero instala CyberLens V0.3." }
    $argsList = @("-m", "ml_scripts.train", "--max-per-class", "$MaxPerClass")
    if ($AcademicFeeds) {
        if (-not $AcceptAcademicTerms) {
            throw "Revisa los terminos de OpenPhish/Tranco y vuelve a ejecutar con -AcceptAcademicTerms (solo investigacion)."
        }
        $argsList += @("--academic-feeds", "--accept-academic-terms")
    } elseif ($PhishingCsv -and $LegitimateCsv) {
        $argsList += @("--phishing", $PhishingCsv, "--legitimate", $LegitimateCsv)
    } else {
        throw "Uso: .\scripts\train_ml_windows.ps1 -AcademicFeeds -AcceptAcademicTerms  O  -PhishingCsv ruta -LegitimateCsv ruta"
    }
    & ".\.venv\Scripts\python.exe" @argsList
    if ($LASTEXITCODE -ne 0) { throw "Fallo el entrenamiento; revisa la salida anterior." }
} finally { Pop-Location }
Write-Host "Modelo creado localmente; analiza una URL de nuevo en CyberLens para ver la salida ML." -ForegroundColor Green
