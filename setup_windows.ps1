<#
.SYNOPSIS
    One-shot setup of this project on a fresh Windows machine.

.DESCRIPTION
    Creates a local virtual environment (.venv), installs dependencies,
    retrains the ML model against the Python/scikit-learn versions that were
    just installed, and runs the test suite.

    Retraining matters: the committed model (.joblib) is a pickle, and
    scikit-learn pickles can fail to load -- or warn -- on a different
    scikit-learn version than the one that wrote them. Training takes a
    few seconds and guarantees the model matches this machine.

.PARAMETER SkipTrain
    Keep the committed pre-trained model instead of retraining.

.PARAMETER SkipTests
    Don't run pytest at the end.

.PARAMETER Demo
    Also write sample data to temporal_state.json so the dashboard and
    terminal report have something to show without waiting on a live scan.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1 -Demo
#>
param(
    [switch]$SkipTrain,
    [switch]$SkipTests,
    [switch]$Demo
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }

# --- 1. Find a supported Python (3.10 - 3.12) -------------------------------
Step "Looking for Python 3.10-3.12"
$python = $null
foreach ($v in @("3.12", "3.11", "3.10")) {
    try {
        & py "-$v" --version *> $null
        if ($LASTEXITCODE -eq 0) { $python = @("py", "-$v"); break }
    } catch {
        break  # py launcher not installed; fall back to plain python below
    }
}
if (-not $python) {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) {
        $ver = & python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
        if ($ver -in @("3.10", "3.11", "3.12")) { $python = @("python") }
    }
}
if (-not $python) {
    Write-Host "No Python 3.10-3.12 found." -ForegroundColor Red
    Write-Host "Install Python 3.11 from https://www.python.org/downloads/windows/"
    Write-Host "(tick 'Add python.exe to PATH' / keep the 'py launcher' option), then re-run this script."
    exit 1
}
Write-Host ("Using: " + ($python -join " "))

function Invoke-Python {
    $exe = $python[0]
    $pre = @()
    if ($python.Count -gt 1) { $pre = $python[1..($python.Count - 1)] }
    & $exe @pre @args
    if ($LASTEXITCODE -ne 0) { throw "Command failed: $($python -join ' ') $args" }
}

# --- 2. Virtual environment --------------------------------------------------
$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Step "Creating virtual environment (.venv)"
    Invoke-Python -m venv .venv
} else {
    Step "Reusing existing .venv"
}

# --- 3. Dependencies ---------------------------------------------------------
Step "Installing dependencies"
& $venvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed" }
& $venvPython -m pip install -r requirements-dev.txt
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

# --- 4. ML model -------------------------------------------------------------
if ($SkipTrain) {
    Step "Skipping retrain (using committed model)"
} else {
    Step "Training ML model on the ClaMP dataset"
    & $venvPython train_model.py
    if ($LASTEXITCODE -ne 0) { throw "train_model.py failed" }
}

# --- 5. Tests ----------------------------------------------------------------
if ($SkipTests) {
    Step "Skipping tests"
} else {
    Step "Running tests"
    & $venvPython -m pytest -q
    if ($LASTEXITCODE -ne 0) {
        # Not fatal: the most common cause on a fresh machine is
        # tests/test_windows_signing.py needing PowerShell 7 (pwsh.exe),
        # which has nothing to do with whether the demo works.
        Write-Host "WARNING: some tests failed -- see output above and the Troubleshooting table in PRESENTATION.md." -ForegroundColor Yellow
    }
}

# --- 6. Optional demo data ---------------------------------------------------
if ($Demo) {
    Step "Writing sample data for the dashboard"
    & $venvPython seed_demo_state.py
    if ($LASTEXITCODE -ne 0) { throw "seed_demo_state.py failed" }
}

Write-Host "`nSetup complete." -ForegroundColor Green
Write-Host "  Dashboard:  .\start_dashboard.bat   (http://127.0.0.1:5000)"
Write-Host "  Monitor:    .\start_monitor.bat     (live scanning, Windows only)"
Write-Host "  Full guide: PRESENTATION.md"
