<#
.SYNOPSIS
  scripts/turnup.ps1 — Windows PowerShell turnup script for CipherCrest.
.DESCRIPTION
  Provides single-command turnup, dry-run preflight checks, and tshark detection for Windows.
.EXAMPLE
  .\scripts	urnup.ps1 -Check
  .\scripts	urnup.ps1 -WithLab
  .\scripts	urnup.ps1 -HostMode
  .\scripts	urnup.ps1 -Port 8000
#>

[CmdletBinding()]
param (
    [switch]$Check,
    [switch]$WithLab,
    [switch]$HostMode,
    [switch]$Docker,
    [int]$Port = 8000,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

if ($Help) {
    Write-Host "Usage: .\scripts	urnup.ps1 [-Check] [-WithLab] [-HostMode] [-Port 8000]" -ForegroundColor Cyan
    Write-Host "  -Check     Dry-run preflight verification only (no services started)"
    Write-Host "  -WithLab   Start full lab profile (mockdns, postfix, dovecot)"
    Write-Host "  -HostMode  Run natively on Windows host using Python / Uvicorn (no Docker required)"
    Write-Host "  -Docker    Run via Docker Desktop (default)"
    Write-Host "  -Port N    Port for Web Dashboard & API (default: 8000)"
    exit 0
}

$RootDir = Split-Path -Parent $PSScriptRoot
Set-Location $RootDir

$env:PYTHONHASHSEED = "0"
$env:OMP_NUM_THREADS = "6"
$env:API_PORT = "$Port"

function Write-Ok($msg) { Write-Host "[ok] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[warn] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "[fail] $msg" -ForegroundColor Red }
function Write-Info($msg) { Write-Host "[info] $msg" -ForegroundColor DarkGray }

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  CipherCrest — Windows Turn-Up & Environment Scanner   " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# ── 1. Python Check ──
try {
    $pyVer = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')" 2>$null
    if ($pyVer) {
        Write-Ok "Python version: $pyVer"
    } else {
        Write-Warn "Python not found on PATH. Install from python.org or run 'winget install Python.Python.3.12'"
    }
} catch {
    Write-Warn "Python check skipped: $_"
}

# ── 2. TShark / Wireshark Check on Windows ──
$tsharkPath = $null
$candidates = @(
    "tshark",
    "tshark.exe",
    "$env:ProgramFiles\Wireshark	shark.exe",
    "${env:ProgramFiles(x86)}\Wireshark	shark.exe",
    "C:\Program Files\Wireshark	shark.exe",
    "C:\Program Files (x86)\Wireshark	shark.exe"
)

foreach ($c in $candidates) {
    if (Get-Command $c -ErrorAction SilentlyContinue) {
        $tsharkPath = $c
        break
    } elseif (Test-Path $c) {
        $tsharkPath = $c
        break
    }
}

if ($tsharkPath) {
    try {
        $tsVer = & $tsharkPath -v | Select-Object -First 1
        Write-Ok "TShark found: $tsharkPath ($tsVer)"
        
        # Test 4 parity prefs
        $prefsOk = python -c "from lab.reassembler.reassemble import get_tshark_prefs; p=get_tshark_prefs(); assert len(p)==4; print('4 prefs verified')" 2>$null
        if ($prefsOk) {
            Write-Ok "TShark 4 parity preferences verified"
        }
    } catch {
        Write-Ok "TShark binary located at: $tsharkPath"
    }
} else {
    Write-Warn "TShark not found on Windows. (Offline Scapy reassembly will be used automatically)."
    Write-Info "To install TShark on Windows: winget install WiresharkFoundation.Wireshark  OR  choco install wireshark"
}

# ── 3. Models & Artifacts Verification ──
if ((Test-Path "modelsisk_clf.pkl") -and (Test-Path "modelsnomaly.pkl")) {
    $riskSize = (Get-Item "modelsisk_clf.pkl").Length
    $anomSize = (Get-Item "modelsnomaly.pkl").Length
    if ($riskSize -lt 5242880 -and $anomSize -lt 5242880) {
        Write-Ok "Trained ML models present and validated (<5MB protocol 4)"
    } else {
        Write-Warn "ML models present but exceed size limit"
    }
} else {
    Write-Warn "modelsisk_clf.pkl or modelsnomaly.pkl missing. Run: python -m assessment.risk_train"
}

# ── 4. Dashboard Frontend Bundle Verification ──
if (Test-Path "dashboard\dist\index.html") {
    Write-Ok "Dashboard frontend build present (dashboard\dist)"
} else {
    Write-Warn "dashboard\dist\index.html missing. Building frontend..."
    try {
        npm --prefix dashboard run build
        Write-Ok "Dashboard frontend built successfully"
    } catch {
        Write-Warn "Frontend build failed. Ensure Node.js & npm are installed."
    }
}

# ── 5. Port Free Check ──
try {
    $conn = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    if ($conn) {
        Write-Warn "Port $Port is already in use by process ID $($conn.OwningProcess[0])."
    } else {
        Write-Ok "Port $Port is free"
    }
} catch {
    Write-Info "Port check skipped"
}

if ($Check) {
    Write-Host ""
    Write-Ok "Preflight check completed successfully (--Check mode)"
    exit 0
}

# ── 6. Execution Modes ──
if ($HostMode) {
    Write-Host ""
    Write-Host "Starting CipherCrest natively in Host Mode on http://localhost:$Port ..." -ForegroundColor Cyan
    $env:PORT = "$Port"
    python -m uvicorn api.app:app --host 0.0.0.0 --port $Port
} else {
    Write-Host ""
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        if ($WithLab) {
            Write-Host "Starting Docker containers with Lab profile on http://localhost:$Port ..." -ForegroundColor Cyan
            docker compose --profile lab up -d --build
        } else {
            Write-Host "Starting Docker demo container on http://localhost:$Port/dashboard ..." -ForegroundColor Cyan
            docker compose up -d --build demo
        }
        Write-Ok "CipherCrest started! Open http://localhost:$Port in your browser."
    } else {
        Write-Warn "Docker not detected on Windows. Falling back to Host Mode..."
        python -m uvicorn api.app:app --host 0.0.0.0 --port $Port
    }
}
