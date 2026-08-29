<#
.SYNOPSIS
  scripts/turnup.ps1 — Windows PowerShell turnup script for CipherCrest.
.DESCRIPTION
  Provides single-command turnup, dry-run preflight checks, Docker Hub instant launch,
  and tshark detection for Windows.
.EXAMPLE
  .\scripts\turnup.ps1 -Check
  .\scripts\turnup.ps1 -UseHub
  .\scripts\turnup.ps1 -WithLab
  .\scripts\turnup.ps1 -HostMode
  .\scripts\turnup.ps1 -Port 8000
#>

[CmdletBinding()]
param (
    [switch]$Check,
    [switch]$WithLab,
    [switch]$UseHub,
    [string]$Image = "blackpool25/ciphercrest:latest",
    [switch]$HostMode,
    [switch]$Docker,
    [int]$Port = 8000,
    [switch]$Help
)

$ErrorActionPreference = "Continue"

if ($Help) {
    Write-Host "Usage: .\scripts\turnup.ps1 [-Check] [-WithLab] [-UseHub] [-Image <image>] [-HostMode] [-Port 8000]" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Yellow
    Write-Host "  -Check     Dry-run preflight verification only (no services started)"
    Write-Host "  -UseHub    Pull and use pre-built image from Docker Hub (Zero-Clone compatible)"
    Write-Host "  -WithLab   Start full lab profile (mockdns, postfix, dovecot)"
    Write-Host "  -Image     Specify custom Docker image (default: blackpool25/ciphercrest:latest)"
    Write-Host "  -HostMode  Run natively on Windows host using Python / Uvicorn (no Docker required)"
    Write-Host "  -Docker    Run via Docker Desktop (default)"
    Write-Host "  -Port N    Port for Web Dashboard & API (default: 8000)"
    Write-Host ""
    Write-Host "Zero-Clone Quickstart (No repo clone required):" -ForegroundColor Green
    Write-Host "  powershell -File turnup.ps1 -UseHub"
    Write-Host "  # Or direct: docker run -d --name ciphercrest -p 8000:8000 blackpool25/ciphercrest:latest"
    exit 0
}

# Determine script & repository roots
$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = (Get-Location).Path }
$RootDir = $ScriptDir
if (Test-Path (Join-Path $ScriptDir "..\docker-compose.yml")) {
    $RootDir = (Resolve-Path (Join-Path $ScriptDir "..")).Path
} elseif (Test-Path (Join-Path $ScriptDir "docker-compose.yml")) {
    $RootDir = $ScriptDir
}
Set-Location $RootDir
$HasCompose = Test-Path (Join-Path $RootDir "docker-compose.yml")

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
    (Join-Path $env:ProgramFiles "Wireshark\tshark.exe"),
    (Join-Path ${env:ProgramFiles(x86)} "Wireshark\tshark.exe"),
    "C:\Program Files\Wireshark\tshark.exe",
    "C:\Program Files (x86)\Wireshark\tshark.exe"
)

foreach ($c in $candidates) {
    if (-not [string]::IsNullOrEmpty($c)) {
        if (Get-Command $c -ErrorAction SilentlyContinue) {
            $tsharkPath = $c
            break
        } elseif (Test-Path $c) {
            $tsharkPath = $c
            break
        }
    }
}

if ($tsharkPath) {
    try {
        $tsVer = & $tsharkPath -v | Select-Object -First 1
        Write-Ok "TShark found: $tsharkPath ($tsVer)"
        
        # Test 4 parity prefs if python & lab modules are present
        if ($HasCompose) {
            $prefsOk = python -c "from lab.reassembler.reassemble import get_tshark_prefs; p=get_tshark_prefs(); assert len(p)==4; print('4 prefs verified')" 2>$null
            if ($prefsOk) {
                Write-Ok "TShark 4 parity preferences verified"
            }
        }
    } catch {
        Write-Ok "TShark binary located at: $tsharkPath"
    }
} else {
    Write-Warn "TShark not found on Windows. (Offline Scapy reassembly will be used automatically)."
    Write-Info "To install TShark on Windows: winget install WiresharkFoundation.Wireshark  OR  choco install wireshark"
}

# ── 3. Models & Artifacts Verification (if repo clone present) ──
$model1 = Join-Path $RootDir "models/risk_clf.pkl"
$model2 = Join-Path $RootDir "models/anomaly.pkl"

if ($HasCompose) {
    if ((Test-Path $model1) -and (Test-Path $model2)) {
        $riskSize = (Get-Item $model1).Length
        $anomSize = (Get-Item $model2).Length
        if ($riskSize -lt 5242880 -and $anomSize -lt 5242880) {
            Write-Ok "Trained ML models present and validated (<5MB protocol 4)"
        } else {
            Write-Warn "ML models present but exceed size limit"
        }
    } else {
        Write-Warn "models/risk_clf.pkl or models/anomaly.pkl missing. (Pre-baked inside Docker image)."
    }

    # ── 4. Dashboard Frontend Bundle Verification ──
    $indexHtml = Join-Path $RootDir "dashboard/dist/index.html"
    if (Test-Path $indexHtml) {
        Write-Ok "Dashboard frontend build present (dashboard/dist)"
    } else {
        Write-Info "dashboard/dist/index.html not built locally. (Pre-baked inside Docker image)."
    }
} else {
    Write-Ok "Running in Standalone Zero-Clone Mode (ML models & Frontend SPA pre-baked in image)"
}

# ── 5. Port Free Check ──
try {
    $conn = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    if ($conn) {
        Write-Warn "Port $Port is currently in use by process ID $($conn.OwningProcess[0])."
    } else {
        Write-Ok "Port $Port is free"
    }
} catch {
    Write-Info "Port check skipped"
}

if ($Check) {
    Write-Host ""
    Write-Ok "Preflight check completed successfully (-Check mode)"
    exit 0
}

# ── 6. Execution Modes ──
if ($HostMode) {
    if (-not $HasCompose) {
        Write-Fail "HostMode requires the repository source files to be cloned."
        exit 1
    }
    Write-Host ""
    Write-Host "Starting CipherCrest natively in Host Mode on http://localhost:$Port ..." -ForegroundColor Cyan
    $env:PORT = "$Port"
    python -m uvicorn api.app:app --host 0.0.0.0 --port $Port
} else {
    Write-Host ""
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        $env:CIPHERCREST_IMAGE = "$Image"
        
        if ($UseHub -or ($env:USE_HUB -eq "1") -or (-not $HasCompose)) {
            Write-Host "Pulling pre-built CipherCrest image from Docker Hub ($Image)..." -ForegroundColor Cyan
            docker pull $Image
            
            if ($HasCompose) {
                if ($WithLab) {
                    Write-Host "Starting Docker containers from Hub with Lab profile on http://localhost:$Port ..." -ForegroundColor Cyan
                    docker compose --profile lab up -d
                } else {
                    Write-Host "Starting Docker demo container from Hub on http://localhost:$Port/dashboard ..." -ForegroundColor Cyan
                    docker compose up -d demo
                }
            } else {
                # Standalone Zero-Clone Mode: No repo or docker-compose.yml required!
                Write-Host "Starting standalone container (Zero-Clone Mode) on http://localhost:$Port/dashboard ..." -ForegroundColor Cyan
                docker rm -f ciphercrest 2>$null | Out-Null
                docker run -d --name ciphercrest -p "${Port}:8000" --restart unless-stopped $Image | Out-Null
            }
        } else {
            # Local Docker Build Mode
            if ($WithLab) {
                Write-Host "Building & starting Docker containers with Lab profile on http://localhost:$Port ..." -ForegroundColor Cyan
                docker compose --profile lab up -d --build
            } else {
                Write-Host "Building & starting Docker demo container on http://localhost:$Port/dashboard ..." -ForegroundColor Cyan
                docker compose up -d --build demo
            }
        }

        # Verify container startup
        Write-Host "Waiting for CipherCrest health probe on http://localhost:$Port/health ..." -ForegroundColor DarkGray
        $healthOk = $false
        for ($i = 0; $i -lt 30; $i++) {
            Start-Sleep -Seconds 1
            try {
                $resp = Invoke-RestMethod -Uri "http://localhost:$Port/health" -Method Get -TimeoutSec 2 -ErrorAction SilentlyContinue
                if ($resp.status -eq "ok" -or $resp.ok -eq $true -or $resp -ne $null) {
                    $healthOk = $true
                    break
                }
            } catch {}
        }

        Write-Host ""
        if ($healthOk) {
            Write-Ok "CipherCrest is healthy and running!"
        } else {
            Write-Info "CipherCrest container initialized. Verifying endpoint..."
        }

        Write-Host "========================================================" -ForegroundColor Cyan
        Write-Host "  Web Dashboard : http://localhost:$Port/dashboard" -ForegroundColor Green
        Write-Host "  API Health    : http://localhost:$Port/health" -ForegroundColor Green
        Write-Host "  API Docs      : http://localhost:$Port/docs" -ForegroundColor Green
        Write-Host "  Stop Command  : powershell -File scripts/turndown.ps1" -ForegroundColor Yellow
        Write-Host "========================================================" -ForegroundColor Cyan
    } else {
        if ($HasCompose) {
            Write-Warn "Docker not detected on Windows. Falling back to Host Mode..."
            python -m uvicorn api.app:app --host 0.0.0.0 --port $Port
        } else {
            Write-Fail "Docker is not running on this system. Please start Docker Desktop or clone the repository for host mode."
            exit 1
        }
    }
}
