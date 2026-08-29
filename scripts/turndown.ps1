<#
.SYNOPSIS
  scripts/turndown.ps1 — Clean down for pure Docker & Host lifecycle on Windows.
.DESCRIPTION
  Stops Docker containers, cleans host processes, verifies port 8000, removes PID files, rotates logs.
.EXAMPLE
  .\scripts	urndown.ps1
  .\scripts	urndown.ps1 -Check
  .\scripts	urndown.ps1 -HostMode
  .\scripts	urndown.ps1 -Port 8000
#>

[CmdletBinding()]
param (
    [switch]$Check,
    [switch]$HostMode,
    [switch]$Wheelhouse,
    [switch]$Native,
    [switch]$UseHub,
    [string]$Image = "blackpool25/ciphercrest:demo",
    [int]$Port = 8000,
    [switch]$Help
)

$ErrorActionPreference = "Continue"

if ($Help) {
    Write-Host "Usage: .\scripts	urndown.ps1 [-Check] [-HostMode] [-Port 8000]" -ForegroundColor Cyan
    Write-Host "  -Check     Dry-run idempotent verification only (no services stopped)"
    Write-Host "  -HostMode  Clean down host processes (PIDs and port 8000)"
    Write-Host "  -Port N    Port to verify/free (default: 8000)"
    exit 0
}

$RootDir = Split-Path -Parent $PSScriptRoot
Set-Location $RootDir

$LogDir = Join-Path $RootDir "logs"
$TmpDir = Join-Path $RootDir ".tmp"

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
if (-not (Test-Path $TmpDir)) { New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null }

$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = Join-Path $LogDir "turndown_$ts.log"
New-Item -ItemType File -Path $LogFile -Force | Out-Null

function Write-Ok($msg) { Write-Host "[ok] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[warn] $msg" -ForegroundColor Yellow }
function Write-Info($msg) { Write-Host "[info] $msg" -ForegroundColor DarkGray }

if ($Check) {
    Write-Host "=== turndown -Check (idempotent) ===" -ForegroundColor Cyan
    Write-Ok "would run: docker compose down"
    Write-Ok "would run: docker compose --profile lab down (if lab up)"
    
    try {
        $conn = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
        if ($conn) {
            Write-Info "port $Port currently in use (PID: $($conn.OwningProcess[0]))"
        } else {
            Write-Ok "port $Port free (Get-NetTCPConnection)"
        }
    } catch {
        Write-Info "Get-NetTCPConnection skipped"
    }
    
    Write-Ok "would rm $TmpDir\*.pid if exist"
    Write-Ok "log rotation: keep last 10, prune older than 7d in $LogDir"
    Write-Ok "turndown -Check done (idempotent, no changes)"
    exit 0
}

Write-Host "=== turndown clean ===" -ForegroundColor Cyan

# ── 1. Docker down ──
if (Get-Command docker -ErrorAction SilentlyContinue) {
    Write-Host "docker compose down"
    docker compose down 2>&1 | Out-Null
    Write-Host "docker compose --profile lab down"
    docker compose --profile lab down 2>&1 | Out-Null
} else {
    Write-Warn "docker not found — skip docker compose down"
}

# ── 2. Clean PID files & Host Processes ──
$pidFiles = Get-ChildItem -Path $TmpDir -Filter "*.pid" -ErrorAction SilentlyContinue
foreach ($f in $pidFiles) {
    try {
        $pidNum = Get-Content $f.FullName -ErrorAction SilentlyContinue
        if ($pidNum) {
            Stop-Process -Id $pidNum -Force -ErrorAction SilentlyContinue
            Write-Host "stopped pid $pidNum ($f.Name)"
        }
    } catch {}
    Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue
}
Write-Ok ".tmp pid files cleaned"

# ── 3. Free Port if lingering ──
try {
    $conn = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    if ($conn) {
        foreach ($p in $conn.OwningProcess) {
            try {
                Stop-Process -Id $p -Force -ErrorAction SilentlyContinue
                Write-Host "terminating process on port $Port (PID: $p)"
            } catch {}
        }
        Start-Sleep -Milliseconds 500
    }
} catch {}

# ── 4. Verify Port Status ──
try {
    $connAfter = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    if ($connAfter) {
        Write-Warn "port $Port still in use"
    } else {
        Write-Ok "port $Port cleaned"
    }
} catch {
    Write-Ok "port $Port free"
}

# ── 5. Log Rotation ──
try {
    $limit = (Get-Date).AddDays(-7)
    Get-ChildItem -Path $LogDir -Filter "turnup_*.log" | Where-Object { $_.LastWriteTime -lt $limit } | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path $LogDir -Filter "turndown_*.log" | Where-Object { $_.LastWriteTime -lt $limit } | Remove-Item -Force -ErrorAction SilentlyContinue
    
    $oldTurnups = Get-ChildItem -Path $LogDir -Filter "turnup_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -Skip 10
    foreach ($old in $oldTurnups) { Remove-Item $old.FullName -Force -ErrorAction SilentlyContinue }
    
    $oldTurndowns = Get-ChildItem -Path $LogDir -Filter "turndown_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -Skip 10
    foreach ($old in $oldTurndowns) { Remove-Item $old.FullName -Force -ErrorAction SilentlyContinue }
    
    Write-Ok "log rotation done (keep last 10, prune older than 7d)"
} catch {}

Write-Host "=== turndown done ===" -ForegroundColor Cyan
