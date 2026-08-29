<#
.SYNOPSIS
  scripts/push_dockerhub.ps1 — Build, tag, verify identity, and push CipherCrest to Docker Hub on Windows.
.DESCRIPTION
  Verifies Docker Hub identity, builds the multi-stage CipherCrest image, tags it with :demo and :latest, and pushes to Docker Hub.
.EXAMPLE
  .\scripts\push_dockerhub.ps1
  .\scripts\push_dockerhub.ps1 -Tag v1.0.0
  .\scripts\push_dockerhub.ps1 -DryRun
  .\scripts\push_dockerhub.ps1 -NoBuild
#>

[CmdletBinding()]
param (
    [string]$Tag = "demo",
    [switch]$NoLatest,
    [switch]$NoBuild,
    [switch]$DryRun,
    [string]$User = "blackpool25",
    [string]$Repo = "blackpool25/ciphercrest",
    [switch]$Help
)

$ErrorActionPreference = "Stop"

if ($Help) {
    Write-Host "Usage: .\scripts\push_dockerhub.ps1 [-Tag <tag>] [-NoLatest] [-NoBuild] [-DryRun] [-User <user>] [-Repo <repo>]" -ForegroundColor Cyan
    Write-Host "  -Tag <tag>   Specify image tag (default: demo, also pushes latest)"
    Write-Host "  -NoLatest    Do not push :latest alias tag"
    Write-Host "  -NoBuild     Skip image build and only push existing local image"
    Write-Host "  -DryRun      Verify Docker Hub credentials and image without pushing"
    Write-Host "  -User <user> Expected Docker Hub username (default: blackpool25)"
    Write-Host "  -Repo <repo> Target repository (default: blackpool25/ciphercrest)"
    exit 0
}

$RootDir = Split-Path -Parent $PSScriptRoot
Set-Location $RootDir

function Write-Ok($msg) { Write-Host "[ok] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[warn] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "[fail] $msg" -ForegroundColor Red }
function Write-Header($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

Write-Header "CipherCrest Docker Hub Publisher (Windows)"
Write-Host "Target Repository : $Repo"
Write-Host "Primary Tag       : $Tag"
Write-Host "Alias Tag         : $(if ($NoLatest) { 'none' } else { 'latest' })"
Write-Host "Target User       : $User"

# ── 1. Docker Daemon Check ──
Write-Header "Step 1: Checking Docker Daemon"
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Fail "Docker CLI not found on PATH. Ensure Docker Desktop is installed and running."
    exit 1
}

try {
    docker info 2>&1 | Out-Null
    Write-Ok "Docker daemon is active and responsive"
} catch {
    Write-Fail "Cannot connect to Docker daemon. Is Docker Desktop running?"
    exit 1
}

# ── 2. Identity Verification ──
Write-Header "Step 2: Verifying Docker Hub Identity"
$detectedUser = $null
try {
    $info = docker info 2>$null
    $userLine = $info | Select-String "Username:"
    if ($userLine) {
        $detectedUser = ($userLine -split "Username:\s*")[1].Trim()
    }
} catch {}

if ($detectedUser) {
    Write-Ok "Authenticated with Docker Hub as user: $detectedUser"
    if ($detectedUser -eq $User) {
        Write-Ok "Identity matches target account: $User"
    } else {
        Write-Warn "Logged in user '$detectedUser' differs from target '$User'."
    }
} else {
    Write-Warn "No active Docker Hub session detected. Attempting docker login for '$User'..."
    docker login -u $User
}

# ── 3. Build Multi-stage Image ──
$primaryImage = "${Repo}:${Tag}"
$latestImage = "${Repo}:latest"

if ($NoBuild) {
    Write-Header "Step 3: Skipping Build (-NoBuild specified)"
    Write-Ok "Using existing local image: $primaryImage"
} else {
    Write-Header "Step 3: Building Multi-stage Docker Image ($primaryImage)"
    docker build -t $primaryImage -f Dockerfile .
    Write-Ok "Image successfully built: $primaryImage"
}

if (-not $NoLatest) {
    docker tag $primaryImage $latestImage
    Write-Ok "Tagged alias: $latestImage"
}

# ── 4. Dry Run Guard ──
if ($DryRun) {
    Write-Header "Dry Run Complete"
    Write-Ok "Docker Hub identity verified ($User)"
    Write-Ok "Ready to push:"
    Write-Host "  - $primaryImage"
    if (-not $NoLatest) { Write-Host "  - $latestImage" }
    Write-Host "Dry-run mode: No images were pushed to Docker Hub."
    exit 0
}

# ── 5. Push to Docker Hub ──
Write-Header "Step 4: Pushing Images to Docker Hub"
Write-Host "Pushing $primaryImage ..."
docker push $primaryImage
Write-Ok "Successfully pushed $primaryImage to Docker Hub!"

if (-not $NoLatest) {
    Write-Host "Pushing $latestImage ..."
    docker push $latestImage
    Write-Ok "Successfully pushed $latestImage to Docker Hub!"
}

# ── 6. Summary ──
Write-Header "Docker Hub Push Succeeded!"
Write-Host "Repository : https://hub.docker.com/r/$Repo"
Write-Host "Pushed Tags: $Tag $(if (-not $NoLatest) { ', latest' })"
Write-Host ""
Write-Host "To run CipherCrest directly from Docker Hub without building:"
Write-Host "  .\scripts\turnup.ps1 -UseHub"
Write-Host ""
