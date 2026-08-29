#!/usr/bin/env bash
# scripts/push_dockerhub.sh — Build, tag, verify identity, and push CipherCrest to Docker Hub
# Repo: blackpool25/ciphercrest (private/public Docker Hub repository)
# Usage:
#   bash scripts/push_dockerhub.sh [--tag <tag>] [--dry-run] [--no-build] [--help]
# Examples:
#   bash scripts/push_dockerhub.sh                # builds and pushes blackpool25/ciphercrest:demo and :latest
#   bash scripts/push_dockerhub.sh --tag v1.0.0   # builds and pushes blackpool25/ciphercrest:v1.0.0 and :latest
#   bash scripts/push_dockerhub.sh --dry-run      # verifies identity and checks build without pushing

set -uo pipefail
trap 'exit 0' PIPE

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Config
DEFAULT_REPO="blackpool25/ciphercrest"
TARGET_REPO="${DOCKER_REPO:-$DEFAULT_REPO}"
DEFAULT_USER="blackpool25"
TARGET_USER="${DOCKER_USER:-$DEFAULT_USER}"
TAG="${TAG:-latest}"
DRY_RUN=0
NO_BUILD=0
PUSH_DEMO=1

# Formatting
if [[ -t 1 ]]; then
  GREEN='\033[0;32m'
  YELLOW='\033[0;33m'
  RED='\033[0;31m'
  BLUE='\033[0;34m'
  CYAN='\033[0;36m'
  DIM='\033[0;2m'
  NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; BLUE=''; CYAN=''; DIM=''; NC=''
fi

ok(){ echo -e "${GREEN}[ok]${NC} $*"; }
warn(){ echo -e "${YELLOW}[warn]${NC} $*"; }
fail(){ echo -e "${RED}[fail]${NC} $*"; }
info(){ echo -e "${DIM}[info]${NC} $*"; }
header(){ echo -e "${CYAN}=== $* ===${NC}"; }

do_help(){
  echo "Usage: bash scripts/push_dockerhub.sh [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --tag <tag>       Specify image tag (default: latest, also pushes :demo)"
  echo "  --no-demo         Do not push :demo alias tag"
  echo "  --no-build        Skip image build and only push existing local image"
  echo "  --dry-run         Verify Docker Hub credentials and image without pushing"
  echo "  --user <name>     Expected Docker Hub username (default: blackpool25)"
  echo "  --repo <repo>     Docker Hub repo name (default: blackpool25/ciphercrest)"
  echo "  --help, -h        Show this help message"
  echo ""
  echo "Environment Variables:"
  echo "  DOCKER_REPO       Docker repository (default: blackpool25/ciphercrest)"
  echo "  DOCKER_USER       Docker Hub user (default: blackpool25)"
  echo "  TAG               Image tag (default: latest)"
}

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) TAG="$2"; shift 2 ;;
    --no-demo|--no-alias) PUSH_DEMO=0; shift ;;
    --no-build) NO_BUILD=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --user) TARGET_USER="$2"; shift 2 ;;
    --repo) TARGET_REPO="$2"; shift 2 ;;
    --help|-h) do_help; exit 0 ;;
    *) warn "Unknown argument: $1"; shift ;;
  esac
done

ALIAS_TAG="demo"
if [[ "$TAG" == "demo" ]]; then
  ALIAS_TAG="latest"
fi

header "CipherCrest Docker Hub Publisher"
echo "Target Repository : $TARGET_REPO"
echo "Primary Tag       : $TAG"
echo "Alias Tag         : $([[ $PUSH_DEMO -eq 1 ]] && echo "$ALIAS_TAG" || echo 'none')"
echo "Target User       : $TARGET_USER"
echo ""

# ── 1. Docker Daemon Check ──
header "Step 1: Checking Docker Daemon"
if ! command -v docker >/dev/null 2>&1; then
  fail "Docker CLI not found on PATH. Please install Docker or start Docker Desktop."
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  fail "Cannot connect to Docker daemon. Is Docker running?"
  exit 1
fi
ok "Docker daemon is active and responsive"
echo ""

# ── 2. Docker Hub Identity Verification ──
header "Step 2: Verifying Docker Hub Identity"
AUTH_OK=0
DETECTED_USER=""

# Method A: Check docker info output
DOCKER_INFO_USER=$(docker info 2>/dev/null | grep -i "Username:" | awk '{print $2}' || true)
if [[ -n "$DOCKER_INFO_USER" ]]; then
  DETECTED_USER="$DOCKER_INFO_USER"
fi

# Method B: Check ~/.docker/config.json for auth keys
if [[ -z "$DETECTED_USER" ]] && [[ -f "$HOME/.docker/config.json" ]]; then
  if grep -q "https://index.docker.io/v1/" "$HOME/.docker/config.json" 2>/dev/null; then
    AUTH_ENTRY=$(python3 -c "
import json, base64, sys
try:
    with open('$HOME/.docker/config.json') as f:
        data = json.load(f)
    auths = data.get('auths', {})
    hub = auths.get('https://index.docker.io/v1/', {}) or auths.get('docker.io', {})
    raw = hub.get('auth', '')
    if raw:
        user = base64.b64decode(raw).decode('utf-8').split(':')[0]
        print(user)
except Exception:
    pass
" 2>/dev/null || true)
    if [[ -n "$AUTH_ENTRY" ]]; then
      DETECTED_USER="$AUTH_ENTRY"
    fi
  fi
fi

if [[ -n "$DETECTED_USER" ]]; then
  ok "Authenticated with Docker Hub as user: ${GREEN}${DETECTED_USER}${NC}"
  if [[ "$DETECTED_USER" == "$TARGET_USER" ]]; then
    ok "Identity matches target account: $TARGET_USER"
    AUTH_OK=1
  else
    warn "Logged in user '$DETECTED_USER' differs from target '$TARGET_USER'."
    warn "Ensure you have push permissions to repository '$TARGET_REPO'."
    AUTH_OK=1
  fi
else
  warn "No active Docker Hub session detected in docker info / config.json."
  echo "Attempting login for '$TARGET_USER'..."
  if docker login -u "$TARGET_USER"; then
    ok "Successfully logged into Docker Hub as $TARGET_USER"
    AUTH_OK=1
  else
    fail "Docker login failed. Please run 'docker login' and re-run this script."
    exit 1
  fi
fi
echo ""

# ── 3. Build Multi-stage Image ──
PRIMARY_IMAGE="${TARGET_REPO}:${TAG}"
ALIAS_IMAGE="${TARGET_REPO}:${ALIAS_TAG}"

if [[ "$NO_BUILD" -eq 1 ]]; then
  header "Step 3: Skipping Build (--no-build specified)"
  if ! docker image inspect "$PRIMARY_IMAGE" >/dev/null 2>&1; then
    fail "Image '$PRIMARY_IMAGE' does not exist locally. Build it first or remove --no-build."
    exit 1
  fi
  ok "Using existing local image: $PRIMARY_IMAGE"
else
  header "Step 3: Building Multi-stage Docker Image ($PRIMARY_IMAGE)"
  echo "Context: $ROOT"
  echo "Dockerfile: $ROOT/Dockerfile"
  
  if docker build -t "$PRIMARY_IMAGE" -f "$ROOT/Dockerfile" "$ROOT"; then
    ok "Image successfully built: $PRIMARY_IMAGE"
  else
    fail "Docker build failed!"
    exit 1
  fi
fi

# Tag alias if requested
if [[ "$PUSH_DEMO" -eq 1 ]]; then
  docker tag "$PRIMARY_IMAGE" "$ALIAS_IMAGE"
  ok "Tagged alias: $ALIAS_IMAGE"
fi
echo ""

# ── 4. Dry Run Guard ──
if [[ "$DRY_RUN" -eq 1 ]]; then
  header "Dry Run Complete"
  ok "Docker Hub identity verified ($TARGET_USER)"
  ok "Local images ready to push:"
  echo "  - $PRIMARY_IMAGE"
  [[ "$PUSH_DEMO" -eq 1 ]] && echo "  - $ALIAS_IMAGE"
  echo "Dry-run mode: No images were pushed to Docker Hub."
  exit 0
fi

# ── 5. Push to Docker Hub ──
header "Step 4: Pushing Images to Docker Hub"
echo "Pushing $PRIMARY_IMAGE ..."
if docker push "$PRIMARY_IMAGE"; then
  ok "Successfully pushed $PRIMARY_IMAGE to Docker Hub!"
else
  fail "Failed to push $PRIMARY_IMAGE. Check network and repository permissions."
  exit 1
fi

if [[ "$PUSH_DEMO" -eq 1 ]]; then
  echo ""
  echo "Pushing $ALIAS_IMAGE ..."
  if docker push "$ALIAS_IMAGE"; then
    ok "Successfully pushed $ALIAS_IMAGE to Docker Hub!"
  else
    warn "Failed to push $ALIAS_IMAGE"
  fi
fi
echo ""

# ── 6. Completion Summary ──
header "Docker Hub Push Succeeded!"
echo "Repository : https://hub.docker.com/r/$TARGET_REPO"
echo "Pushed Tags: $TAG $([[ "$PUSH_DEMO" -eq 1 ]] && echo ", $ALIAS_TAG" || echo '')"
echo ""
echo "To run CipherCrest directly from Docker Hub without building:"
echo "  bash scripts/turnup.sh --use-hub"
echo "  powershell -File scripts/turnup.ps1 -UseHub"
echo ""
