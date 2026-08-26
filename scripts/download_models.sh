#!/usr/bin/env bash
# scripts/download_models.sh — fetch future large models from GitHub Releases (2 GB per asset, free, versioned by tag)
# Current small models 276K stay in git; this script is no-op now and ready for MicroAE/torch stretch.
# Usage: bash scripts/download_models.sh [--check]   # --check = dry-run, no download
# Env: GH_RELEASE_TAG (default v0.7.0-bridge) or GITHUB_REPOSITORY (owner/repo) for curl URL
# If models already present and <5M, skips. If future large model listed in MANIFEST, downloads via curl -L.
# No-op safe: never overwrites existing pkl, never requires network when small models present.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TAG="${GH_RELEASE_TAG:-v0.7.0-bridge}"
REPO="${GITHUB_REPOSITORY:-ntro/SecureMailScope}"
CHECK_ONLY=0
if [[ "${1:-}" == "--check" ]]; then CHECK_ONLY=1; fi

# Manifest of models that may become large (future). Current small ones are in git, so this is placeholder.
# Add future entries like: models/microae_27-8-1.pt  52428800  <sha256>
MANIFEST=(
  "models/risk_clf.pkl"
  "models/anomaly.pkl"
  "models/anomaly_honest.pkl"
  # future stretch uncomment when file >5M:
  # "models/microae_27-8-1.pt"
  # "models/torch_cpu_2.4.0_frozen.pt"
)

have=0; miss=0
for rel in "${MANIFEST[@]}"; do
  # skip commented future
  [[ "$rel" == \#* ]] && continue
  abs="$ROOT/$rel"
  if [[ -f "$abs" ]]; then
    sz=$(stat -c%s "$abs" 2>/dev/null || stat -f%z "$abs" 2>/dev/null || echo 0)
    echo "[ok] $rel $(du -h "$abs" 2>/dev/null | cut -f1) present (<5M keep in git, no download needed)"
    have=$((have+1))
    # optional sha256 check if .sha256 exists
    if [[ -f "$abs.sha256" ]]; then
      if command -v sha256sum >/dev/null 2>&1; then
        echo "  sha256 $(sha256sum "$abs" | cut -d' ' -f1 | cut -c1-16)… vs $(cat "$abs.sha256" | cut -d' ' -f1 | cut -c1-16)…"
      fi
    fi
  else
    echo "[miss] $rel not found"
    miss=$((miss+1))
    if [[ $CHECK_ONLY -eq 1 ]]; then
      echo "  dry-run: would fetch https://github.com/$REPO/releases/download/$TAG/$(basename "$rel")"
    else
      url="https://github.com/$REPO/releases/download/$TAG/$(basename "$rel")"
      echo "  fetching $url ..."
      if command -v curl >/dev/null 2>&1; then
        mkdir -p "$(dirname "$abs")"
        if curl -fL --retry 2 -o "$abs" "$url" 2>&1; then
          echo "  downloaded $rel"
          have=$((have+1)); miss=$((miss-1))
        else
          echo "  download failed (no release asset yet — train fallback: python -m assessment.risk_model / anomaly_model)"
          rm -f "$abs" 2>/dev/null || true
        fi
      else
        echo "  curl not found — cannot fetch Releases asset (fallback: python -m assessment.risk_model)"
      fi
    fi
  fi
done

echo "download_models: have=$have miss=$miss tag=$TAG repo=$REPO"
if [[ $CHECK_ONLY -eq 1 ]]; then
  echo "dry-run done — no download attempted"
fi
# No-op safe exit 0 even if miss (future model not yet released) — turnup.sh will try train fallback
exit 0
