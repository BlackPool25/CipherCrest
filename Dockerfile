# SecureMailScope hybrid core+lab — 3-stage: frontend (node 20) + builder (python 3.11) + runtime (python 3.11 + tini + tshark)
# Single port 8000 via FastAPI StaticFiles; no wheelhouse bake (per-arch pip install); no s6/supervisord

# ── Stage 1: frontend ────────────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM node:20-bookworm-slim AS frontend
WORKDIR /app/dashboard
COPY dashboard/package.json dashboard/package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY dashboard/ ./
COPY shared/ /app/shared/
RUN npm run build

# ── Stage 2: builder ─────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS builder
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc python3-dev libffi-dev tshark \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# ── Stage 3: runtime ─────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl tini tshark \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 app
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0 \
    OMP_NUM_THREADS=6 \
    USE_STUB=false \
    PORT=8000
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY api/ ./api/
COPY analyzer/ ./analyzer/
COPY validator/ ./validator/
COPY assessment/ ./assessment/
COPY shared/ ./shared/
COPY lab/ ./lab/
COPY models/ ./models/
COPY --from=frontend /app/dashboard/dist ./dashboard/dist
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD curl -fsS http://localhost:8000/health || curl -fsS http://localhost:8000/flows || exit 1
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sh", "-c", "uvicorn api.app:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
