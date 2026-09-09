# SecureMailScope hybrid core+lab — 3-stage: frontend (node 20) + builder (python 3.11) + runtime (python 3.11 + tini + tshark)
# Single port 8000 via FastAPI StaticFiles; no wheelhouse bake (per-arch pip install); no s6/supervisord

# ── Stage 1: frontend ────────────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM node:20-bookworm-slim AS frontend
WORKDIR /app/dashboard
COPY dashboard/package.json dashboard/package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY dashboard/ ./
COPY shared/ /app/shared/
COPY lab/ /app/lab/
RUN npm run build

# ── Stage 2: builder ─────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS builder
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1
RUN apt-get update && (apt-cache madison tshark | grep 4.2 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc python3-dev libffi-dev libpq-dev tshark=4.2.* --allow-downgrades || DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc python3-dev libffi-dev libpq-dev tshark) && rm -rf /var/lib/apt/lists/* && tshark --version | grep -Eq "4\.(2|6)"
WORKDIR /app
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# ── Stage 3: runtime ─────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS runtime
RUN apt-get update && (apt-cache madison tshark | grep 4.2 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl tini tshark=4.2.* --allow-downgrades || DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl tini tshark) && rm -rf /var/lib/apt/lists/* && tshark --version | grep -Eq "4\.(2|6)" && useradd -m -u 10001 app
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
COPY eval/ ./eval/
COPY --from=frontend /app/dashboard/dist ./dashboard/dist
RUN chown -R 10001:10001 /app && chmod -R g+w /app/api 2>/dev/null || true
RUN rm -f /app/api/flows.db && apt-get update && apt-get install -y --no-install-recommends postgresql-client && rm -rf /var/lib/apt/lists/*
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD curl -fsS --max-time 2 http://localhost:8000/health || curl -fsS --max-time 2 http://localhost:8000/flows || exit 1
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sh", "-c", "uvicorn api.app:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
