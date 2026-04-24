# ── Build stage ────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# Install dependencies into an isolated prefix so we can copy them cleanly
COPY requirements.txt .
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt


# ── Runtime stage ───────────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL org.opencontainers.image.title="CNX"
LABEL org.opencontainers.image.description="High-performance subdomain takeover scanner"
LABEL org.opencontainers.image.source="https://github.com/EdOverflow/can-i-take-over-xyz"

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy source
COPY main.py .
COPY core/   core/
COPY output/ output/
COPY utils/  utils/

# Results land here — mount a host directory to persist them
VOLUME ["/app/results", "/app/input"]

ENTRYPOINT ["python", "main.py"]
# Default: help text (override CMD or pass args after image name)
CMD ["--help"]
