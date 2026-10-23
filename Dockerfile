# ==============================================================================
# HomeBOM - Containerfile / Dockerfile
#
# Production slim, non-root container deployment for AWS App Runner or ECS.
# Bundles server/data (NVD/KEV/EPSS feeds) and server/static (Web UI).
# Binds 0.0.0.0 only inside the container, with PORT read from environment.
# ==============================================================================

FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8000 \
    HOST=0.0.0.0 \
    HOMEBOM_PUBLIC_DEMO=1

# Create non-root user and group
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/bash -m appuser

WORKDIR /app

# Install uv for reproducible dependency installation
COPY --from=ghcr.io/astral-sh/uv:0.5.21 /uv /bin/uv

# Copy project manifests and packages
COPY pyproject.toml ./
COPY packages/ ./packages/

# Install packages into system environment
RUN uv pip install --system -e ./packages/homebom-core -e .

# Copy application code, pre-cached data feeds, and static web assets
COPY server/ ./server/

# Fix ownership
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose default port
EXPOSE 8000

# Launch server with PORT dynamically resolved from environment
CMD ["sh", "-c", "exec python -m uvicorn server.main:app --host 0.0.0.0 --port ${PORT}"]
