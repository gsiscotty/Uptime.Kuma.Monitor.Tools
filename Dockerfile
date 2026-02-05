# =============================================================================
# Kuma Management Console - Docker Image
# Multi-stage build for smaller image size
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build dependencies
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /app

# Install build dependencies (including those needed for cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    cargo \
    rustc \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY web/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# -----------------------------------------------------------------------------
# Stage 2: Production image
# -----------------------------------------------------------------------------
FROM python:3.12-slim

LABEL maintainer="gsiscotty"
LABEL description="Kuma Management Console - Web interface for Uptime Kuma management"
LABEL version="1.0.0-beta"

WORKDIR /app

# Security: Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY web/ ./web/
COPY kuma-bulk-editor.py ./

# Create data directory for SQLite
RUN mkdir -p /app/data && chown -R appuser:appuser /app

# Set proper permissions (directories need 755 for traversal, files 644)
RUN find /app/web -type d -exec chmod 755 {} \; && \
    find /app/web -type f -exec chmod 644 {} \;

# Switch to non-root user
USER appuser

# Environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=web.app:app \
    DATABASE_URL=sqlite:////app/data/users.db

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/auth/login')" || exit 1

# Run with gunicorn
# Using 1 worker to ensure in-memory KumaService instances persist across requests
# Multiple threads still provide concurrency within the single worker
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "1", \
     "--threads", "8", \
     "--worker-class", "gthread", \
     "--timeout", "120", \
     "--keep-alive", "5", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "50", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--capture-output", \
     "web.app:app"]
