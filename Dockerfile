# ============================================================
# Dockerfile — Abuse Pattern Detection & Risk Monitoring System
# ============================================================
# Multi-stage build: dependency layer cached separately from source.

FROM python:3.11-slim AS base

WORKDIR /app

# Install OS-level build dependencies (needed by some Python packages)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# --- dependency stage --------------------------------------------------
FROM base AS deps

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# --- runtime stage -----------------------------------------------------
FROM deps AS runtime

WORKDIR /app

# Copy only the necessary application directories
COPY src/     src/
COPY config/  config/
COPY sql/     sql/

# Create logs directory expected by the logging configuration
RUN mkdir -p logs

# Expose the application port
EXPOSE 8080

# Default command: verify the package imports correctly (health check)
CMD ["python", "-c", "import src; print('Abuse Pattern Detection System — OK')"]
