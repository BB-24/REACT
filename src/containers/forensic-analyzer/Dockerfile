# ==============================================================================
# DFIR SIFT Forensic Analyzer Container
# Multi-stage build for forensic artifact triage and timeline analysis
# ==============================================================================

# Build Stage: Install build dependencies and compile python wheels
FROM python:3.14-slim-bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    git \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /install

# Install core DFIR Python packages
RUN pip install --prefix=/install --no-warn-script-location \
    volatility3 \
    yara-python \
    pefile \
    olefile \
    pytsk3 \
    dfvfs \
    azure-storage-blob \
    azure-identity

# Final Runtime Stage
FROM python:3.14-slim-bookworm AS runtime

LABEL maintainer="REACT DFIR Team" \
      description="Forensic artifact analyzer and memory triage container" \
      version="1.0.0"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    FORENSIC_WORKSPACE="/workspace"

RUN apt-get update && apt-get install -y --no-install-recommends \
    sleuthkit \
    binutils \
    p7zip-full \
    tesseract-ocr \
    curl \
    jq \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy python packages from builder
COPY --from=builder /install /usr/local

# Create non-privileged service user
RUN groupadd -r dfiruser && useradd -r -g dfiruser -d /workspace -s /bin/bash dfiruser \
    && mkdir -p /workspace/input /workspace/output \
    && chown -R dfiruser:dfiruser /workspace

WORKDIR /workspace
USER dfiruser

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import volatility3, yara, pytsk3; print('DFIR tools OK')" || exit 1

ENTRYPOINT ["python3"]
CMD ["-c", "print('DFIR SIFT Forensic Analyzer ready.')"]
