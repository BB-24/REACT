#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

IMAGE_TAG="${IMAGE_TAG:-react-forensic-analyzer:local}"
SAMPLE_EVIDENCE_DIR="${SAMPLE_EVIDENCE_DIR:-${REPO_ROOT}/sample-evidence}"
OUTPUT_DIR="${OUTPUT_DIR:-${REPO_ROOT}/sample-evidence-output}"
TIMELINE_OUTPUT="${OUTPUT_DIR}/timeline.json"
SKIP_BUILD="${SKIP_BUILD:-false}"

log() {
    printf '[verify-local] %s\n' "$*" >&2
}

fail() {
    log "ERROR: $*"
    exit 1
}

# Verify Docker availability
if ! command -v docker >/dev/null 2>&1; then
    fail "Docker CLI is not installed or not in PATH."
fi

if ! docker info >/dev/null 2>&1; then
    fail "Docker daemon is not running. Please start Docker Desktop or the Docker daemon and retry."
fi

# Ensure sample evidence fixture exists
if [[ ! -d "${SAMPLE_EVIDENCE_DIR}" ]] || [[ -z "$(ls -A "${SAMPLE_EVIDENCE_DIR}" 2>/dev/null)" ]]; then
    log "Sample evidence directory is missing or empty: ${SAMPLE_EVIDENCE_DIR}"
    log "Creating mock evidence fixture..."
    mkdir -p "${SAMPLE_EVIDENCE_DIR}"
    cat << 'EOF' > "${SAMPLE_EVIDENCE_DIR}/syslog.log"
Oct 24 00:00:01 web-vm-01 systemd[1]: Started Daily apt upgrade and clean activities.
Oct 24 00:01:15 web-vm-01 sshd[4321]: Accepted publickey for azureuser from 10.0.1.4 port 52341 ssh2
Oct 24 00:02:30 web-vm-01 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by azureuser(uid=1000)
EOF
fi

mkdir -p "${OUTPUT_DIR}"
rm -f "${TIMELINE_OUTPUT}"

# Build Docker image
if [[ "${SKIP_BUILD}" != "true" ]]; then
    log "Building forensic analyzer Docker image: ${IMAGE_TAG}..."
    docker build -t "${IMAGE_TAG}" "${SCRIPT_DIR}"
else
    log "Skipping Docker image build (SKIP_BUILD=true)."
fi

# Run Docker container with read-only input mount and writable output mount
log "Running container with sample evidence mounted read-only at /workspace/input..."
docker run --rm \
    -v "${SAMPLE_EVIDENCE_DIR}:/workspace/input:ro" \
    -v "${OUTPUT_DIR}:/workspace/output" \
    "${IMAGE_TAG}"

# Validate output
if [[ ! -f "${TIMELINE_OUTPUT}" ]]; then
    fail "Timeline file was not created: ${TIMELINE_OUTPUT}"
fi

if [[ ! -s "${TIMELINE_OUTPUT}" ]]; then
    fail "Timeline file is empty: ${TIMELINE_OUTPUT}"
fi

EVENT_COUNT="$(wc -l < "${TIMELINE_OUTPUT}" | tr -d ' ')"
log "Verification PASSED successfully!"
log "Extracted timeline events: ${EVENT_COUNT}"
log "Output file: ${TIMELINE_OUTPUT}"
