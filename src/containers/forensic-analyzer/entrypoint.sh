#!/usr/bin/env bash

set -Eeuo pipefail

INPUT_DIR="${FORENSIC_INPUT_DIR:-/workspace/input}"
OUTPUT_DIR="${FORENSIC_OUTPUT_DIR:-/workspace/output}"
TIMELINE_PATH="${FORENSIC_TIMELINE_PATH:-${OUTPUT_DIR}/timeline.json}"
STORAGE_PATH="${FORENSIC_STORAGE_PATH:-/tmp/plaso/timeline.plaso}"
LOG2TIMELINE_BIN="${LOG2TIMELINE_BIN:-log2timeline.py}"
PSORT_BIN="${PSORT_BIN:-psort.py}"
PLASO_PARSERS="${PLASO_PARSERS:-amcache,bash_history,bencode,binary_cookies,esedb,filestat,lnk,mft,olecf,pe,prefetch,recycle_bin,sqlite,syslog,usnjrnl,winevt,winevtx,winjob,winreg}"

log() {
    printf '[forensic-entrypoint] %s\n' "$*" >&2
}

fail() {
    log "ERROR: $*"
    exit 1
}

run_log2timeline() {
    local -a sources=("$@")
    local -a cmd=(
        "${LOG2TIMELINE_BIN}"
        --parsers "${PLASO_PARSERS}"
        --partitions all
        --vss_stores all
        --status_view none
        --storage-file "${STORAGE_PATH}"
    )
    cmd+=("${sources[@]}")

    log "Running log2timeline.py with ${#sources[@]} evidence source(s)."
    "${cmd[@]}"
}

run_psort() {
    log "Running psort.py and writing JSON timeline to ${TIMELINE_PATH}."
    "${PSORT_BIN}" -o json_line --status_view none -w "${TIMELINE_PATH}" "${STORAGE_PATH}"
}

main() {
    if [[ ! -d "${INPUT_DIR}" ]]; then
        fail "Input directory not found: ${INPUT_DIR}"
    fi

    mkdir -p "${OUTPUT_DIR}" "$(dirname "${STORAGE_PATH}")"

    mapfile -t evidence_sources < <(find "${INPUT_DIR}" -mindepth 1 -maxdepth 1 -print | sort)
    if [[ "${#evidence_sources[@]}" -eq 0 ]]; then
        fail "No evidence found under ${INPUT_DIR}. Mount evidence read-only at /workspace/input."
    fi

    if ! run_log2timeline "${evidence_sources[@]}"; then
        fail "log2timeline.py failed while processing evidence from ${INPUT_DIR}"
    fi
    if [[ ! -s "${STORAGE_PATH}" ]]; then
        fail "Plaso storage file was not created: ${STORAGE_PATH}"
    fi

    if ! run_psort; then
        fail "psort.py failed while exporting timeline JSON"
    fi
    if [[ ! -s "${TIMELINE_PATH}" ]]; then
        fail "Timeline output is missing or empty: ${TIMELINE_PATH}"
    fi

    log "Timeline generation completed successfully: ${TIMELINE_PATH}"
}

main "$@"
