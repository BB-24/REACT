#!/usr/bin/env bash

set -Eeuo pipefail

INPUT_DIR="${FORENSIC_INPUT_DIR:-/workspace/input}"
OUTPUT_DIR="${FORENSIC_OUTPUT_DIR:-/workspace/output}"
TIMELINE_PATH="${FORENSIC_TIMELINE_PATH:-${OUTPUT_DIR}/timeline.json}"
STORAGE_PATH="${FORENSIC_STORAGE_PATH:-/tmp/plaso/timeline.plaso}"
LOG2TIMELINE_BIN="${LOG2TIMELINE_BIN:-log2timeline}"
PSORT_BIN="${PSORT_BIN:-psort}"
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

    # If configured parsers are specified and not 'default', attempt configured parsers first
    if [[ -n "${PLASO_PARSERS:-}" && "${PLASO_PARSERS}" != "default" ]]; then
        local -a configured_cmd=(
            "${LOG2TIMELINE_BIN}"
            --parsers "${PLASO_PARSERS}"
            --partitions all
            --vss_stores all
            --status_view none
            --storage-file "${STORAGE_PATH}"
        )
        configured_cmd+=("${sources[@]}")

        log "Running ${LOG2TIMELINE_BIN} using configured parsers mode: ${PLASO_PARSERS}"
        if "${configured_cmd[@]}"; then
            log "Extraction completed successfully using configured parsers mode."
            return 0
        fi

        log "WARNING: ${LOG2TIMELINE_BIN} failed with configured parsers (${PLASO_PARSERS}). Safely retrying using Plaso default parser set mode..."
        rm -f "${STORAGE_PATH}"
    fi

    # Fallback or default execution: run without --parsers to use Plaso's default parser set
    local -a default_cmd=(
        "${LOG2TIMELINE_BIN}"
        --partitions all
        --vss_stores all
        --status_view none
        --storage-file "${STORAGE_PATH}"
    )
    default_cmd+=("${sources[@]}")

    log "Running ${LOG2TIMELINE_BIN} using Plaso default parser set mode."
    if "${default_cmd[@]}"; then
        log "Extraction completed successfully using Plaso default parser set mode."
        return 0
    fi

    log "ERROR: ${LOG2TIMELINE_BIN} failed in both configured and default parser modes."
    return 1
}

run_psort() {
    log "Running ${PSORT_BIN} and writing JSON timeline to ${TIMELINE_PATH}."
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
        fail "${LOG2TIMELINE_BIN} failed while processing evidence from ${INPUT_DIR}"
    fi
    if [[ ! -s "${STORAGE_PATH}" ]]; then
        fail "Plaso storage file was not created: ${STORAGE_PATH}"
    fi

    if ! run_psort; then
        fail "${PSORT_BIN} failed while exporting timeline JSON"
    fi
    if [[ ! -s "${TIMELINE_PATH}" ]]; then
        fail "Timeline output is missing or empty: ${TIMELINE_PATH}"
    fi

    log "Timeline generation completed successfully: ${TIMELINE_PATH}"
}

main "$@"
