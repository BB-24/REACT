#!/usr/bin/env bash
#
# acquire-memory.sh -- stream Linux physical memory into the forensic enclave
# without writing an image file to the target's disk (SOP 2, Phase 2).
#
# The acquisition tool writes the raw image to stdout. This script slices that
# stream into fixed-size blocks and uploads each one with the Azure Blob
# "Put Block" REST operation, committing them at the end with "Put Block List".
#
# Why Put Block rather than a single upload: the plain "Put Blob" call requires
# a Content-Length for the whole body, which is unknowable for a live stream,
# and Azure Blob Storage rejects chunked transfer-encoding. AzCopy cannot read
# from stdin at all. Sizing each block individually satisfies both constraints.
#
# One block at a time is staged in $STAGE_DIR, which defaults to /dev/shm -- a
# tmpfs, i.e. RAM. Nothing reaches the block device. The script refuses to run
# if the staging directory turns out to be disk-backed. Writing the image to
# disk would overwrite unallocated space that may itself be evidence, and hands
# an attacker on the host a copy of the artifact being collected.
#
# A SHA-256 is folded over the stream in flight. That "witness hash" is stamped
# into the blob metadata; the ChainOfCustody function compares it to the hash it
# computes server-side, so any change in transit is detectable.
#
# Requires root: reading physical memory needs kernel access.

set -euo pipefail

SAS_URL=""
INCIDENT_ID=""
SOURCE="auto"
BLOCK_MB=64
STAGE_DIR="/dev/shm"
API_VERSION="2021-08-06"
INITIATOR_OBJECT_ID=""
AVML_PATH="$(dirname "$0")/tools/avml"
LIME_MODULE=""
LIME_PORT=4444
AZURE_MAX_BLOCKS=50000

usage() {
    cat <<'USAGE'
Usage: acquire-memory.sh --sas-url URL --incident-id ID [options]

Required:
  --sas-url URL            Write-only blob SAS URL (uploadUrl from
                           NetworkContainment). Valid 60 minutes by default.
  --incident-id ID         Incident identifier, stamped into blob metadata.

Options:
  --source MODE            auto | avml | lime | kcore     (default: auto)
  --avml-path PATH         AVML binary                    (default: ./tools/avml)
  --lime-module PATH       lime.ko, required for --source lime
  --lime-port PORT         LiME TCP listener port         (default: 4444)
  --block-mb N             Put Block size in MB           (default: 64)
  --stage-dir DIR          tmpfs staging directory        (default: /dev/shm)
  --initiator-object-id ID AAD object ID of the triggering Logic App
  -h, --help               Show this help

Acquisition sources:
  avml   AVML writes LiME format to /dev/stdout. Preferred: no kernel module to
         build, and it understands the memory layout of every major distro.
  lime   LiME's own TCP listener (path=tcp:PORT), read back over loopback.
         Use when a lime.ko is already built for this exact kernel.
  kcore  Read /proc/kcore. A last resort -- ELF-wrapped and only present when
         the kernel was built with CONFIG_PROC_KCORE.
USAGE
}

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --sas-url)             SAS_URL="$2"; shift 2 ;;
        --incident-id)         INCIDENT_ID="$2"; shift 2 ;;
        --source)              SOURCE="$2"; shift 2 ;;
        --avml-path)           AVML_PATH="$2"; shift 2 ;;
        --lime-module)         LIME_MODULE="$2"; shift 2 ;;
        --lime-port)           LIME_PORT="$2"; shift 2 ;;
        --block-mb)            BLOCK_MB="$2"; shift 2 ;;
        --stage-dir)           STAGE_DIR="$2"; shift 2 ;;
        --initiator-object-id) INITIATOR_OBJECT_ID="$2"; shift 2 ;;
        -h|--help)             usage; exit 0 ;;
        *)                     usage >&2; die "Unknown argument: $1" ;;
    esac
done

# --- Preconditions -----------------------------------------------------------

[ -n "$SAS_URL" ]     || { usage >&2; die "--sas-url is required."; }
[ -n "$INCIDENT_ID" ] || { usage >&2; die "--incident-id is required."; }

case "$SAS_URL" in
    *\?*) : ;;
    *) die "--sas-url has no query string; it is not a SAS URL." ;;
esac

[ "$(id -u)" -eq 0 ] || die "Must run as root: reading physical memory needs kernel access."

for tool in curl dd sha256sum base64 stat; do
    command -v "$tool" >/dev/null 2>&1 || die "Required tool not found: $tool"
done

[ -d "$STAGE_DIR" ] || die "Staging directory does not exist: $STAGE_DIR"

# The no-disk-write guarantee rests entirely on this check.
STAGE_FS="$(stat -f -c %T "$STAGE_DIR" 2>/dev/null || echo unknown)"
case "$STAGE_FS" in
    tmpfs|ramfs) log "Staging on $STAGE_DIR ($STAGE_FS): RAM-backed, no disk writes." ;;
    *) die "Staging directory $STAGE_DIR is '$STAGE_FS', not tmpfs/ramfs. \
Refusing to stage evidence on a block device (SOP 2, Phase 2.2)." ;;
esac

BLOCK_BYTES=$((BLOCK_MB * 1024 * 1024))
STAGE_FILE="$STAGE_DIR/react-block-$$"
BLOCK_IDS_FILE="$STAGE_DIR/react-blocks-$$"
HASH_FILE="$STAGE_DIR/react-hash-$$"
SOURCE_HOST="$(hostname)"
ACQUIRED_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LIME_LOADED=0

cleanup() {
    rm -f "$STAGE_FILE" "$BLOCK_IDS_FILE" "$HASH_FILE"
    # LIME_LOADED is set inside the pipeline subshell, so it never propagates
    # here; unload unconditionally whenever a module was supplied.
    if [ "$LIME_LOADED" -eq 1 ] || [ -n "$LIME_MODULE" ]; then
        rmmod lime 2>/dev/null || true
    fi
}
trap cleanup EXIT

# --- Acquisition sources -----------------------------------------------------

resolve_source() {
    if [ "$SOURCE" != "auto" ]; then
        echo "$SOURCE"
        return
    fi
    if [ -x "$AVML_PATH" ] || command -v avml >/dev/null 2>&1; then
        echo avml
    elif [ -n "$LIME_MODULE" ] && [ -f "$LIME_MODULE" ]; then
        echo lime
    elif [ -r /proc/kcore ]; then
        echo kcore
    else
        die "No usable acquisition source. Provide AVML via --avml-path or a \
lime.ko via --lime-module."
    fi
}

stream_avml() {
    local binary="$AVML_PATH"
    [ -x "$binary" ] || binary="$(command -v avml)"
    [ -x "$binary" ] || die "AVML not found or not executable."
    log "Acquiring via AVML to stdout."
    exec "$binary" /dev/stdout
}

stream_lime() {
    [ -n "$LIME_MODULE" ] || die "--lime-module is required for --source lime."
    [ -f "$LIME_MODULE" ] || die "LiME module not found: $LIME_MODULE"
    command -v nc >/dev/null 2>&1 || die "netcat (nc) is required for LiME TCP mode."

    log "Loading LiME with a TCP listener on port $LIME_PORT (no disk path)."
    # insmod blocks until a client has drained the dump, so it runs in the
    # background and the reader connects to it.
    insmod "$LIME_MODULE" "path=tcp:$LIME_PORT" "format=lime" &
    LIME_LOADED=1

    local attempt=0
    while [ "$attempt" -lt 30 ]; do
        if nc -z 127.0.0.1 "$LIME_PORT" 2>/dev/null; then
            break
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    [ "$attempt" -lt 30 ] || die "LiME listener never came up on port $LIME_PORT."

    exec nc 127.0.0.1 "$LIME_PORT"
}

stream_kcore() {
    [ -r /proc/kcore ] || die "/proc/kcore is not readable (CONFIG_PROC_KCORE off?)."
    log "Acquiring via /proc/kcore. Note: ELF-wrapped, not a flat raw image."
    exec cat /proc/kcore
}

stream_source() {
    case "$(resolve_source)" in
        avml)  stream_avml ;;
        lime)  stream_lime ;;
        kcore) stream_kcore ;;
        *)     die "Unknown --source '$SOURCE'." ;;
    esac
}

# --- Upload ------------------------------------------------------------------

# Azure block IDs travel in the query string, so the base64 padding and the
# non-URL-safe alphabet have to be percent-encoded.
urlencode_block_id() {
    printf '%s' "$1" | sed -e 's/+/%2B/g' -e 's|/|%2F|g' -e 's/=/%3D/g'
}

put_block() {
    local block_id="$1" file="$2"
    curl --fail --silent --show-error --retry 4 --retry-delay 2 \
        --request PUT \
        --header "x-ms-version: $API_VERSION" \
        --header "Content-Type: application/octet-stream" \
        --header "Expect:" \
        --upload-file "$file" \
        "${SAS_URL}&comp=block&blockid=$(urlencode_block_id "$block_id")" \
        >/dev/null
}

put_block_list() {
    local witness_hash="$1"
    local body="$STAGE_DIR/react-blocklist-$$"
    {
        printf '<?xml version="1.0" encoding="utf-8"?><BlockList>'
        while IFS= read -r id; do
            printf '<Latest>%s</Latest>' "$id"
        done < "$BLOCK_IDS_FILE"
        printf '</BlockList>'
    } > "$body"

    curl --fail --silent --show-error --retry 4 --retry-delay 2 \
        --request PUT \
        --header "x-ms-version: $API_VERSION" \
        --header "Content-Type: application/xml" \
        --header "x-ms-blob-content-type: application/octet-stream" \
        --header "x-ms-meta-incidentid: $INCIDENT_ID" \
        --header "x-ms-meta-sourcehost: $SOURCE_HOST" \
        --header "x-ms-meta-acquiredutc: $ACQUIRED_UTC" \
        --header "x-ms-meta-witnesssha256: $witness_hash" \
        --header "x-ms-meta-acquisitiontool: $(resolve_source)" \
        --header "x-ms-meta-initiatorobjectid: $INITIATOR_OBJECT_ID" \
        --data-binary "@$body" \
        "${SAS_URL}&comp=blocklist" >/dev/null
    rm -f "$body"
}

upload_stream() {
    local index=0 total=0 size block_id
    : > "$BLOCK_IDS_FILE"

    while : ; do
        # iflag=fullblock matters: without it dd stops at the first short read
        # from the pipe and emits undersized blocks.
        dd of="$STAGE_FILE" bs=1M count="$BLOCK_MB" iflag=fullblock 2>/dev/null || true
        size="$(stat -c %s "$STAGE_FILE")"
        [ "$size" -eq 0 ] && break

        block_id="$(printf '%08d' "$index" | base64 | tr -d '\n')"
        put_block "$block_id" "$STAGE_FILE"
        printf '%s\n' "$block_id" >> "$BLOCK_IDS_FILE"

        index=$((index + 1))
        total=$((total + size))
        if [ "$index" -ge "$AZURE_MAX_BLOCKS" ]; then
            die "Reached Azure's $AZURE_MAX_BLOCKS-block limit. Re-run with a larger --block-mb."
        fi
        if [ $((index % 10)) -eq 0 ]; then
            log "Uploaded $index blocks ($((total / 1024 / 1024)) MB)."
        fi
        # A short read means the source stream ended mid-block.
        [ "$size" -lt "$BLOCK_BYTES" ] && break
    done

    printf '%s' "$total" > "$STAGE_DIR/react-total-$$"
}

# --- Main --------------------------------------------------------------------

log "Starting memory acquisition for incident $INCIDENT_ID on $SOURCE_HOST."
log "Block size ${BLOCK_MB} MB; no image file will touch local disk."

# tee forks the stream: one copy is hashed, one is uploaded. Both see identical
# bytes, so the witness hash describes exactly what was stored.
stream_source | tee >(sha256sum | awk '{print $1}' > "$HASH_FILE") | upload_stream

[ -s "$BLOCK_IDS_FILE" ] || die "Acquisition produced no data; nothing uploaded."

WITNESS_HASH="$(cat "$HASH_FILE")"
TOTAL_BYTES="$(cat "$STAGE_DIR/react-total-$$" 2>/dev/null || echo 0)"
rm -f "$STAGE_DIR/react-total-$$"

log "Committing $(wc -l < "$BLOCK_IDS_FILE") blocks ($((TOTAL_BYTES / 1024 / 1024)) MB)."
put_block_list "$WITNESS_HASH"

log "Acquisition complete. Witness SHA-256: $WITNESS_HASH"
printf '{"incidentId":"%s","sourceHost":"%s","acquiredUtc":"%s","sizeBytes":%s,"witnessSha256":"%s"}\n' \
    "$INCIDENT_ID" "$SOURCE_HOST" "$ACQUIRED_UTC" "$TOTAL_BYTES" "$WITNESS_HASH"
