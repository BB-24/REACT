"""Phase 2 -- Live-response memory acquisition (SOP 2, Phase 2).

Called by the Logic App once NetworkContainment reports the target isolated.
It mints the credentials the target will need, generates a bootstrap script for
the target's OS, and executes it through the Azure Compute Run Command API.

Requirement mapping:

* **REQ-3.3.1** -- the script is generated per invocation (target OS, incident
  ID and freshly minted URLs are baked in) and executed via Run Command.
* **REQ-3.3.2** -- the bootstrap fetches WinPmem/AVML *and* the real acquisition
  script from the tool repository container, using read-only blob SAS tokens.
* **REQ-3.3.3** -- the upload token is the 60-minute write-only SAS from
  ``shared.sas``.
* **REQ-3.3.4** -- the fetched script streams the image straight to Blob
  Storage; no ``memdump.raw`` is ever written to the target's disk.

Two decisions worth stating:

**Managed Run Command (v2), not ``begin_run_command``.** v2 accepts
``protected_parameters``, whose values are write-only: they are not readable
back off the VM's run-command resource afterwards. Every URL here carries a SAS
-- a bearer credential handed to a machine we have already declared
compromised -- so none of them may be left legible on the target.

**A bootstrap, not the whole script.** Run Command caps the script it accepts,
and more importantly the acquisition logic belongs in one reviewed, versioned
artifact in the tool repository rather than being re-emitted from Python on
every invocation. The bootstrap only fetches and invokes it.
"""

import json
import logging

import azure.functions as func
from NetworkContainment import ContainmentError, parse_target_vm
from shared import clients, config, sas

bp = func.Blueprint()

WINDOWS = "windows"
LINUX = "linux"

# Order is a contract with both bootstrap scripts: Run Command passes these
# through positionally on Linux, so the sequence must not be reordered.
PARAMETER_ORDER = (
    "SasUrl",
    "ToolUrl",
    "ScriptUrl",
    "IncidentId",
    "InitiatorObjectId",
)

DEFAULT_TOOL_BLOBS = {WINDOWS: "winpmem.exe", LINUX: "avml"}
DEFAULT_SCRIPT_BLOBS = {WINDOWS: "Acquire-Memory.ps1", LINUX: "acquire-memory.sh"}

RUN_COMMAND_NAME_PREFIX = "REACT-Acquire-"
DEFAULT_TIMEOUT_SECONDS = 5400


class AcquisitionError(ValueError):
    """Raised when the request cannot be turned into a Run Command."""


def target_platform(vm, payload=None):
    """Return ``windows`` or ``linux`` for the target VM.

    Read from the OS disk rather than trusted from the payload, because getting
    this wrong means shipping a PowerShell bootstrap to a Linux host and
    burning the one chance at a clean acquisition.
    """
    override = (payload or {}).get("platform") or (payload or {}).get("Platform")
    if override:
        lowered = str(override).strip().lower()
        if lowered not in (WINDOWS, LINUX):
            raise AcquisitionError(
                f"platform override must be 'windows' or 'linux', got '{override}'."
            )
        return lowered

    os_disk = getattr(getattr(vm, "storage_profile", None), "os_disk", None)
    os_type = getattr(os_disk, "os_type", None)
    if os_type is None:
        raise AcquisitionError(
            f"VM '{getattr(vm, 'name', 'unknown')}' does not report an OS type; "
            "pass 'platform' explicitly so the correct acquisition tool is used."
        )
    return WINDOWS if str(os_type).lower().startswith("windows") else LINUX


def build_windows_bootstrap():
    """PowerShell bootstrap: fetch WinPmem and the acquisition script, run it.

    The ~1 MB tool binary does land on the target's disk -- Windows offers no
    tmpfs equivalent, and a kernel driver cannot be loaded from memory. That is
    a bounded, known write of a file we supplied. The multi-gigabyte *image*,
    which is the artifact REQ-3.3.4 is about, never touches the disk.
    """
    return "\n".join(
        [
            "param(",
            "    [Parameter(Mandatory = $true)][string]$SasUrl,",
            "    [Parameter(Mandatory = $true)][string]$ToolUrl,",
            "    [Parameter(Mandatory = $true)][string]$ScriptUrl,",
            "    [Parameter(Mandatory = $true)][string]$IncidentId,",
            "    [string]$InitiatorObjectId = ''",
            ")",
            "$ErrorActionPreference = 'Stop'",
            "$ProgressPreference = 'SilentlyContinue'",
            "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12",
            "",
            "$stage = Join-Path $env:TEMP ('react-' + $IncidentId)",
            "$tools = Join-Path $stage 'tools'",
            "New-Item -ItemType Directory -Force -Path $tools | Out-Null",
            "$scriptPath = Join-Path $stage 'Acquire-Memory.ps1'",
            "$toolPath = Join-Path $tools 'winpmem.exe'",
            "",
            "try {",
            "    # REQ-3.3.2: both artifacts come from the tool repository over a",
            "    # read-only, blob-scoped SAS.",
            "    Invoke-WebRequest -Uri $ScriptUrl -OutFile $scriptPath -UseBasicParsing",
            "    Invoke-WebRequest -Uri $ToolUrl -OutFile $toolPath -UseBasicParsing",
            "",
            "    & $scriptPath -SasUrl $SasUrl -IncidentId $IncidentId "
            "-WinPmemPath $toolPath -InitiatorObjectId $InitiatorObjectId",
            "}",
            "finally {",
            "    # Leave nothing of ours behind on the evidence source.",
            "    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $stage",
            "}",
        ]
    )


def build_linux_bootstrap():
    """Bash bootstrap: stage AVML and the acquisition script in tmpfs, run them.

    Everything is staged under ``/dev/shm`` -- RAM, not a block device -- so on
    Linux not even the tool binary reaches the disk.
    """
    return "\n".join(
        [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            "",
            'SAS_URL="$1"',
            'TOOL_URL="$2"',
            'SCRIPT_URL="$3"',
            'INCIDENT_ID="$4"',
            'INITIATOR_OBJECT_ID="${5:-}"',
            "",
            'STAGE="/dev/shm/react-${INCIDENT_ID}"',
            'mkdir -p "${STAGE}/tools"',
            'cleanup() { rm -rf "${STAGE}"; }',
            "trap cleanup EXIT",
            "",
            "# REQ-3.3.2: tool and script both come from the repository container",
            "# over a read-only, blob-scoped SAS.",
            'curl --fail --silent --show-error --location "${SCRIPT_URL}" '
            '-o "${STAGE}/acquire-memory.sh"',
            'curl --fail --silent --show-error --location "${TOOL_URL}" -o "${STAGE}/tools/avml"',
            'chmod +x "${STAGE}/acquire-memory.sh" "${STAGE}/tools/avml"',
            "",
            '"${STAGE}/acquire-memory.sh" \\',
            '    --sas-url "${SAS_URL}" \\',
            '    --incident-id "${INCIDENT_ID}" \\',
            '    --avml-path "${STAGE}/tools/avml" \\',
            "    --stage-dir /dev/shm \\",
            '    --initiator-object-id "${INITIATOR_OBJECT_ID}"',
        ]
    )


def build_bootstrap_script(platform):
    if platform == WINDOWS:
        return build_windows_bootstrap()
    if platform == LINUX:
        return build_linux_bootstrap()
    raise AcquisitionError(f"Unsupported platform '{platform}'.")


def build_run_command(platform, location, parameters, timeout_seconds=None):
    """Assemble the Managed Run Command resource body.

    Every parameter goes in ``protected_parameters``. Splitting them would make
    the positional order Linux relies on ambiguous, and none of these values
    benefit from being legible on a compromised host.
    """
    return {
        "location": location,
        "source": {"script": build_bootstrap_script(platform)},
        "protected_parameters": [
            {"name": name, "value": str(parameters.get(name, ""))} for name in PARAMETER_ORDER
        ],
        "timeout_in_seconds": int(
            timeout_seconds
            or config.get_int("ACQUISITION_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)
        ),
        "async_execution": False,
        "treat_failure_as_deployment_failure": True,
    }


def _tool_blob_name(platform):
    setting = "WINPMEM_BLOB_NAME" if platform == WINDOWS else "AVML_BLOB_NAME"
    return config.get(setting, DEFAULT_TOOL_BLOBS[platform])


def _script_blob_name(platform):
    setting = "WINDOWS_SCRIPT_BLOB_NAME" if platform == WINDOWS else "LINUX_SCRIPT_BLOB_NAME"
    return config.get(setting, DEFAULT_SCRIPT_BLOBS[platform])


def _parse_run_command_output(result):
    """Pull the acquisition summary out of the Run Command instance view."""
    view = getattr(result, "instance_view", None)
    raw = (getattr(view, "output", None) or "").strip()
    summary = {
        "executionState": getattr(view, "execution_state", None),
        "exitCode": getattr(view, "exit_code", None),
        "error": getattr(view, "error", None) or None,
    }
    if not raw:
        return summary
    # The acquisition scripts print a one-line JSON summary as their last act.
    for line in reversed(raw.splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                summary["acquisition"] = json.loads(line)
            except ValueError:
                pass
            break
    if "acquisition" not in summary:
        summary["output"] = raw[-2000:]
    return summary


def handle_acquisition(req, credential=None):
    """Core handler, kept free of decorators so it is directly unit-testable."""
    try:
        payload = req.get_json()
    except ValueError:
        return _json_response(400, {"error": "Request body is not valid JSON."})

    if not isinstance(payload, dict):
        return _json_response(400, {"error": "Request body must be a JSON object."})

    lowered = {str(key).lower(): value for key, value in payload.items()}
    incident_id = lowered.get("incidentid") or lowered.get("incident_id")
    if not incident_id:
        return _json_response(400, {"error": "Payload must include 'IncidentId'."})

    try:
        subscription, resource_group, vm_name = parse_target_vm(payload)
    except ContainmentError as error:
        return _json_response(400, {"error": str(error)})

    credential = credential or clients.credential()
    compute_client = clients.compute_client(subscription, cred=credential)
    vm = compute_client.virtual_machines.get(resource_group, vm_name)

    try:
        platform = target_platform(vm, lowered)
    except AcquisitionError as error:
        return _json_response(400, {"error": str(error)})

    # REQ-3.3.3: 60-minute, write-only, single-blob upload token.
    blob_name = sas.build_blob_name(incident_id, vm_name)
    upload_url, expires_on = sas.mint_write_only_sas(blob_name, credential=credential)

    # REQ-3.3.2: read-only tokens for the tool repository.
    tool_blob = _tool_blob_name(platform)
    script_blob = _script_blob_name(platform)
    tool_url, _ = sas.mint_read_only_sas(tool_blob, credential=credential)
    script_url, _ = sas.mint_read_only_sas(script_blob, credential=credential)

    initiator = lowered.get("initiatorobjectid") or config.get("LOGIC_APP_PRINCIPAL_ID", "")

    run_command = build_run_command(
        platform,
        vm.location,
        {
            "SasUrl": upload_url,
            "ToolUrl": tool_url,
            "ScriptUrl": script_url,
            "IncidentId": str(incident_id),
            "InitiatorObjectId": initiator,
        },
    )
    run_command_name = f"{RUN_COMMAND_NAME_PREFIX}{sas.slug(incident_id)}"[:80]

    # Note the absence of any URL in this log line: all three carry a SAS.
    logging.info(
        "Dispatching %s acquisition to %s via Run Command '%s' (incident %s).",
        platform,
        vm_name,
        run_command_name,
        incident_id,
    )

    poller = compute_client.virtual_machine_run_commands.begin_create_or_update(
        resource_group, vm_name, run_command_name, run_command
    )
    result = poller.result()
    summary = _parse_run_command_output(result)

    succeeded = summary.get("executionState") in (None, "Succeeded")
    return _json_response(
        200 if succeeded else 502,
        {
            "status": "acquired" if succeeded else "acquisition-failed",
            "incidentId": str(incident_id),
            "targetVm": vm_name,
            "platform": platform,
            "resourceGroup": resource_group,
            "blobName": blob_name,
            "uploadUrlExpiresOn": expires_on.isoformat(),
            "toolBlob": tool_blob,
            "scriptBlob": script_blob,
            "runCommandName": run_command_name,
            "runCommand": summary,
            # ChainOfCustody records the hash asynchronously off the Event Grid
            # BlobCreated event; the ledger row is not written yet.
            "custody": "pending-event-grid",
        },
    )


def _json_response(status_code, body):
    return func.HttpResponse(
        json.dumps(body),
        status_code=status_code,
        mimetype="application/json",
    )


@bp.route(route="acquire", methods=["POST"])
def memory_acquisition(req: func.HttpRequest) -> func.HttpResponse:
    try:
        return handle_acquisition(req)
    except config.ConfigError as error:
        logging.exception("Acquisition blocked by configuration error.")
        return _json_response(500, {"error": str(error)})
    except Exception as error:  # noqa: BLE001 - the Logic App needs a verdict
        logging.exception("Memory acquisition failed.")
        return _json_response(500, {"error": f"Memory acquisition failed: {error}"})
