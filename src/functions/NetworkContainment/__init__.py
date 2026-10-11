"""Phase 1 -- Network containment (SOP 2, Phase 1).

Called by Person 1's Logic App the moment Sentinel raises an incident. Builds a
deny-by-default NSG named ``Forensic-Isolation-NSG-<IncidentID>``, swaps it onto
every NIC of the target VM, and returns a write-only SAS URL that the Phase 2
acquisition script uses to stream memory into the enclave.

Containment must happen *before* acquisition: an attacker with an active session
on the box can wipe or tamper with memory while the dump is in flight.

Two properties matter for forensic soundness:

* The VM is **isolated, not deallocated.** Volatile memory -- the whole point of
  the acquisition -- is lost the instant the VM is stopped.
* The previous NSG assignment of each NIC is captured and returned so the
  responder can restore the original network posture after the investigation.
"""

import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import NetworkSecurityGroup
from shared import clients, config, sas

bp = func.Blueprint()

LOGGER = logging.getLogger(__name__)

NSG_NAME_PREFIX = "Forensic-Isolation-NSG-"
# Azure caps NSG names at 80 characters.
MAX_INCIDENT_SLUG = 80 - len(NSG_NAME_PREFIX)

# The lowest priority Azure accepts is 4096. Sitting there means every explicit
# rule an operator adds later still wins, but the platform defaults do not.
DENY_ALL_PRIORITY = 4096
ALLOW_STORAGE_PRIORITY = 100

_VM_ID = re.compile(
    r"^/subscriptions/(?P<subscription>[^/]+)"
    r"/resourceGroups/(?P<resource_group>[^/]+)"
    r"/providers/Microsoft\.Compute/virtualMachines/(?P<name>[^/]+)/?$",
    re.IGNORECASE,
)

_NIC_ID = re.compile(
    r"^/subscriptions/(?P<subscription>[^/]+)"
    r"/resourceGroups/(?P<resource_group>[^/]+)"
    r"/providers/Microsoft\.Network/networkInterfaces/(?P<name>[^/]+)/?$",
    re.IGNORECASE,
)


class ContainmentError(ValueError):
    """Raised when the Logic App payload cannot be resolved to a target VM."""


def parse_target_vm(payload):
    """Resolve ``(subscription_id, resource_group, vm_name)`` from the payload.

    Person 1's Logic App may send the target as a full ARM resource ID, as a
    nested object, or as flat properties, depending on which Sentinel entity
    mapping fired. All three are accepted so a playbook change on their side
    cannot silently break containment on ours.
    """
    if not isinstance(payload, dict):
        raise ContainmentError("Request body must be a JSON object.")

    lowered = {str(key).lower(): value for key, value in payload.items()}
    target = lowered.get("targetvm")

    if isinstance(target, str):
        match = _VM_ID.match(target.strip())
        if match:
            return (
                match.group("subscription"),
                match.group("resource_group"),
                match.group("name"),
            )
        # A bare VM name: subscription and resource group must come from the
        # surrounding payload or from configuration.
        vm_name = target.strip()
    elif isinstance(target, dict):
        nested = {str(key).lower(): value for key, value in target.items()}
        resource_id = nested.get("id") or nested.get("resourceid")
        if isinstance(resource_id, str):
            match = _VM_ID.match(resource_id.strip())
            if match:
                return (
                    match.group("subscription"),
                    match.group("resource_group"),
                    match.group("name"),
                )
        vm_name = nested.get("name") or nested.get("vmname")
        lowered = dict(lowered)
        for key in ("subscriptionid", "resourcegroup", "resourcegroupname"):
            if nested.get(key) and not lowered.get(key):
                lowered[key] = nested[key]
    else:
        vm_name = lowered.get("vmname") or lowered.get("targetvmname")

    if not vm_name:
        raise ContainmentError(
            "Payload does not identify a target VM. Supply 'TargetVM' as an "
            "ARM resource ID, as an object with an 'id', or as a name "
            "alongside 'SubscriptionId' and 'ResourceGroup'."
        )

    subscription = (
        lowered.get("subscriptionid")
        or lowered.get("subscription")
        or config.get("AZURE_SUBSCRIPTION_ID")
    )
    resource_group = (
        lowered.get("resourcegroup")
        or lowered.get("resourcegroupname")
        or config.get("TARGET_RESOURCE_GROUP")
    )

    if not subscription or not resource_group:
        raise ContainmentError(
            f"Target VM '{vm_name}' was given by name, but the subscription ID and/or "
            "resource group could not be resolved from the payload or "
            "configuration."
        )
    return str(subscription), str(resource_group), str(vm_name)


def isolation_nsg_name(incident_id):
    """Return the NSG name for an incident, truncated to Azure's 80-char cap."""
    return NSG_NAME_PREFIX + sas.slug(incident_id)[:MAX_INCIDENT_SLUG]


def build_isolation_rules(storage_prefix=None, extra_allow_tags=None, storage_port=443):
    """Return the deny-by-default rule set for the isolation NSG.

    ``storage_prefix`` defaults to the regional ``Storage`` service tag, which
    is narrower than the global one. Set ``EVIDENCE_STORAGE_SERVICE_TAG`` to a
    private endpoint address to narrow it further to the single enclave account.
    """
    storage_prefix = storage_prefix or config.get("EVIDENCE_STORAGE_SERVICE_TAG", "Storage")
    rules = [
        {
            "name": "Allow-Evidence-Storage-Outbound",
            "priority": ALLOW_STORAGE_PRIORITY,
            "direction": "Outbound",
            "access": "Allow",
            "protocol": "Tcp",
            "source_address_prefix": "*",
            "source_port_range": "*",
            "destination_address_prefix": storage_prefix,
            "destination_port_range": str(storage_port),
            "description": (
                "Sole permitted egress: streaming the memory image to the "
                "forensic enclave storage account."
            ),
        }
    ]

    priority = ALLOW_STORAGE_PRIORITY + 10
    for tag in extra_allow_tags or config.get_list("CONTAINMENT_EXTRA_ALLOW_TAGS"):
        rules.append(
            {
                "name": f"Allow-{sas.slug(tag)}-Outbound",
                "priority": priority,
                "direction": "Outbound",
                "access": "Allow",
                "protocol": "Tcp",
                "source_address_prefix": "*",
                "source_port_range": "*",
                "destination_address_prefix": tag,
                "destination_port_range": "443",
                "description": (
                    f"Operator-approved containment exception for service tag '{tag}'."
                ),
            }
        )
        priority += 10

    rules.append(
        {
            "name": "Deny-All-Inbound",
            "priority": DENY_ALL_PRIORITY,
            "direction": "Inbound",
            "access": "Deny",
            "protocol": "*",
            "source_address_prefix": "*",
            "source_port_range": "*",
            "destination_address_prefix": "*",
            "destination_port_range": "*",
            "description": (
                "Required: Azure's default AllowVnetInBound rule (priority "
                "65000) would otherwise permit lateral movement from every "
                "peer in the VNet."
            ),
        }
    )
    rules.append(
        {
            "name": "Deny-All-Outbound",
            "priority": DENY_ALL_PRIORITY,
            "direction": "Outbound",
            "access": "Deny",
            "protocol": "*",
            "source_address_prefix": "*",
            "source_port_range": "*",
            "destination_address_prefix": "*",
            "destination_port_range": "*",
            "description": (
                "Required: overrides the default AllowInternetOutBound rule "
                "(priority 65001) that would leave C2 channels open."
            ),
        }
    )
    return rules


def ensure_isolation_nsg(network_client, resource_group, location, incident_id):
    """Create or update the incident's isolation NSG. Idempotent by design."""
    name = isolation_nsg_name(incident_id)
    parameters = {
        "location": location,
        "security_rules": build_isolation_rules(),
        "tags": {
            "react:purpose": "forensic-isolation",
            "react:incidentId": str(incident_id),
        },
    }
    logging.info("Creating isolation NSG %s in %s.", name, resource_group)
    return network_client.network_security_groups.begin_create_or_update(
        resource_group, name, parameters
    ).result()


def swap_nics(network_client, vm, nsg_id):
    """Attach ``nsg_id`` to every NIC on ``vm``, recording what it replaced.

    Only NIC-level NSGs are touched. Subnet-level NSGs belong to Person 1's
    network design, and because Azure requires *both* the subnet and NIC NSG to
    allow a flow, adding ours can only ever tighten access -- never loosen it.
    """
    results = []
    profile = getattr(vm, "network_profile", None)
    references = list(getattr(profile, "network_interfaces", None) or [])
    if not references:
        raise ContainmentError(f"VM '{vm.name}' has no network interfaces to contain.")

    for reference in references:
        match = _NIC_ID.match(reference.id or "")
        if not match:
            raise ContainmentError(f"Unrecognised network interface ID: {reference.id}")
        nic_group = match.group("resource_group")
        nic_name = match.group("name")

        nic = network_client.network_interfaces.get(nic_group, nic_name)
        previous = getattr(nic.network_security_group, "id", None)

        if previous == nsg_id:
            # Replayed invocation: leave it alone, and do not clobber the
            # recorded original NSG with our own.
            results.append({"nic": nic_name, "previousNsgId": previous, "changed": False})
            continue

        nic.network_security_group = NetworkSecurityGroup(id=nsg_id)
        network_client.network_interfaces.begin_create_or_update(nic_group, nic_name, nic).result()
        logging.info("Contained NIC %s (previous NSG: %s).", nic_name, previous or "none")
        results.append({"nic": nic_name, "previousNsgId": previous, "changed": True})
    return results


def handle_containment(req, credential=None):
    """Core handler, kept free of decorators so it is directly unit-testable."""
    try:
        payload = req.get_json()
    except ValueError:
        return _json_response(400, {"error": "Request body is not valid JSON."})

    incident_id = None
    if isinstance(payload, dict):
        lowered = {str(key).lower(): value for key, value in payload.items()}
        incident_id = lowered.get("incidentid") or lowered.get("incident_id")
    if not incident_id:
        return _json_response(400, {"error": "Payload must include 'IncidentId'."})

    try:
        subscription, resource_group, vm_name = parse_target_vm(payload)
    except ContainmentError as error:
        return _json_response(400, {"error": str(error)})

    logging.info("Containment requested for VM %s (incident %s).", vm_name, incident_id)

    credential = credential or clients.credential()
    compute_client = clients.compute_client(subscription, cred=credential)
    network_client = clients.network_client(subscription, cred=credential)

    vm = compute_client.virtual_machines.get(resource_group, vm_name)
    nsg = ensure_isolation_nsg(network_client, resource_group, vm.location, incident_id)
    swaps = swap_nics(network_client, vm, nsg.id)

    blob_name = sas.build_blob_name(incident_id, vm_name)
    upload_url, expires_on = sas.mint_write_only_sas(blob_name, credential=credential)

    # `uploadUrl` is a bearer credential. It is returned to the Logic App over
    # TLS and is deliberately absent from every log statement above.
    return _json_response(
        200,
        {
            "status": "contained",
            "incidentId": str(incident_id),
            "targetVm": vm_name,
            "resourceGroup": resource_group,
            "isolationNsgId": nsg.id,
            "isolationNsgName": nsg.name,
            "interfaces": swaps,
            "blobName": blob_name,
            "uploadUrl": upload_url,
            "uploadUrlExpiresOn": expires_on.isoformat(),
        },
    )


def _json_response(status_code, body):
    return func.HttpResponse(
        json.dumps(body),
        status_code=status_code,
        mimetype="application/json",
    )


@bp.route(route="contain", methods=["POST"])
def network_containment(req: func.HttpRequest) -> func.HttpResponse:
    try:
        return handle_containment(req)
    except config.ConfigError as error:
        logging.exception("Containment blocked by configuration error.")
        return _json_response(500, {"error": str(error)})
    except Exception as error:  # noqa: BLE001 - the Logic App needs a verdict
        logging.exception("Containment failed.")
        return _json_response(500, {"error": f"Containment failed: {error}"})


# ============================================================================
# Legacy v1 contract (function.json entry point + Person 1 Logic App).
#
# ``function.json`` still declares ``__init__.py`` as the script file for the
# classic Functions host, which resolves the ``main`` entry point, and Person
# 1's Logic App (``src/logic-apps/workflow.json``) was built against the
# response contract below (``status`` of ``Contained``/``Bypassed``,
# ``IsolationNSG``, and the Critical-Infrastructure tag bypass). The helpers
# above power the v2 blueprint; this section keeps the deployed endpoint and
# the P1<->P2 contract stable.
# ============================================================================

_REQUIRED_FIELDS = {"IncidentID", "TargetVM", "IPAddress", "SubscriptionID", "IncidentSeverity"}
_RESOURCE_ID_PATTERN = re.compile(
    r"^/subscriptions/(?P<subscription>[^/]+)/resourceGroups/(?P<resource_group>[^/]+)/"
    r"providers/Microsoft\.Compute/virtualMachines/(?P<name>[^/]+)$",
    re.IGNORECASE,
)
_NAME_SAFE_PATTERN = re.compile(r"[^A-Za-z0-9_-]")


class ValidationError(ValueError):
    """A caller supplied a request that cannot safely be actioned."""


@dataclass(frozen=True)
class Incident:
    incident_id: str
    target_vm: str
    ip_address: str
    subscription_id: str
    severity: str
    resource_group: str | None = None


def _parse_incident(req: func.HttpRequest) -> Incident:
    try:
        data: dict[str, Any] = req.get_json()
    except ValueError as exc:
        raise ValidationError("Request body must be valid JSON.") from exc

    missing = sorted(_REQUIRED_FIELDS - data.keys())
    if missing:
        raise ValidationError(f"Missing required payload fields: {', '.join(missing)}.")

    values = {field: data[field] for field in _REQUIRED_FIELDS}
    if not all(isinstance(value, str) and value.strip() for value in values.values()):
        raise ValidationError("All payload contract fields must be non-empty strings.")
    if values["IncidentSeverity"] not in ("High", "Critical"):
        raise ValidationError(
            "Network containment only accepts IncidentSeverity 'High' or 'Critical'."
        )

    match = _RESOURCE_ID_PATTERN.fullmatch(values["TargetVM"].rstrip("/"))
    if not match:
        raise ValidationError(
            "TargetVM must be a full Microsoft.Compute/virtualMachines resource ID."
        )
    if match.group("subscription").lower() != values["SubscriptionID"].lower():
        raise ValidationError("SubscriptionID does not match the subscription in TargetVM.")

    provided_rg = data.get("ResourceGroupName")
    if provided_rg and provided_rg.lower() != match.group("resource_group").lower():
        raise ValidationError("ResourceGroupName does not match the resource group in TargetVM.")

    return Incident(
        incident_id=values["IncidentID"],
        target_vm=values["TargetVM"].rstrip("/"),
        ip_address=values["IPAddress"],
        subscription_id=values["SubscriptionID"],
        severity=values["IncidentSeverity"],
        resource_group=provided_rg or match.group("resource_group"),
    )


def _resource_parts(resource_id: str, resource_type: str) -> tuple[str, str, str]:
    """Extract subscription, resource group, and resource name from an Azure ID."""
    expression = (
        r"^/subscriptions/(?P<subscription>[^/]+)/resourceGroups/(?P<resource_group>[^/]+)/"
        + re.escape(resource_type)
        + r"/(?P<name>[^/]+)$"
    )
    match = re.fullmatch(expression, resource_id, flags=re.IGNORECASE)
    if not match:
        raise ValidationError(f"Unexpected Azure resource ID: {resource_id}")
    return match.group("subscription"), match.group("resource_group"), match.group("name")


def _nsg_name(incident_id: str) -> str:
    safe_id = _NAME_SAFE_PATTERN.sub("-", incident_id).strip("-_") or "incident"
    # NSG names cannot exceed 80 characters.
    return f"Forensic-Isolation-NSG-{safe_id}"[:80]


def _private_endpoint_prefixes() -> list[str]:
    """Read optional comma-separated IP/CIDR prefixes for evidence Private Endpoints."""
    raw_prefixes = os.getenv("EVIDENCE_STORAGE_PRIVATE_ENDPOINT_PREFIXES", "")
    return [prefix.strip() for prefix in raw_prefixes.split(",") if prefix.strip()]


def _rule_payload(
    name: str, priority: int, direction: str, access: str, destination: str
) -> dict[str, Any]:
    return {
        "name": name,
        "priority": priority,
        "protocol": "*",
        "access": access,
        "direction": direction,
        "source_address_prefix": "*",
        "source_port_range": "*",
        "destination_address_prefix": destination,
        "destination_port_range": "*",
    }


def _create_isolation_nsg(
    client: NetworkManagementClient, resource_group: str, incident_id: str
) -> str:
    nsg_name = _nsg_name(incident_id)
    region = os.getenv("REGION_NAME", os.getenv("AZURE_REGION", "eastus"))
    client.network_security_groups.begin_create_or_update(
        resource_group,
        nsg_name,
        {"location": region, "tags": {"Purpose": "ForensicIsolation", "IncidentID": incident_id}},
    ).result()

    # Lower numbers are evaluated first: permit only evidence-upload traffic
    # before denying all other egress. The Storage service tag supports Azure
    # Storage service endpoints; explicit prefixes support Private Endpoints.
    rules = [_rule_payload("Allow-Azure-Storage-Egress", 100, "Outbound", "Allow", "Storage")]
    for offset, prefix in enumerate(_private_endpoint_prefixes(), start=101):
        if offset > 199:
            raise ValidationError("At most 99 evidence private endpoint prefixes are supported.")
        rules.append(
            _rule_payload(
                f"Allow-Evidence-PrivateLink-{offset}", offset, "Outbound", "Allow", prefix
            )
        )
    rules.extend(
        [
            _rule_payload("Deny-All-Inbound", 4095, "Inbound", "Deny", "*"),
            _rule_payload("Deny-All-Outbound", 4096, "Outbound", "Deny", "*"),
        ]
    )
    for rule in rules:
        client.security_rules.begin_create_or_update(
            resource_group, nsg_name, rule["name"], rule
        ).result()
    return nsg_name


def _primary_nic_id(vm: Any) -> str:
    interfaces = vm.network_profile.network_interfaces if vm.network_profile else []
    if not interfaces:
        raise ValidationError("Target VM does not have an attached network interface.")
    primary = next((nic for nic in interfaces if nic.primary), interfaces[0])
    if not primary.id:
        raise ValidationError("Target VM's primary NIC has no resource ID.")
    return primary.id


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Create an isolation NSG, then attach it to the target VM's primary NIC."""
    try:
        incident = _parse_incident(req)
        _, vm_resource_group, vm_name = _resource_parts(
            incident.target_vm, "providers/Microsoft.Compute/virtualMachines"
        )
        credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        network_client = NetworkManagementClient(credential, incident.subscription_id)

        # The compute client is intentionally imported lazily: this keeps the
        # declared network SDK as the primary dependency while resolving NICs
        # from the VM's authoritative network profile.
        from azure.mgmt.compute import ComputeManagementClient

        compute_client = ComputeManagementClient(credential, incident.subscription_id)
        vm = compute_client.virtual_machines.get(vm_resource_group, vm_name)
        nic_id = _primary_nic_id(vm)

        # Check for Critical-Infrastructure tag
        vm_tags = vm.tags or {}
        is_critical_infrastructure = vm_tags.get("Critical-Infrastructure", "").lower() == "true"

        if is_critical_infrastructure:
            LOGGER.warning(
                "Incident %s: VM %s has Critical-Infrastructure:True tag. "
                "Skipping network isolation per policy. Memory/disk acquisition will proceed.",
                incident.incident_id,
                vm_name,
            )
            return func.HttpResponse(
                json.dumps(
                    {
                        "status": "Bypassed",
                        "IncidentID": incident.incident_id,
                        "TargetVM": incident.target_vm,
                        "Reason": "Critical-Infrastructure tag set to True",
                        "NetworkInterface": nic_id,
                        "Action": "Network isolation skipped; acquisition proceeds",
                    }
                ),
                status_code=200,
                mimetype="application/json",
            )

        _, nic_resource_group, nic_name = _resource_parts(
            nic_id, "providers/Microsoft.Network/networkInterfaces"
        )

        nsg_name = _create_isolation_nsg(network_client, nic_resource_group, incident.incident_id)
        nic = network_client.network_interfaces.get(nic_resource_group, nic_name)
        previous_nsg_id = nic.network_security_group.id if nic.network_security_group else None
        nic.network_security_group = {
            "id": network_client.network_security_groups.get(nic_resource_group, nsg_name).id
        }
        network_client.network_interfaces.begin_create_or_update(
            nic_resource_group, nic_name, nic
        ).result()

        LOGGER.warning(
            "Incident %s: attached isolation NSG %s to NIC %s",
            incident.incident_id,
            nsg_name,
            nic_name,
        )
        return func.HttpResponse(
            json.dumps(
                {
                    "status": "Contained",
                    "IncidentID": incident.incident_id,
                    "TargetVM": incident.target_vm,
                    "NetworkInterface": nic_id,
                    "IsolationNSG": nsg_name,
                    "PreviousNSGId": previous_nsg_id,
                    "CriticalInfrastructureBypass": False,
                }
            ),
            status_code=200,
            mimetype="application/json",
        )
    except ValidationError as exc:
        return func.HttpResponse(
            json.dumps({"status": "Rejected", "error": str(exc)}),
            status_code=400,
            mimetype="application/json",
        )
    except KeyError as exc:
        LOGGER.exception("Containment function configuration is incomplete.")
        return func.HttpResponse(
            json.dumps(
                {"status": "Failed", "error": f"Missing application setting: {exc.args[0]}"}
            ),
            status_code=500,
            mimetype="application/json",
        )
    except Exception:  # Azure SDK errors are deliberately not exposed to callers.
        LOGGER.exception("Network containment failed.")
        return func.HttpResponse(
            json.dumps(
                {"status": "Failed", "error": "Network containment could not be completed."}
            ),
            status_code=500,
            mimetype="application/json",
        )
