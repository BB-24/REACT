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
import re

import azure.functions as func
from azure.mgmt.network.models import NetworkSecurityGroup
from shared import clients, config, sas

bp = func.Blueprint()

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
