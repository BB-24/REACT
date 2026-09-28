"""HTTP-triggered network isolation for a confirmed high-severity incident.

TargetVM must be a full Azure virtual machine resource ID.  This avoids
guessing resource groups and makes the operation safe across subscriptions.
The Function App's managed identity needs Network Contributor on the target
resource group (or NIC/NSG resources).
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient


LOGGER = logging.getLogger(__name__)
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
        raise ValidationError("Network containment only accepts IncidentSeverity 'High' or 'Critical'.")

    match = _RESOURCE_ID_PATTERN.fullmatch(values["TargetVM"].rstrip("/"))
    if not match:
        raise ValidationError("TargetVM must be a full Microsoft.Compute/virtualMachines resource ID.")
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


def _rule_payload(name: str, priority: int, direction: str, access: str, destination: str) -> dict[str, Any]:
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


def _create_isolation_nsg(client: NetworkManagementClient, resource_group: str, incident_id: str) -> str:
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
        rules.append(_rule_payload(f"Allow-Evidence-PrivateLink-{offset}", offset, "Outbound", "Allow", prefix))
    rules.extend(
        [
            _rule_payload("Deny-All-Inbound", 4095, "Inbound", "Deny", "*"),
            _rule_payload("Deny-All-Outbound", 4096, "Outbound", "Deny", "*"),
        ]
    )
    for rule in rules:
        client.security_rules.begin_create_or_update(resource_group, nsg_name, rule["name"], rule).result()
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
        _, vm_resource_group, vm_name = _resource_parts(incident.target_vm, "providers/Microsoft.Compute/virtualMachines")
        credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        network_client = NetworkManagementClient(credential, incident.subscription_id)

        # The compute client is intentionally imported lazily: this keeps the
        # declared network SDK as the primary dependency while resolving NICs
        # from the VM's authoritative network profile.
        from azure.mgmt.compute import ComputeManagementClient

        compute_client = ComputeManagementClient(credential, incident.subscription_id)
        vm = compute_client.virtual_machines.get(vm_resource_group, vm_name)
        nic_id = _primary_nic_id(vm)
        _, nic_resource_group, nic_name = _resource_parts(nic_id, "providers/Microsoft.Network/networkInterfaces")

        nsg_name = _create_isolation_nsg(network_client, nic_resource_group, incident.incident_id)
        nic = network_client.network_interfaces.get(nic_resource_group, nic_name)
        previous_nsg_id = nic.network_security_group.id if nic.network_security_group else None
        nic.network_security_group = {"id": network_client.network_security_groups.get(nic_resource_group, nsg_name).id}
        network_client.network_interfaces.begin_create_or_update(nic_resource_group, nic_name, nic).result()

        LOGGER.warning("Incident %s: attached isolation NSG %s to NIC %s", incident.incident_id, nsg_name, nic_name)
        return func.HttpResponse(
            json.dumps({
                "status": "Contained",
                "IncidentID": incident.incident_id,
                "TargetVM": incident.target_vm,
                "NetworkInterface": nic_id,
                "IsolationNSG": nsg_name,
                "PreviousNSGId": previous_nsg_id,
            }),
            status_code=200,
            mimetype="application/json",
        )
    except ValidationError as exc:
        return func.HttpResponse(json.dumps({"status": "Rejected", "error": str(exc)}), status_code=400, mimetype="application/json")
    except KeyError as exc:
        LOGGER.exception("Containment function configuration is incomplete.")
        return func.HttpResponse(json.dumps({"status": "Failed", "error": f"Missing application setting: {exc.args[0]}"}), status_code=500, mimetype="application/json")
    except Exception:  # Azure SDK errors are deliberately not exposed to callers.
        LOGGER.exception("Network containment failed.")
        return func.HttpResponse(json.dumps({"status": "Failed", "error": "Network containment could not be completed."}), status_code=500, mimetype="application/json")
