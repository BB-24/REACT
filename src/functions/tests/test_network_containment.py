"""Unit tests for the Phase 1 containment logic.

No Azure calls: the management clients are replaced with recording doubles so
the NSG rule set and NIC swap behaviour are asserted directly.
"""
import json

import azure.functions as func
import pytest

from NetworkContainment import (
    ALLOW_STORAGE_PRIORITY,
    DENY_ALL_PRIORITY,
    ContainmentError,
    build_isolation_rules,
    handle_containment,
    isolation_nsg_name,
    parse_target_vm,
    swap_nics,
)

VM_RESOURCE_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000001"
    "/resourceGroups/rg-victims"
    "/providers/Microsoft.Compute/virtualMachines/web-01"
)
NIC_RESOURCE_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000001"
    "/resourceGroups/rg-victims"
    "/providers/Microsoft.Network/networkInterfaces/web-01-nic"
)


# --- parse_target_vm ---------------------------------------------------------


def test_parses_full_resource_id():
    result = parse_target_vm({"IncidentId": "INC-1", "TargetVM": VM_RESOURCE_ID})
    assert result == (
        "00000000-0000-0000-0000-000000000001",
        "rg-victims",
        "web-01",
    )


def test_parses_nested_object_with_id():
    payload = {"TargetVM": {"id": VM_RESOURCE_ID, "name": "web-01"}}
    assert parse_target_vm(payload)[2] == "web-01"


def test_parses_flat_name_with_scope():
    payload = {
        "TargetVM": "web-01",
        "SubscriptionId": "sub-123",
        "ResourceGroup": "rg-victims",
    }
    assert parse_target_vm(payload) == ("sub-123", "rg-victims", "web-01")


def test_payload_keys_are_case_insensitive():
    payload = {"targetvm": VM_RESOURCE_ID}
    assert parse_target_vm(payload)[1] == "rg-victims"


def test_bare_name_without_scope_is_rejected(monkeypatch):
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    monkeypatch.delenv("TARGET_RESOURCE_GROUP", raising=False)
    with pytest.raises(ContainmentError):
        parse_target_vm({"TargetVM": "web-01"})


def test_missing_target_is_rejected():
    with pytest.raises(ContainmentError):
        parse_target_vm({"IncidentId": "INC-1"})


# --- NSG rule construction ---------------------------------------------------


def test_nsg_name_follows_sop_convention():
    assert isolation_nsg_name("INC-2024-0042") == (
        "Forensic-Isolation-NSG-INC-2024-0042"
    )


def test_nsg_name_is_sanitised_and_truncated():
    name = isolation_nsg_name("INC/2024 0042" + "x" * 200)
    assert len(name) <= 80
    assert "/" not in name and " " not in name


def test_exactly_one_allow_rule_by_default(monkeypatch):
    monkeypatch.delenv("CONTAINMENT_EXTRA_ALLOW_TAGS", raising=False)
    rules = build_isolation_rules(storage_prefix="Storage.eastus")
    allows = [rule for rule in rules if rule["access"] == "Allow"]
    assert len(allows) == 1
    assert allows[0]["destination_address_prefix"] == "Storage.eastus"
    assert allows[0]["destination_port_range"] == "443"
    assert allows[0]["priority"] == ALLOW_STORAGE_PRIORITY


def test_both_directions_are_denied_at_lowest_priority(monkeypatch):
    monkeypatch.delenv("CONTAINMENT_EXTRA_ALLOW_TAGS", raising=False)
    rules = build_isolation_rules()
    denies = {
        rule["direction"]: rule for rule in rules if rule["access"] == "Deny"
    }
    assert set(denies) == {"Inbound", "Outbound"}
    for rule in denies.values():
        assert rule["priority"] == DENY_ALL_PRIORITY
        assert rule["protocol"] == "*"
        assert rule["destination_port_range"] == "*"


def test_allow_rule_outranks_the_deny_rules(monkeypatch):
    """Lower priority number wins in Azure; the storage allow must be first."""
    monkeypatch.delenv("CONTAINMENT_EXTRA_ALLOW_TAGS", raising=False)
    rules = build_isolation_rules()
    allow = next(rule for rule in rules if rule["access"] == "Allow")
    denies = [rule for rule in rules if rule["access"] == "Deny"]
    assert all(allow["priority"] < deny["priority"] for deny in denies)


def test_extra_allow_tags_are_appended(monkeypatch):
    monkeypatch.setenv("CONTAINMENT_EXTRA_ALLOW_TAGS", "AzureActiveDirectory,AzureMonitor")
    rules = build_isolation_rules()
    allows = [rule for rule in rules if rule["access"] == "Allow"]
    assert len(allows) == 3
    assert len({rule["priority"] for rule in allows}) == 3


# --- NIC swap ----------------------------------------------------------------


class _FakePoller:
    def __init__(self, value=None):
        self._value = value

    def result(self):
        return self._value


class _FakeNic:
    def __init__(self, nsg_id=None):
        self.network_security_group = (
            type("Nsg", (), {"id": nsg_id})() if nsg_id else None
        )


class _FakeNicOperations:
    def __init__(self, nic):
        self.nic = nic
        self.updated = []

    def get(self, resource_group, name):
        return self.nic

    def begin_create_or_update(self, resource_group, name, parameters):
        self.updated.append((name, parameters))
        return _FakePoller(parameters)


class _FakeNetworkClient:
    def __init__(self, nic):
        self.network_interfaces = _FakeNicOperations(nic)


def _fake_vm(nic_id=NIC_RESOURCE_ID):
    reference = type("Ref", (), {"id": nic_id})()
    profile = type("Profile", (), {"network_interfaces": [reference]})()
    return type("Vm", (), {"name": "web-01", "location": "eastus",
                           "network_profile": profile})()


def test_swap_records_the_previous_nsg_for_rollback():
    client = _FakeNetworkClient(_FakeNic("/old/nsg"))
    result = swap_nics(client, _fake_vm(), "/new/nsg")
    assert result == [
        {"nic": "web-01-nic", "previousNsgId": "/old/nsg", "changed": True}
    ]
    assert client.network_interfaces.updated[0][0] == "web-01-nic"


def test_swap_is_idempotent_and_preserves_the_original_nsg():
    """A replayed Logic App call must not record our own NSG as the original."""
    client = _FakeNetworkClient(_FakeNic("/new/nsg"))
    result = swap_nics(client, _fake_vm(), "/new/nsg")
    assert result[0]["changed"] is False
    assert result[0]["previousNsgId"] == "/new/nsg"
    assert client.network_interfaces.updated == []


def test_nic_without_prior_nsg_is_handled():
    client = _FakeNetworkClient(_FakeNic(None))
    result = swap_nics(client, _fake_vm(), "/new/nsg")
    assert result[0]["previousNsgId"] is None
    assert result[0]["changed"] is True


def test_vm_with_no_nics_is_rejected():
    vm = type("Vm", (), {"name": "web-01", "location": "eastus",
                         "network_profile": None})()
    with pytest.raises(ContainmentError):
        swap_nics(_FakeNetworkClient(_FakeNic(None)), vm, "/new/nsg")


# --- HTTP handler ------------------------------------------------------------


def _request(body):
    return func.HttpRequest(
        method="POST",
        url="/api/contain",
        headers={"Content-Type": "application/json"},
        body=json.dumps(body).encode("utf-8"),
    )


def test_missing_incident_id_returns_400():
    response = handle_containment(_request({"TargetVM": VM_RESOURCE_ID}))
    assert response.status_code == 400
    assert "IncidentId" in json.loads(response.get_body())["error"]


def test_unresolvable_target_returns_400(monkeypatch):
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    monkeypatch.delenv("TARGET_RESOURCE_GROUP", raising=False)
    response = handle_containment(_request({"IncidentId": "INC-1"}))
    assert response.status_code == 400


def test_malformed_json_returns_400():
    request = func.HttpRequest(
        method="POST",
        url="/api/contain",
        headers={"Content-Type": "application/json"},
        body=b"not json",
    )
    assert handle_containment(request).status_code == 400
