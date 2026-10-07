"""Stand-in for ``azure.mgmt.network.NetworkManagementClient``.

Only the two operation groups Phase 1 containment touches: creating the
isolation NSG and swapping it onto each NIC.
"""
from . import _world
from ._compute import _Poller
from ._world import Model, MockAzureError


class _NetworkSecurityGroupsOperations(object):
    def __init__(self, world, subscription_id):
        self._world = world
        self._subscription = subscription_id

    def begin_create_or_update(self, resource_group_name, network_security_group_name,
                               parameters, **kwargs):
        payload = (
            parameters if isinstance(parameters, dict) else parameters.as_dict()
        )
        identifier = _world.nsg_id(
            self._subscription, resource_group_name, network_security_group_name
        )
        record = Model(
            id=identifier,
            name=network_security_group_name,
            location=payload.get("location", _world.DEFAULT_LOCATION),
            security_rules=list(payload.get("security_rules") or []),
            tags=dict(payload.get("tags") or {}),
            provisioning_state="Succeeded",
        )
        self._world.nsgs[identifier.lower()] = record
        return _Poller(record)

    def get(self, resource_group_name, network_security_group_name, **kwargs):
        key = _world.nsg_id(
            self._subscription, resource_group_name, network_security_group_name
        ).lower()
        try:
            return self._world.nsgs[key]
        except KeyError:
            raise MockAzureError(
                "NSG '{0}' not found.".format(network_security_group_name)
            )


class _NetworkInterfacesOperations(object):
    def __init__(self, world, subscription_id):
        self._world = world
        self._subscription = subscription_id

    def get(self, resource_group_name, network_interface_name, **kwargs):
        key = _world.nic_id(
            self._subscription, resource_group_name, network_interface_name
        ).lower()
        try:
            return self._world.nics[key]
        except KeyError:
            raise MockAzureError(
                "NIC '{0}' not found in '{1}'.".format(
                    network_interface_name, resource_group_name
                )
            )

    def begin_create_or_update(self, resource_group_name, network_interface_name,
                               parameters, **kwargs):
        key = _world.nic_id(
            self._subscription, resource_group_name, network_interface_name
        ).lower()
        self._world.nics[key] = parameters
        return _Poller(parameters)


class MockNetworkManagementClient(object):
    def __init__(self, credential, subscription_id, **kwargs):
        self._credential = credential
        self.subscription_id = subscription_id
        estate = _world.world()
        self.network_security_groups = _NetworkSecurityGroupsOperations(
            estate, subscription_id
        )
        self.network_interfaces = _NetworkInterfacesOperations(
            estate, subscription_id
        )
