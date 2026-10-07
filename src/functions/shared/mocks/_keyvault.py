"""Stand-in for ``azure.keyvault.secrets.SecretClient``.

REQ-3.3.3 names Key Vault as the source of the SAS-signing material. In mock
mode the vault holds one obviously-fake storage account key, so the
``SAS_MODE=key-vault`` path is exercised without a real secret existing.
"""
from . import _world
from ._world import Model, MockAzureError


class MockSecretClient(object):
    def __init__(self, vault_url, credential=None, **kwargs):
        self.vault_url = vault_url
        self._credential = credential
        self._world = _world.world()

    def get_secret(self, name, version=None, **kwargs):
        try:
            value = self._world.secrets[(self.vault_url, name)]
        except KeyError:
            raise MockAzureError(
                "Secret '{0}' not found in vault '{1}'.".format(name, self.vault_url)
            )
        return Model(name=name, value=value, properties=Model(vault_url=self.vault_url))

    def set_secret(self, name, value, **kwargs):
        self._world.secrets[(self.vault_url, name)] = value
        return Model(name=name, value=value)
