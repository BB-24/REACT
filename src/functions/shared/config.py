"""Environment-backed configuration.

Every value here comes from Azure Functions application settings, which are
sourced from Key Vault references in Person 1's Bicep deployment. Nothing in
this repository may contain a literal connection string or account key.
"""
import os


class ConfigError(RuntimeError):
    """Raised when a required application setting is missing or malformed."""


def get(name, default=None):
    """Return an application setting, or ``default`` when unset or empty."""
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


def require(name):
    """Return an application setting, raising ``ConfigError`` when unset."""
    value = get(name)
    if value is None:
        raise ConfigError(
            "Missing required application setting '{0}'. Check the Function "
            "App configuration and its Key Vault references.".format(name)
        )
    return value


def get_int(name, default):
    """Return an integer application setting, falling back to ``default``."""
    raw = get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        raise ConfigError(
            "Application setting '{0}' must be an integer, got '{1}'.".format(
                name, raw
            )
        )


def get_list(name, default=None):
    """Return a comma-separated application setting as a list of strings."""
    raw = get(name)
    if raw is None:
        return list(default or [])
    return [item.strip() for item in raw.split(",") if item.strip()]
