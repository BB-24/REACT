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
            f"Missing required application setting '{name}'. Check the Function "
            "App configuration and its Key Vault references."
        )
    return value


def get_int(name, default):
    """Return an integer application setting, falling back to ``default``."""
    raw = get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as err:
        raise ConfigError(f"Application setting '{name}' must be an integer, got '{raw}'.") from err


def get_list(name, default=None):
    """Return a comma-separated application setting as a list of strings."""
    raw = get(name)
    if raw is None:
        return list(default or [])
    return [item.strip() for item in raw.split(",") if item.strip()]


_TRUTHY = ("1", "true", "yes", "on")
_FALSY = ("0", "false", "no", "off")


def get_bool(name, default=False):
    """Return a boolean application setting.

    Azure application settings are always strings, so ``"false"`` must not be
    read as truthy -- which is exactly the bug that would silently leave mock
    mode enabled in production.
    """
    raw = get(name)
    if raw is None:
        return default
    lowered = raw.strip().lower()
    if lowered in _TRUTHY:
        return True
    if lowered in _FALSY:
        return False
    raise ConfigError(
        f"Application setting '{name}' must be a boolean (one of "
        f"{', '.join(_TRUTHY + _FALSY)}), got '{raw}'."
    )
