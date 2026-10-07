"""Unit tests for write-only SAS minting.

The SAS is generated with a throwaway account key so the token can be parsed
and asserted on without contacting Azure.
"""

import base64
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs

import pytest
from shared import config, sas

FAKE_ACCOUNT_KEY = base64.b64encode(b"react-test-key-material-0123456789").decode()


@pytest.fixture(autouse=True)
def _storage_env(monkeypatch):
    monkeypatch.setenv("EVIDENCE_STORAGE_ACCOUNT", "reactenclave01")
    monkeypatch.setenv("EVIDENCE_CONTAINER", "evidence")
    monkeypatch.setenv("SAS_MODE", "key-vault")
    monkeypatch.setattr(
        sas, "_account_key_from_key_vault", lambda credential=None: FAKE_ACCOUNT_KEY
    )


def _token(url):
    return parse_qs(url.split("?", 1)[1])


# --- Blob naming -------------------------------------------------------------


def test_blob_name_layout_groups_by_incident_and_host():
    now = datetime(2024, 5, 1, 12, 30, 0, tzinfo=UTC)
    name = sas.build_blob_name("INC-2024-0042", "web-01", now=now)
    assert name == "INC-2024-0042/web-01/memory-20240501T123000Z.raw"


def test_blob_name_sanitises_path_traversal():
    name = sas.build_blob_name("../../etc", "a/b", now=datetime.now(UTC))
    assert ".." not in name
    assert name.count("/") == 2


def test_blob_names_do_not_collide_across_runs():
    early = datetime(2024, 5, 1, 12, 0, 0, tzinfo=UTC)
    later = early + timedelta(seconds=1)
    assert sas.build_blob_name("INC-1", "web-01", now=early) != sas.build_blob_name(
        "INC-1", "web-01", now=later
    )


# --- Token properties --------------------------------------------------------


def test_token_is_write_only():
    """No read, list or delete: a scraped token cannot exfiltrate or tamper."""
    url, _expiry = sas.mint_write_only_sas("INC-1/web-01/memory.raw")
    permissions = _token(url)["sp"][0]
    assert set(permissions) <= set("acw")
    assert "w" in permissions and "c" in permissions
    for forbidden in "rdl":
        assert forbidden not in permissions


def test_default_ttl_is_sixty_minutes():
    now = datetime(2024, 5, 1, 12, 0, 0, tzinfo=UTC)
    _url, expiry = sas.mint_write_only_sas("INC-1/mem.raw", now=now)
    assert expiry - now == timedelta(minutes=60)


def test_ttl_is_configurable(monkeypatch):
    monkeypatch.setenv("SAS_TTL_MINUTES", "15")
    now = datetime(2024, 5, 1, 12, 0, 0, tzinfo=UTC)
    _url, expiry = sas.mint_write_only_sas("INC-1/mem.raw", now=now)
    assert expiry - now == timedelta(minutes=15)


def test_start_time_is_backdated_for_clock_skew():
    now = datetime(2024, 5, 1, 12, 0, 0, tzinfo=UTC)
    url, _expiry = sas.mint_write_only_sas("INC-1/mem.raw", now=now)
    start = _token(url)["st"][0]
    assert start.startswith("2024-05-01T11:55")


def test_token_is_https_only():
    url, _expiry = sas.mint_write_only_sas("INC-1/mem.raw")
    assert _token(url)["spr"][0] == "https"
    assert url.startswith("https://reactenclave01.blob.core.windows.net/evidence/")


def test_token_is_scoped_to_a_single_blob():
    url, _expiry = sas.mint_write_only_sas("INC-1/web-01/memory.raw")
    assert _token(url)["sr"][0] == "b"


# --- Configuration guards ----------------------------------------------------


def test_unknown_sas_mode_is_rejected(monkeypatch):
    monkeypatch.setenv("SAS_MODE", "account-key-in-app-settings")
    with pytest.raises(config.ConfigError):
        sas.mint_write_only_sas("INC-1/mem.raw")


def test_missing_storage_account_is_reported(monkeypatch):
    monkeypatch.delenv("EVIDENCE_STORAGE_ACCOUNT", raising=False)
    with pytest.raises(config.ConfigError):
        sas.mint_write_only_sas("INC-1/mem.raw")
