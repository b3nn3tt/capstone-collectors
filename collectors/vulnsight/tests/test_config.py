"""Configuration loading and validation tests (offline, synthetic values only)."""

from __future__ import annotations

import pytest

from vulnsight.config import (
    ENV_FILE_NAME,
    EXAMPLE_ENV_FILE_NAME,
    REQUIRED_KEYS,
    ConfigError,
    load_config,
)
from conftest import (
    FAKE_ACCESS_KEY,
    FAKE_SECRET_KEY,
    env_values,
    make_config,
    write_env_file,
)


def test_load_valid_configuration(tmp_path):
    path = write_env_file(tmp_path, env_values())
    config = load_config(path)

    assert config.scheme == "https"
    assert config.host == "nessus.lab.invalid"
    assert config.port == 8834
    assert config.base_url == "https://nessus.lab.invalid:8834"
    assert config.endpoint == "https://nessus.lab.invalid:8834"
    assert config.scans_url == "https://nessus.lab.invalid:8834/scans"
    assert config.verify_tls is True
    assert config.connect_timeout_seconds == 5.0
    assert config.read_timeout_seconds == 15.0
    assert config.timeout == (5.0, 15.0)
    assert config.warnings == ()


def test_port_defaults_from_scheme_when_absent():
    config = make_config(NESSUS_BASE_URL="https://nessus.lab.invalid")
    assert config.port == 443


def test_missing_env_file_reports_actionable_message(tmp_path):
    with pytest.raises(ConfigError) as excinfo:
        load_config(tmp_path / ENV_FILE_NAME)

    message = str(excinfo.value)
    assert EXAMPLE_ENV_FILE_NAME in message
    assert ENV_FILE_NAME in message


@pytest.mark.parametrize("key", REQUIRED_KEYS)
def test_missing_required_setting_is_rejected(tmp_path, key):
    path = write_env_file(tmp_path, env_values(**{key: None}))

    with pytest.raises(ConfigError) as excinfo:
        load_config(path)

    assert key in str(excinfo.value)


@pytest.mark.parametrize("key", REQUIRED_KEYS)
def test_blank_required_setting_is_rejected(tmp_path, key):
    path = write_env_file(tmp_path, env_values(**{key: ""}))

    with pytest.raises(ConfigError) as excinfo:
        load_config(path)

    assert key in str(excinfo.value)


@pytest.mark.parametrize(
    "base_url",
    [
        "not-a-url",
        "://nessus.lab.invalid",
        "https://",
        "ftp://nessus.lab.invalid:8834",
        "https://nessus.lab.invalid:notaport",
        "https://nessus.lab.invalid:0",
        "https://nessus.lab.invalid:70000",
    ],
)
def test_malformed_base_url_is_rejected(base_url):
    with pytest.raises(ConfigError):
        make_config(NESSUS_BASE_URL=base_url)


def test_http_scheme_is_accepted_with_a_warning():
    config = make_config(NESSUS_BASE_URL="http://nessus.lab.invalid:8834")

    assert config.scheme == "http"
    assert config.port == 8834
    assert any("https" in warning for warning in config.warnings)


@pytest.mark.parametrize("value", ["maybe", "2", "yes please"])
def test_invalid_boolean_is_rejected(value):
    with pytest.raises(ConfigError) as excinfo:
        make_config(NESSUS_VERIFY_TLS=value)

    assert "NESSUS_VERIFY_TLS" in str(excinfo.value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("true", True),
        ("TRUE", True),
        ("1", True),
        ("yes", True),
        ("on", True),
        ("false", False),
        ("False", False),
        ("0", False),
        ("no", False),
        ("off", False),
    ],
)
def test_supported_boolean_forms(value, expected):
    config = make_config(NESSUS_VERIFY_TLS=value)
    assert config.verify_tls is expected


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("NESSUS_CONNECT_TIMEOUT_SECONDS", "0"),
        ("NESSUS_CONNECT_TIMEOUT_SECONDS", "-1"),
        ("NESSUS_CONNECT_TIMEOUT_SECONDS", "soon"),
        ("NESSUS_READ_TIMEOUT_SECONDS", "0"),
        ("NESSUS_READ_TIMEOUT_SECONDS", "-2.5"),
        ("NESSUS_READ_TIMEOUT_SECONDS", "later"),
    ],
)
def test_invalid_timeout_is_rejected(key, value):
    with pytest.raises(ConfigError) as excinfo:
        make_config(**{key: value})

    assert key in str(excinfo.value)


def test_disabling_tls_verification_records_a_warning():
    config = make_config(NESSUS_VERIFY_TLS="false")

    assert config.verify_tls is False
    assert any("TLS" in warning for warning in config.warnings)


def test_repr_and_str_never_contain_secrets():
    config = make_config()

    for rendered in (repr(config), str(config)):
        assert FAKE_ACCESS_KEY not in rendered
        assert FAKE_SECRET_KEY not in rendered


def test_configuration_error_messages_never_contain_secrets():
    with pytest.raises(ConfigError) as excinfo:
        make_config(NESSUS_BASE_URL="not-a-url")

    message = str(excinfo.value)
    assert FAKE_ACCESS_KEY not in message
    assert FAKE_SECRET_KEY not in message


# ---------------------------------------------------------------------------
# Optional export settings (Tranche 2)
# ---------------------------------------------------------------------------


def test_an_env_written_before_export_existed_remains_valid(tmp_path):
    """The Tranche 0 settings alone must still produce a usable config."""
    path = write_env_file(tmp_path, env_values())
    config = load_config(path)

    assert config.export_poll_interval_seconds == 2.0
    assert config.export_poll_timeout_seconds == 600.0
    assert config.export_max_bytes == 1_073_741_824


def test_optional_export_settings_are_not_required():
    from vulnsight.config import OPTIONAL_KEYS

    for key in OPTIONAL_KEYS:
        assert key not in REQUIRED_KEYS


def test_optional_export_settings_may_be_supplied():
    config = make_config(
        NESSUS_EXPORT_POLL_INTERVAL_SECONDS="0.5",
        NESSUS_EXPORT_POLL_TIMEOUT_SECONDS="30",
        NESSUS_EXPORT_MAX_BYTES="2048",
    )

    assert config.export_poll_interval_seconds == 0.5
    assert config.export_poll_timeout_seconds == 30.0
    assert config.export_max_bytes == 2048


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("NESSUS_EXPORT_POLL_INTERVAL_SECONDS", "0"),
        ("NESSUS_EXPORT_POLL_INTERVAL_SECONDS", "-1"),
        ("NESSUS_EXPORT_POLL_INTERVAL_SECONDS", "soon"),
        ("NESSUS_EXPORT_POLL_TIMEOUT_SECONDS", "0"),
        ("NESSUS_EXPORT_POLL_TIMEOUT_SECONDS", "later"),
        ("NESSUS_EXPORT_MAX_BYTES", "0"),
        ("NESSUS_EXPORT_MAX_BYTES", "-5"),
        ("NESSUS_EXPORT_MAX_BYTES", "lots"),
        ("NESSUS_EXPORT_MAX_BYTES", "1.5"),
    ],
)
def test_invalid_optional_export_settings_are_rejected(key, value):
    with pytest.raises(ConfigError) as excinfo:
        make_config(**{key: value})

    assert key in str(excinfo.value)


def test_a_poll_interval_longer_than_the_timeout_is_rejected():
    with pytest.raises(ConfigError) as excinfo:
        make_config(
            NESSUS_EXPORT_POLL_INTERVAL_SECONDS="60",
            NESSUS_EXPORT_POLL_TIMEOUT_SECONDS="10",
        )

    assert "NESSUS_EXPORT_POLL_INTERVAL_SECONDS" in str(excinfo.value)


def test_auth_headers_use_the_documented_format():
    config = make_config()
    headers = config.auth_headers()

    assert headers["X-ApiKeys"] == (
        f"accessKey={FAKE_ACCESS_KEY}; secretKey={FAKE_SECRET_KEY}"
    )
