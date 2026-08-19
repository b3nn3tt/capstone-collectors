"""Loading and validation of VulnSight configuration.

Configuration is read from a local ``.env`` file.  Nothing in this module ever
places an API key into a log message, an exception message or an object
representation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit

from dotenv import dotenv_values

ENV_FILE_NAME = ".env"
EXAMPLE_ENV_FILE_NAME = ".env.example"

KEY_BASE_URL = "NESSUS_BASE_URL"
KEY_ACCESS_KEY = "NESSUS_ACCESS_KEY"
KEY_SECRET_KEY = "NESSUS_SECRET_KEY"
KEY_VERIFY_TLS = "NESSUS_VERIFY_TLS"
KEY_CONNECT_TIMEOUT = "NESSUS_CONNECT_TIMEOUT_SECONDS"
KEY_READ_TIMEOUT = "NESSUS_READ_TIMEOUT_SECONDS"

KEY_EXPORT_POLL_INTERVAL = "NESSUS_EXPORT_POLL_INTERVAL_SECONDS"
KEY_EXPORT_POLL_TIMEOUT = "NESSUS_EXPORT_POLL_TIMEOUT_SECONDS"
KEY_EXPORT_MAX_BYTES = "NESSUS_EXPORT_MAX_BYTES"

REQUIRED_KEYS: tuple[str, ...] = (
    KEY_BASE_URL,
    KEY_ACCESS_KEY,
    KEY_SECRET_KEY,
    KEY_VERIFY_TLS,
    KEY_CONNECT_TIMEOUT,
    KEY_READ_TIMEOUT,
)

#: Settings that may be absent.  Each has an explicit documented default, so
#: an existing ``.env`` written before export existed remains valid.
OPTIONAL_KEYS: tuple[str, ...] = (
    KEY_EXPORT_POLL_INTERVAL,
    KEY_EXPORT_POLL_TIMEOUT,
    KEY_EXPORT_MAX_BYTES,
)

#: Documented defaults for the optional export settings.
DEFAULT_EXPORT_POLL_INTERVAL_SECONDS = 2.0
DEFAULT_EXPORT_POLL_TIMEOUT_SECONDS = 600.0
DEFAULT_EXPORT_MAX_BYTES = 1_073_741_824  # 1 GiB

#: Keys whose values must never be echoed back to the user.
SECRET_KEYS: tuple[str, ...] = (KEY_ACCESS_KEY, KEY_SECRET_KEY)

_TRUE_VALUES = frozenset({"true", "1", "yes", "on"})
_FALSE_VALUES = frozenset({"false", "0", "no", "off"})

_SUPPORTED_SCHEMES = ("https", "http")
_DEFAULT_PORTS = {"https": 443, "http": 80}


class ConfigError(Exception):
    """Raised when configuration is absent, incomplete or invalid.

    Instances are constructed only from static text and from non-secret
    setting names, so the message is always safe to display.
    """


@dataclass(frozen=True)
class NessusConfig:
    """Validated Nessus connection settings.

    ``access_key`` and ``secret_key`` are excluded from the generated
    ``__repr__`` so that neither can leak through logging or debugging output.
    """

    base_url: str
    scheme: str
    host: str
    port: int
    access_key: str = field(repr=False)
    secret_key: str = field(repr=False)
    verify_tls: bool = True
    connect_timeout_seconds: float = 5.0
    read_timeout_seconds: float = 15.0
    export_poll_interval_seconds: float = DEFAULT_EXPORT_POLL_INTERVAL_SECONDS
    export_poll_timeout_seconds: float = DEFAULT_EXPORT_POLL_TIMEOUT_SECONDS
    export_max_bytes: int = DEFAULT_EXPORT_MAX_BYTES
    warnings: tuple[str, ...] = ()

    @property
    def endpoint(self) -> str:
        """The normalised ``scheme://host:port`` endpoint."""
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def scans_url(self) -> str:
        """The read-only scan-list URL used by the connectivity preflight."""
        return f"{self.endpoint}/scans"

    @property
    def timeout(self) -> tuple[float, float]:
        """The explicit ``(connect, read)`` timeout pair for requests."""
        return (self.connect_timeout_seconds, self.read_timeout_seconds)

    def auth_headers(self) -> dict[str, str]:
        """Build the Nessus API key header.

        The returned dictionary contains secrets and must never be logged.
        """
        return {
            "X-ApiKeys": f"accessKey={self.access_key}; secretKey={self.secret_key}",
            "Accept": "application/json",
        }


def redact(text: str, config: NessusConfig | None) -> str:
    """Remove any configured key material from *text*.

    This is defence in depth: no code path is expected to place a key into a
    message, but third-party exception text is not fully under our control.
    """
    if config is None or not text:
        return text
    cleaned = text
    for secret in (config.access_key, config.secret_key):
        if secret:
            cleaned = cleaned.replace(secret, "[REDACTED]")
    return cleaned


def default_env_path(project_root: Path | None = None) -> Path:
    """Return the ``.env`` path used by the command-line interface."""
    root = Path.cwd() if project_root is None else Path(project_root)
    return root / ENV_FILE_NAME


def load_config(env_path: Path | str | None = None) -> NessusConfig:
    """Load and validate configuration from a ``.env`` file.

    Raises :class:`ConfigError` with an actionable, secret-free message when
    the file is absent or any setting is missing or invalid.
    """
    path = default_env_path() if env_path is None else Path(env_path)

    if not path.is_file():
        raise ConfigError(
            f"Configuration file not found: {path}. "
            f"Copy {EXAMPLE_ENV_FILE_NAME} to {ENV_FILE_NAME} in the project "
            "directory and enter your Nessus endpoint and API keys."
        )

    raw = dotenv_values(path)
    return build_config(raw)


def build_config(raw: Mapping[str, str | None]) -> NessusConfig:
    """Validate an already-loaded mapping of settings."""
    values: dict[str, str] = {}
    for key in REQUIRED_KEYS:
        if key not in raw or raw[key] is None:
            raise ConfigError(
                f"Required setting {key} is missing from {ENV_FILE_NAME}. "
                f"See {EXAMPLE_ENV_FILE_NAME} for the expected settings."
            )
        value = str(raw[key]).strip()
        if not value:
            raise ConfigError(
                f"Required setting {key} is present but blank in {ENV_FILE_NAME}. "
                "Provide a value; VulnSight will not guess configuration."
            )
        values[key] = value

    scheme, host, port, warnings = _parse_base_url(values[KEY_BASE_URL])
    verify_tls = _parse_bool(KEY_VERIFY_TLS, values[KEY_VERIFY_TLS])
    connect_timeout = _parse_timeout(KEY_CONNECT_TIMEOUT, values[KEY_CONNECT_TIMEOUT])
    read_timeout = _parse_timeout(KEY_READ_TIMEOUT, values[KEY_READ_TIMEOUT])

    poll_interval = _optional_timeout(
        raw, KEY_EXPORT_POLL_INTERVAL, DEFAULT_EXPORT_POLL_INTERVAL_SECONDS
    )
    poll_timeout = _optional_timeout(
        raw, KEY_EXPORT_POLL_TIMEOUT, DEFAULT_EXPORT_POLL_TIMEOUT_SECONDS
    )
    max_bytes = _optional_positive_int(
        raw, KEY_EXPORT_MAX_BYTES, DEFAULT_EXPORT_MAX_BYTES
    )
    if poll_interval > poll_timeout:
        raise ConfigError(
            f"{KEY_EXPORT_POLL_INTERVAL} must not be greater than "
            f"{KEY_EXPORT_POLL_TIMEOUT}."
        )

    if not verify_tls:
        warnings = warnings + (
            "TLS certificate verification is disabled by "
            f"{KEY_VERIFY_TLS}=false; use this only against a lab scanner.",
        )

    return NessusConfig(
        base_url=f"{scheme}://{host}:{port}",
        scheme=scheme,
        host=host,
        port=port,
        access_key=values[KEY_ACCESS_KEY],
        secret_key=values[KEY_SECRET_KEY],
        verify_tls=verify_tls,
        connect_timeout_seconds=connect_timeout,
        read_timeout_seconds=read_timeout,
        export_poll_interval_seconds=poll_interval,
        export_poll_timeout_seconds=poll_timeout,
        export_max_bytes=max_bytes,
        warnings=warnings,
    )


def _parse_base_url(value: str) -> tuple[str, str, int, tuple[str, ...]]:
    """Split and validate the configured base URL."""
    try:
        parts = urlsplit(value)
    except ValueError:
        raise ConfigError(
            f"{KEY_BASE_URL} is not a valid URL. "
            "Use the form https://host:8834."
        ) from None

    scheme = parts.scheme.lower()
    if not scheme:
        raise ConfigError(
            f"{KEY_BASE_URL} has no URL scheme. Use the form https://host:8834."
        )
    if scheme not in _SUPPORTED_SCHEMES:
        raise ConfigError(
            f"{KEY_BASE_URL} uses the unsupported scheme '{scheme}'. "
            "Only https or http are accepted; https is expected."
        )

    hostname = parts.hostname
    if not hostname:
        raise ConfigError(
            f"{KEY_BASE_URL} does not contain a host. "
            "Use the form https://host:8834."
        )

    try:
        port = parts.port
    except ValueError:
        raise ConfigError(
            f"{KEY_BASE_URL} contains an invalid port. "
            "Use a whole number between 1 and 65535, such as 8834."
        ) from None

    if port is None:
        port = _DEFAULT_PORTS[scheme]
    if not 1 <= port <= 65535:
        raise ConfigError(
            f"{KEY_BASE_URL} contains an out-of-range port. "
            "Use a whole number between 1 and 65535, such as 8834."
        )

    warnings: tuple[str, ...] = ()
    if scheme == "http":
        warnings = (
            f"{KEY_BASE_URL} uses http; Nessus is normally reached over https "
            "on port 8834.",
        )

    return scheme, hostname, port, warnings


def _parse_bool(key: str, value: str) -> bool:
    lowered = value.strip().lower()
    if lowered in _TRUE_VALUES:
        return True
    if lowered in _FALSE_VALUES:
        return False
    raise ConfigError(
        f"{key} must be a Boolean value such as true or false."
    )


def _optional_timeout(
    raw: Mapping[str, str | None], key: str, default: float
) -> float:
    """Read an optional positive-seconds setting, or return its default."""
    if key not in raw or raw[key] is None or not str(raw[key]).strip():
        return default
    return _parse_timeout(key, str(raw[key]).strip())


def _optional_positive_int(
    raw: Mapping[str, str | None], key: str, default: int
) -> int:
    """Read an optional positive-integer setting, or return its default."""
    if key not in raw or raw[key] is None or not str(raw[key]).strip():
        return default
    text = str(raw[key]).strip()
    try:
        number = int(text)
    except ValueError:
        raise ConfigError(f"{key} must be a positive whole number of bytes.") from None
    if number <= 0:
        raise ConfigError(f"{key} must be a positive whole number of bytes.")
    return number


def _parse_timeout(key: str, value: str) -> float:
    try:
        seconds = float(value)
    except ValueError:
        raise ConfigError(
            f"{key} must be a positive number of seconds."
        ) from None
    if seconds <= 0 or seconds != seconds or seconds == float("inf"):
        raise ConfigError(
            f"{key} must be a positive number of seconds."
        )
    return seconds
