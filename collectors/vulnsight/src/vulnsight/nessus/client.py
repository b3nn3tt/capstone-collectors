"""Read-only Nessus connectivity preflight and shared request plumbing.

The preflight performs a TCP reachability test followed by a single
authenticated ``GET /scans`` request.  It creates, modifies, launches, stops,
exports and deletes nothing, and it does not retain the scan-list response.

This module is also the single place where a Nessus HTTP request is actually
issued.  :func:`perform_get`, :func:`perform_get_stream` and
:func:`perform_post` all route through one private sender that applies the
configured API-key header, the explicit connect and read timeouts and the
configured TLS setting, and :func:`classify_request_exception` maps transport
failures onto outcomes.  The discovery and export modules reuse these rather
than defining a second client.

:func:`perform_post` is the only write-shaped call in the project.  It exists
solely because Nessus creates a ``.nessus`` export artefact with
``POST /scans/{scan_id}/export``; nothing here launches, stops, reschedules,
modifies or deletes a scan, and no PUT, PATCH or DELETE request exists.

The preflight returns a structured :class:`ConnectivityResult` rather than
printing; presentation is the responsibility of the command-line interface.
"""

from __future__ import annotations

import socket
import warnings as warnings_module
from dataclasses import dataclass
from enum import Enum

import requests
import urllib3

from ..config import NessusConfig, redact

SCANS_PATH = "/scans"


class Outcome(str, Enum):
    """The classified result of a connectivity preflight."""

    SUCCESS = "success"
    CONFIGURATION_ERROR = "configuration_error"
    NETWORK_ERROR = "network_error"
    AUTHENTICATION_ERROR = "authentication_error"
    API_ERROR = "api_error"


class Stage(str, Enum):
    """The stage of the preflight at which the outcome was determined."""

    CONFIGURATION = "configuration"
    TARGET_RESOLUTION = "target_resolution"
    TCP_CONNECTIVITY = "tcp_connectivity"
    API_REQUEST = "api_request"
    API_RESPONSE = "api_response"


#: Stable process exit codes.
EXIT_CODES: dict[Outcome, int] = {
    Outcome.SUCCESS: 0,
    Outcome.CONFIGURATION_ERROR: 2,
    Outcome.NETWORK_ERROR: 3,
    Outcome.AUTHENTICATION_ERROR: 4,
    Outcome.API_ERROR: 5,
}


@dataclass(frozen=True)
class ConnectivityResult:
    """A structured, secret-free summary of the preflight.

    The scan-list payload is deliberately absent: the response body is
    validated and discarded, never stored or persisted.
    """

    outcome: Outcome
    stage: Stage
    summary: str
    endpoint: str
    verify_tls: bool
    detail: str = ""
    http_status: int | None = None
    tcp_connected: bool = False
    authenticated: bool = False
    json_valid: bool = False
    warnings: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        """True when connectivity and authentication were both verified."""
        return self.outcome is Outcome.SUCCESS

    @property
    def exit_code(self) -> int:
        """The stable process exit code for this outcome."""
        return EXIT_CODES[self.outcome]


def check_connectivity(config: NessusConfig) -> ConnectivityResult:
    """Run the Nessus connectivity preflight and return a structured result."""
    tcp_failure = _check_tcp(config)
    if tcp_failure is not None:
        return tcp_failure
    return _check_api(config)


# --------------------------------------------------------------------------
# Stage 3: TCP connectivity
# --------------------------------------------------------------------------


def _check_tcp(config: NessusConfig) -> ConnectivityResult | None:
    """Attempt a TCP connection; return a failure result, or None on success."""
    try:
        connection = socket.create_connection(
            (config.host, config.port),
            timeout=config.connect_timeout_seconds,
        )
    except socket.gaierror as exc:
        return _failure(
            config,
            Outcome.NETWORK_ERROR,
            Stage.TARGET_RESOLUTION,
            f"The host '{config.host}' could not be resolved.",
            exc,
        )
    except ConnectionRefusedError as exc:
        return _failure(
            config,
            Outcome.NETWORK_ERROR,
            Stage.TCP_CONNECTIVITY,
            f"The connection to {config.endpoint} was refused. "
            "Confirm that Nessus is running and listening on that port.",
            exc,
        )
    except (TimeoutError, socket.timeout) as exc:
        return _failure(
            config,
            Outcome.NETWORK_ERROR,
            Stage.TCP_CONNECTIVITY,
            f"The connection to {config.endpoint} timed out after "
            f"{config.connect_timeout_seconds:g} seconds.",
            exc,
        )
    except OSError as exc:
        return _failure(
            config,
            Outcome.NETWORK_ERROR,
            Stage.TCP_CONNECTIVITY,
            f"The network route to {config.endpoint} is unavailable. "
            "Check routing, the local firewall and any intervening controls.",
            exc,
        )

    try:
        connection.close()
    except OSError:  # pragma: no cover - closing failures are not diagnostic
        pass
    return None


# --------------------------------------------------------------------------
# Stages 4 and 5: authenticated request and response validation
# --------------------------------------------------------------------------


def _check_api(config: NessusConfig) -> ConnectivityResult:
    """Issue one authenticated GET /scans request and validate the response."""
    session = requests.Session()
    try:
        response = perform_get(session, config, config.scans_url)
    except requests.exceptions.RequestException as exc:
        outcome, summary = classify_request_exception(config, exc, SCANS_PATH)
        return _failure(config, outcome, Stage.API_REQUEST, summary, exc)
    finally:
        session.close()

    return _classify_response(config, response)


def perform_get(
    session: requests.Session,
    config: NessusConfig,
    url: str,
):
    """Perform one read-only GET request against the configured scanner.

    It always uses GET, always applies the configured API-key header and the
    explicit ``(connect, read)`` timeout pair, never sends a query string and
    never follows redirects.
    """
    return _send(session, config, "GET", url)


def perform_get_stream(
    session: requests.Session,
    config: NessusConfig,
    url: str,
):
    """Perform one streaming GET request, used only to download an export.

    Identical to :func:`perform_get` except that the response body is not
    read eagerly, so a large artefact can be consumed in bounded chunks.
    """
    return _send(session, config, "GET", url, stream=True)


def perform_post(
    session: requests.Session,
    config: NessusConfig,
    url: str,
    json_body: dict[str, object],
):
    """Perform the one POST VulnSight is permitted to make.

    This exists solely because Nessus creates an export artefact with
    ``POST /scans/{scan_id}/export``.  It never launches, stops, reschedules,
    modifies or deletes a scan, and no other POST target is reachable from
    this codebase.  The body is supplied by the caller and is JSON-encoded by
    ``requests``.
    """
    return _send(session, config, "POST", url, json_body=json_body)


def _send(
    session: requests.Session,
    config: NessusConfig,
    method: str,
    url: str,
    *,
    json_body: dict[str, object] | None = None,
    stream: bool = False,
):
    """Issue one request with the established authentication and timeouts.

    This is the only place a Nessus request is issued.  It applies the
    configured API-key header and the explicit ``(connect, read)`` timeout
    pair, and never follows redirects.  TLS verification follows the
    configured setting and is never weakened here.

    When TLS verification is disabled, the insecure-request warning is
    suppressed only for the duration of this call rather than globally.
    No request is ever retried, so an authentication or authorisation failure
    results in exactly one request.
    """
    request_kwargs: dict[str, object] = {
        "headers": config.auth_headers(),
        "timeout": config.timeout,
        "verify": config.verify_tls,
        "allow_redirects": False,
    }
    if stream:
        request_kwargs["stream"] = True
    if json_body is not None:
        request_kwargs["json"] = json_body

    call = session.post if method == "POST" else session.get

    if config.verify_tls:
        return call(url, **request_kwargs)

    with warnings_module.catch_warnings():
        warnings_module.simplefilter(
            "ignore", urllib3.exceptions.InsecureRequestWarning
        )
        return call(url, **request_kwargs)


def classify_request_exception(
    config: NessusConfig,
    exc: requests.exceptions.RequestException,
    path: str,
) -> tuple[Outcome, str]:
    """Map a transport failure onto an outcome and an actionable summary.

    *path* is the request path used in the message; no key material is ever
    included.
    """
    if isinstance(exc, requests.exceptions.SSLError):
        return (
            Outcome.NETWORK_ERROR,
            "The TLS certificate presented by the scanner could not be "
            "verified. Install a trusted certificate, or set "
            "NESSUS_VERIFY_TLS=false for a self-signed lab scanner.",
        )
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return (
            Outcome.NETWORK_ERROR,
            f"Connecting to {config.endpoint} timed out after "
            f"{config.connect_timeout_seconds:g} seconds.",
        )
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return (
            Outcome.NETWORK_ERROR,
            f"The scanner did not respond within "
            f"{config.read_timeout_seconds:g} seconds.",
        )
    if isinstance(exc, requests.exceptions.Timeout):
        return (
            Outcome.NETWORK_ERROR,
            f"The request to {config.endpoint}{path} timed out.",
        )
    if isinstance(exc, requests.exceptions.ConnectionError):
        return (
            Outcome.NETWORK_ERROR,
            f"The connection to {config.endpoint} failed. "
            "Check the host, the port and any intervening network controls.",
        )
    return (
        Outcome.NETWORK_ERROR,
        f"The request to {config.endpoint}{path} could not be completed.",
    )


def _classify_response(config: NessusConfig, response) -> ConnectivityResult:
    """Map an HTTP response onto a classified connectivity result."""
    status = getattr(response, "status_code", None)

    if status == 401:
        return _failure(
            config,
            Outcome.AUTHENTICATION_ERROR,
            Stage.API_RESPONSE,
            "Authentication was rejected (HTTP 401). Check the Nessus API "
            "access and secret keys in the .env file.",
            http_status=status,
            tcp_connected=True,
        )
    if status == 403:
        return _failure(
            config,
            Outcome.AUTHENTICATION_ERROR,
            Stage.API_RESPONSE,
            "The authenticated account lacks permission to list scans "
            "(HTTP 403). Grant the account read access to scans.",
            http_status=status,
            tcp_connected=True,
        )
    if status == 404:
        return _failure(
            config,
            Outcome.API_ERROR,
            Stage.API_RESPONSE,
            f"The endpoint {config.endpoint}{SCANS_PATH} was not found "
            "(HTTP 404). Check NESSUS_BASE_URL and the scanner's API version.",
            http_status=status,
            tcp_connected=True,
        )
    if status is None or not 200 <= int(status) < 300:
        return _failure(
            config,
            Outcome.API_ERROR,
            Stage.API_RESPONSE,
            f"The scanner returned an unexpected HTTP status ({status}).",
            http_status=status,
            tcp_connected=True,
        )

    try:
        payload = response.json()
    except Exception as exc:  # requests raises a ValueError subclass here
        return _failure(
            config,
            Outcome.API_ERROR,
            Stage.API_RESPONSE,
            "The scanner returned a response that is not valid JSON.",
            exc,
            http_status=status,
            tcp_connected=True,
            authenticated=True,
        )

    if not isinstance(payload, dict):
        # The payload is inspected only for shape and is then discarded.
        return _failure(
            config,
            Outcome.API_ERROR,
            Stage.API_RESPONSE,
            "The scan list response was valid JSON but not the expected "
            "object structure.",
            http_status=status,
            tcp_connected=True,
            authenticated=True,
        )

    return ConnectivityResult(
        outcome=Outcome.SUCCESS,
        stage=Stage.API_RESPONSE,
        summary="Nessus connectivity and authentication verified.",
        endpoint=config.endpoint,
        verify_tls=config.verify_tls,
        http_status=int(status),
        tcp_connected=True,
        authenticated=True,
        json_valid=True,
        warnings=config.warnings,
    )


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _failure(
    config: NessusConfig,
    outcome: Outcome,
    stage: Stage,
    summary: str,
    exc: BaseException | None = None,
    *,
    http_status: int | None = None,
    tcp_connected: bool = False,
    authenticated: bool = False,
) -> ConnectivityResult:
    """Build a failure result, retaining redacted technical detail only."""
    detail = ""
    if exc is not None:
        detail = redact(f"{type(exc).__name__}: {exc}", config)
    return ConnectivityResult(
        outcome=outcome,
        stage=stage,
        summary=redact(summary, config),
        endpoint=config.endpoint,
        verify_tls=config.verify_tls,
        detail=detail,
        http_status=http_status,
        tcp_connected=tcp_connected,
        authenticated=authenticated,
        json_valid=False,
        warnings=config.warnings,
    )
