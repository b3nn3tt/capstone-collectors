"""Shared test fixtures.

Every test in this suite is offline: no test may contact a real Nessus
instance, and no real credentials appear anywhere.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import requests

from vulnsight import config as config_module
from vulnsight.config import NessusConfig, build_config
from vulnsight.nessus import client as client_module

# Synthetic, obviously fake key material.
FAKE_ACCESS_KEY = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaFAKEACCESS"
FAKE_SECRET_KEY = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbFAKESECRET"

BASE_ENV: dict[str, str] = {
    "NESSUS_BASE_URL": "https://nessus.lab.invalid:8834",
    "NESSUS_ACCESS_KEY": FAKE_ACCESS_KEY,
    "NESSUS_SECRET_KEY": FAKE_SECRET_KEY,
    "NESSUS_VERIFY_TLS": "true",
    "NESSUS_CONNECT_TIMEOUT_SECONDS": "5",
    "NESSUS_READ_TIMEOUT_SECONDS": "15",
}

SAMPLE_SCANS_PAYLOAD = {
    "folders": [{"id": 2, "name": "My Scans"}],
    "scans": [{"id": 41, "name": "Sensitive Lab Scan Name", "status": "completed"}],
    "timestamp": 1700000000,
}


def env_values(**overrides: str | None) -> dict[str, str]:
    """Return a copy of the base environment with overrides applied.

    An override value of ``None`` removes the key entirely.
    """
    values = dict(BASE_ENV)
    for key, value in overrides.items():
        if value is None:
            values.pop(key, None)
        else:
            values[key] = value
    return values


def write_env_file(directory: Path, values: dict[str, str]) -> Path:
    """Write a synthetic ``.env`` file and return its path."""
    path = Path(directory) / ".env"
    path.write_text(
        "\n".join(f"{key}={value}" for key, value in values.items()) + "\n",
        encoding="utf-8",
    )
    return path


def make_config(**overrides: str | None) -> NessusConfig:
    """Build a validated configuration from synthetic values."""
    return build_config(env_values(**overrides))


#: Sentinel distinguishing "no payload given" from an explicit JSON null.
UNSET = object()


class FakeResponse:
    """A minimal stand-in for :class:`requests.Response`.

    It also serves the export pipeline: ``headers`` and ``iter_content``
    support streamed downloads, and ``closed`` records that the response was
    released.
    """

    def __init__(
        self,
        status_code: int = 200,
        payload: object = UNSET,
        json_exception: Exception | None = None,
        headers: dict[str, str] | None = None,
        chunks: list[bytes] | None = None,
        chunk_exception: Exception | None = None,
    ) -> None:
        self.status_code = status_code
        self._payload = SAMPLE_SCANS_PAYLOAD if payload is UNSET else payload
        self._json_exception = json_exception
        self.headers = dict(headers or {})
        self.chunks = list(chunks or [])
        self.chunk_exception = chunk_exception
        self.closed = False
        self.chunk_sizes: list[int | None] = []

    def json(self) -> object:
        if self._json_exception is not None:
            raise self._json_exception
        return self._payload

    def iter_content(self, chunk_size: int | None = None):
        self.chunk_sizes.append(chunk_size)
        for chunk in self.chunks:
            yield chunk
        if self.chunk_exception is not None:
            raise self.chunk_exception

    def close(self) -> None:
        self.closed = True


class FakeSession:
    """A requests session double that records calls and forbids writes."""

    def __init__(self, response: object = None, exception: Exception | None = None):
        self.response = response
        self.exception = exception
        self.get_calls: list[tuple[tuple, dict]] = []
        self.closed = False
        self.forbidden_calls: list[str] = []

    def get(self, *args, **kwargs):
        self.get_calls.append((args, kwargs))
        if self.exception is not None:
            raise self.exception
        return self.response

    def _forbidden(self, name: str):
        def _call(*args, **kwargs):
            self.forbidden_calls.append(name)
            raise AssertionError(
                f"The connectivity preflight must not issue a {name.upper()} request."
            )

        return _call

    def __getattr__(self, name: str):
        if name in {"post", "put", "patch", "delete", "head", "options", "request"}:
            return self._forbidden(name)
        raise AttributeError(name)

    def close(self) -> None:
        self.closed = True


class FakeApiSession:
    """A session double for the export pipeline.

    Unlike :class:`FakeSession` it permits POST, because Nessus builds an
    export artefact with ``POST /scans/{scan_id}/export``. Every other
    write-shaped method remains forbidden and fails the test loudly.
    """

    def __init__(self, responses: list | None = None) -> None:
        self.responses = list(responses or [])
        self.calls: list[tuple[str, str, dict]] = []
        self.closed = False
        self.forbidden_calls: list[str] = []

    @property
    def methods(self) -> list[str]:
        return [method for method, _url, _kwargs in self.calls]

    @property
    def urls(self) -> list[str]:
        return [url for _method, url, _kwargs in self.calls]

    def get(self, url, **kwargs):
        return self._next("GET", url, kwargs)

    def post(self, url, **kwargs):
        return self._next("POST", url, kwargs)

    def _next(self, method: str, url: str, kwargs: dict):
        self.calls.append((method, url, kwargs))
        if not self.responses:
            raise AssertionError(
                f"The code under test issued an unexpected {method} {url}; "
                "the test supplied no further responses."
            )
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def _forbidden(self, name: str):
        def _call(*args, **kwargs):
            self.forbidden_calls.append(name)
            raise AssertionError(
                f"VulnSight must never issue a {name.upper()} request."
            )

        return _call

    def __getattr__(self, name: str):
        if name in {"put", "patch", "delete", "head", "options", "request"}:
            return self._forbidden(name)
        raise AttributeError(name)

    def close(self) -> None:
        self.closed = True


class FakeClock:
    """A monotonic clock and sleeper that never waits in real time."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds

    def as_clock(self):
        from vulnsight.nessus.export import Clock

        return Clock(monotonic=self.monotonic, sleep=self.sleep)


#: A minimal but structurally valid native Nessus export.
VALID_NESSUS_XML = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b"<NessusClientData_v2>\n"
    b"  <Policy><policyName>Lab</policyName></Policy>\n"
    b'  <Report name="synthetic-lab-scan">\n'
    b'    <ReportHost name="host-a">\n'
    b'      <ReportItem port="0" pluginID="19506" severity="0" />\n'
    b'      <ReportItem port="22" pluginID="10267" severity="1" />\n'
    b"    </ReportHost>\n"
    b"  </Report>\n"
    b"</NessusClientData_v2>\n"
)

#: A completed scan that found no live hosts is still valid evidence.
EMPTY_REPORT_NESSUS_XML = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<NessusClientData_v2><Report name="empty" /></NessusClientData_v2>\n'
)


@pytest.fixture
def fake_clock() -> FakeClock:
    """A clock and sleeper injected into export polling."""
    return FakeClock()


@pytest.fixture
def patch_api_session(monkeypatch: pytest.MonkeyPatch):
    """Return a helper that installs a :class:`FakeApiSession`."""

    def _install(responses: list | None = None) -> FakeApiSession:
        session = FakeApiSession(responses=responses)
        monkeypatch.setattr(requests, "Session", lambda: session)
        return session

    return _install


@pytest.fixture
def config() -> NessusConfig:
    """A valid configuration with TLS verification enabled."""
    return make_config()


@pytest.fixture
def patch_tcp_success(monkeypatch: pytest.MonkeyPatch):
    """Make TCP connection attempts succeed with a dummy socket."""

    class DummySocket:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    created: list[tuple] = []

    def _create_connection(address, timeout=None):
        created.append((address, timeout))
        return DummySocket()

    monkeypatch.setattr(client_module.socket, "create_connection", _create_connection)
    return created


@pytest.fixture
def patch_tcp_failure(monkeypatch: pytest.MonkeyPatch):
    """Return a helper that makes TCP connection attempts raise."""

    def _install(exception: BaseException):
        def _create_connection(address, timeout=None):
            raise exception

        monkeypatch.setattr(
            client_module.socket, "create_connection", _create_connection
        )

    return _install


@pytest.fixture
def patch_session(monkeypatch: pytest.MonkeyPatch):
    """Return a helper that installs a :class:`FakeSession`."""

    def _install(response: object = None, exception: Exception | None = None):
        session = FakeSession(response=response, exception=exception)
        monkeypatch.setattr(requests, "Session", lambda: session)
        return session

    return _install


@pytest.fixture
def env_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A temporary working directory used as the project root."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture(autouse=True)
def no_ambient_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure ambient process environment cannot influence configuration."""
    for key in config_module.REQUIRED_KEYS:
        monkeypatch.delenv(key, raising=False)
