"""Tests for depsguard.

These run fully offline: deps.dev HTTP calls are mocked, and the MCP tools are
exercised through the server module directly. Run with:  pytest -q
"""

from unittest.mock import patch

import httpx
import pytest

import depsguard.server as server

_PKG = {
    "packageKey": {"system": "PYPI", "name": "requests"},
    "versions": [
        {
            "versionKey": {"name": "requests", "version": "2.31.0"},
            "publishedAt": "2023-05-22T00:00:00Z",
            "isDefault": True,
        },
        {
            "versionKey": {"name": "requests", "version": "2.30.0"},
            "publishedAt": "2023-05-03T00:00:00Z",
        },
    ],
}
_VER = {
    "versionKey": {"name": "urllib3", "version": "1.26.4"},
    "publishedAt": "2021-03-15T00:00:00Z",
    "licenses": ["MIT"],
    "advisoryKeys": [{"id": "GHSA-5phf-px7c-ng8b"}],
    "links": [{"label": "SOURCE_REPO", "url": "https://github.com/urllib3/urllib3"}],
}
_ADV = {
    "advisoryKey": {"id": "GHSA-5phf-px7c-ng8b"},
    "title": "CRLF injection",
    "aliases": ["CVE-2021-33503"],
    "cvss3Score": 7.5,
    "cvss3Vector": "CVSS:3.1/...",
    "url": "https://osv.dev/vulnerability/GHSA-5phf-px7c-ng8b",
}


class _FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("GET", "https://api.deps.dev/v3/test")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError(
                "HTTP error",
                request=request,
                response=response,
            )


class _FakeAsyncClient:
    def __init__(self, response=None, error=None, calls=None, **kwargs):
        self._response = response or _FakeResponse()
        self._error = error
        self._calls = calls if calls is not None else []
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url):
        self._calls.append(url)
        if self._error is not None:
            raise self._error
        return self._response


def _router(payload_by_kind):
    async def _fake(path):
        if path.startswith("advisories"):
            return payload_by_kind["advisory"]
        if "/versions/" in path:
            return payload_by_kind["version"]
        return payload_by_kind["package"]
    return _fake


@pytest.mark.asyncio
async def test_get_returns_json_from_deps_dev_path():
    calls = []

    def _client(**kwargs):
        return _FakeAsyncClient(
            response=_FakeResponse(payload={"ok": True}),
            calls=calls,
            **kwargs,
        )

    with patch.object(server.httpx, "AsyncClient", _client):
        out = await server._get("systems/PYPI/packages/requests")

    assert out == {"ok": True}
    assert calls == ["https://api.deps.dev/v3/systems/PYPI/packages/requests"]


@pytest.mark.asyncio
async def test_get_reports_not_found_with_actionable_message():
    with patch.object(
        server.httpx,
        "AsyncClient",
        lambda **kwargs: _FakeAsyncClient(
            response=_FakeResponse(status_code=404),
            **kwargs,
        ),
    ):
        with pytest.raises(RuntimeError, match="Not found on deps.dev"):
            await server._get("systems/PYPI/packages/nope")


@pytest.mark.asyncio
async def test_get_reports_rate_limit_without_raw_http_error():
    with patch.object(
        server.httpx,
        "AsyncClient",
        lambda **kwargs: _FakeAsyncClient(
            response=_FakeResponse(status_code=429),
            **kwargs,
        ),
    ):
        with pytest.raises(RuntimeError, match="rate-limiting"):
            await server._get("systems/PYPI/packages/requests")


@pytest.mark.asyncio
async def test_get_wraps_network_errors():
    request = httpx.Request("GET", "https://api.deps.dev/v3/test")
    error = httpx.RequestError("connection failed", request=request)

    with patch.object(
        server.httpx,
        "AsyncClient",
        lambda **kwargs: _FakeAsyncClient(error=error, **kwargs),
    ):
        with pytest.raises(RuntimeError, match="Could not reach deps.dev"):
            await server._get("systems/PYPI/packages/requests")


@pytest.mark.asyncio
async def test_get_package_info():
    with patch.object(
        server,
        "_get",
        _router({"package": _PKG, "version": _VER, "advisory": _ADV}),
    ):
        out = await server.get_package_info("pypi", "requests")
    assert out["total_versions"] == 2
    assert out["default_version"] == "2.31.0"
    assert out["recent_versions"][0]["version"] == "2.31.0"


@pytest.mark.asyncio
async def test_get_package_info_allows_packages_without_default_version():
    no_default = {
        "packageKey": {"system": "PYPI", "name": "example"},
        "versions": [
            {
                "versionKey": {"name": "example", "version": "1.0.0"},
                "publishedAt": "2024-01-01T00:00:00Z",
            },
        ],
    }

    with patch.object(
        server,
        "_get",
        _router({"package": no_default, "version": _VER, "advisory": _ADV}),
    ):
        out = await server.get_package_info("pypi", "example")

    assert out["default_version"] is None
    assert out["recent_versions"][0]["version"] == "1.0.0"


@pytest.mark.asyncio
async def test_get_package_info_percent_encodes_scoped_npm_package_names():
    paths = []

    async def _fake(path):
        paths.append(path)
        return {
            "packageKey": {"system": "NPM", "name": "@colors/colors"},
            "versions": [],
        }

    with patch.object(server, "_get", _fake):
        await server.get_package_info("npm", "@colors/colors")

    assert paths == ["systems/NPM/packages/%40colors%2Fcolors"]


@pytest.mark.asyncio
async def test_get_version_details_surfaces_advisories():
    with patch.object(
        server,
        "_get",
        _router({"package": _PKG, "version": _VER, "advisory": _ADV}),
    ):
        out = await server.get_version_details("pypi", "urllib3", "1.26.4")
    assert out["licenses"] == ["MIT"]
    assert out["advisory_count"] == 1
    assert out["advisory_ids"] == ["GHSA-5phf-px7c-ng8b"]
    assert out["source_repo"] == "https://github.com/urllib3/urllib3"


@pytest.mark.asyncio
async def test_get_version_details_percent_encodes_maven_coordinates_and_version():
    paths = []
    payload = {
        "versionKey": {
            "name": "org.apache.logging.log4j:log4j-core",
            "version": "2.14.1+build/metadata",
        },
        "licenses": [],
        "advisoryKeys": [],
        "links": [],
    }

    async def _fake(path):
        paths.append(path)
        return payload

    with patch.object(server, "_get", _fake):
        await server.get_version_details(
            "maven",
            "org.apache.logging.log4j:log4j-core",
            "2.14.1+build/metadata",
        )

    assert paths == [
        "systems/MAVEN/packages/"
        "org.apache.logging.log4j%3Alog4j-core/"
        "versions/2.14.1%2Bbuild%2Fmetadata"
    ]


@pytest.mark.asyncio
async def test_get_advisory_details_severity_bucketing():
    with patch.object(
        server,
        "_get",
        _router({"package": _PKG, "version": _VER, "advisory": _ADV}),
    ):
        out = await server.get_advisory_details("GHSA-5phf-px7c-ng8b")
    assert out["cvss3_score"] == 7.5
    assert out["severity"] == "high"
    assert "CVE-2021-33503" in out["aliases"]


@pytest.mark.asyncio
async def test_get_advisory_details_strips_and_encodes_id():
    paths = []

    async def _fake(path):
        paths.append(path)
        return {"advisoryKey": {"id": "GHSA-2qrg-x229-3v8q"}, "aliases": []}

    with patch.object(server, "_get", _fake):
        out = await server.get_advisory_details("  GHSA-2qrg-x229-3v8q  ")

    assert paths == ["advisories/GHSA-2qrg-x229-3v8q"]
    assert out["id"] == "GHSA-2qrg-x229-3v8q"


@pytest.mark.asyncio
async def test_get_advisory_details_unknown_when_cvss_missing():
    no_score = {
        "advisoryKey": {"id": "GHSA-unknown"},
        "title": "No score yet",
        "aliases": [],
        "url": "https://osv.dev/vulnerability/GHSA-unknown",
    }

    with patch.object(
        server,
        "_get",
        _router({"package": _PKG, "version": _VER, "advisory": no_score}),
    ):
        out = await server.get_advisory_details("GHSA-unknown")

    assert out["severity"] == "unknown"
    assert out["cvss3_score"] is None


@pytest.mark.asyncio
async def test_unknown_ecosystem_rejected():
    with pytest.raises(ValueError):
        server._sys("bogus")


def _policy_router(version_payload, advisory_payload):
    async def _fake(path):
        if path.startswith("advisories"):
            return advisory_payload
        if "/versions/" in path:
            return version_payload
        return _PKG
    return _fake


@pytest.mark.asyncio
async def test_policy_blocks_when_severity_exceeds_threshold():
    with patch.object(server, "_get", _policy_router(_VER, _ADV)):
        out = await server.evaluate_dependency_policy(
            "pypi",
            "urllib3",
            "1.26.4",
            max_severity="medium",
        )
    assert out["verdict"] == "BLOCK"
    assert out["worst_severity"] == "high"


@pytest.mark.asyncio
async def test_policy_warns_within_threshold():
    with patch.object(server, "_get", _policy_router(_VER, _ADV)):
        out = await server.evaluate_dependency_policy(
            "pypi",
            "urllib3",
            "1.26.4",
            max_severity="high",
        )
    assert out["verdict"] == "WARN"


@pytest.mark.asyncio
async def test_policy_allows_when_clean():
    clean = {
        "versionKey": {"name": "requests", "version": "2.31.0"},
        "licenses": ["Apache-2.0"],
        "advisoryKeys": [],
        "links": [],
    }
    with patch.object(server, "_get", _policy_router(clean, _ADV)):
        out = await server.evaluate_dependency_policy("pypi", "requests", "2.31.0")
    assert out["verdict"] == "ALLOW"
    assert out["advisories"] == []


@pytest.mark.asyncio
async def test_policy_rejects_invalid_max_severity():
    async def _fail_if_called(path):
        raise AssertionError(f"_get should not be called for invalid policy: {path}")

    with patch.object(server, "_get", _fail_if_called):
        with pytest.raises(ValueError, match="Unknown max_severity"):
            await server.evaluate_dependency_policy(
                "pypi",
                "urllib3",
                "1.26.4",
                max_severity="severe",
            )


@pytest.mark.asyncio
async def test_policy_preserves_unknown_worst_severity_label():
    unknown_advisory = {
        "advisoryKey": {"id": "GHSA-unknown"},
        "title": "Pending score",
        "aliases": [],
        "url": "https://osv.dev/vulnerability/GHSA-unknown",
    }
    version = {
        "versionKey": {"name": "demo", "version": "1.0.0"},
        "licenses": ["MIT"],
        "advisoryKeys": [{"id": "GHSA-unknown"}],
        "links": [],
    }

    with patch.object(server, "_get", _policy_router(version, unknown_advisory)):
        out = await server.evaluate_dependency_policy(
            "pypi",
            "demo",
            "1.0.0",
            max_severity="low",
        )

    assert out["verdict"] == "BLOCK"
    assert out["worst_severity"] == "unknown"
    assert out["advisories"][0]["severity"] == "unknown"
