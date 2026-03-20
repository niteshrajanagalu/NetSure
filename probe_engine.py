"""Service probing layer — lightweight active validation beyond nmap data.

Probes are intentionally shallow: 2-second timeouts, no heavy tools,
no subprocess calls.  The goal is configuration signals, not exploitation.

Public API
----------
probe_service(ip, port, service) -> dict
    Route a single port/service to the appropriate probe and return results.

probe_device(ip, ports, services) -> list[dict]
    Run probe_service for every port on a device and return the list.
"""

from __future__ import annotations

import logging
import re
import socket

import requests

logger = logging.getLogger(__name__)

_TIMEOUT = 2  # seconds — applied to every network call


# ---------------------------------------------------------------------------
# HTTP probe
# ---------------------------------------------------------------------------


def probe_http(ip: str, port: int) -> dict:
    """Probe an HTTP endpoint and capture surface-level configuration signals.

    Args:
        ip: Target IP address.
        port: TCP port to probe.

    Returns:
        Dict with keys: reachable, status_code, server, title,
        redirect_to_https, https_valid.
    """
    result: dict = {
        "reachable": False,
        "status_code": None,
        "server": None,
        "title": None,
        "redirect_to_https": False,
        "https_valid": False,
    }

    url = f"http://{ip}:{port}"
    try:
        resp = requests.get(
            url,
            timeout=_TIMEOUT,
            allow_redirects=False,
            verify=False,  # noqa: S501 — intentional; we are probing, not verifying
        )
        result["reachable"] = True
        result["status_code"] = resp.status_code
        result["server"] = resp.headers.get("Server") or resp.headers.get("server")

        # Detect redirect to HTTPS
        if resp.status_code in (301, 302, 307, 308):
            location = resp.headers.get("Location", "")
            if location.lower().startswith("https://"):
                result["redirect_to_https"] = True

        # Extract <title> from body (best-effort, first 4 KB only)
        body = resp.text[:4096]
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if m:
            result["title"] = m.group(1).strip()[:120]

    except requests.exceptions.SSLError:
        # Port is speaking HTTPS, not HTTP
        result["https_valid"] = True
    except requests.exceptions.ConnectionError:
        pass
    except requests.exceptions.Timeout:
        pass
    except Exception as exc:  # noqa: BLE001
        logger.debug("probe_http %s:%d unexpected error: %s", ip, port, exc)

    return result


# ---------------------------------------------------------------------------
# HTTPS probe
# ---------------------------------------------------------------------------


def probe_https(ip: str, port: int) -> dict:
    """Probe an HTTPS endpoint for basic TLS configuration signals.

    Args:
        ip: Target IP address.
        port: TCP port to probe.

    Returns:
        Dict with keys: reachable, status_code, server, title, tls_ok.
    """
    result: dict = {
        "reachable": False,
        "status_code": None,
        "server": None,
        "title": None,
        "tls_ok": False,
    }

    url = f"https://{ip}:{port}"
    try:
        resp = requests.get(
            url,
            timeout=_TIMEOUT,
            allow_redirects=False,
            verify=False,  # noqa: S501 — intentional; probing only
        )
        result["reachable"] = True
        result["tls_ok"] = True
        result["status_code"] = resp.status_code
        result["server"] = resp.headers.get("Server") or resp.headers.get("server")

        body = resp.text[:4096]
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if m:
            result["title"] = m.group(1).strip()[:120]

    except requests.exceptions.SSLError:
        result["reachable"] = True  # port answered, cert/TLS issue
    except requests.exceptions.ConnectionError:
        pass
    except requests.exceptions.Timeout:
        pass
    except Exception as exc:  # noqa: BLE001
        logger.debug("probe_https %s:%d unexpected error: %s", ip, port, exc)

    return result


# ---------------------------------------------------------------------------
# Banner grab
# ---------------------------------------------------------------------------


def probe_banner(ip: str, port: int) -> str | None:
    """Connect to a TCP port and read the initial server banner.

    Args:
        ip: Target IP address.
        port: TCP port to connect to.

    Returns:
        Decoded banner string (stripped), or None if nothing was received.
    """
    try:
        with socket.create_connection((ip, port), timeout=_TIMEOUT) as sock:
            sock.settimeout(_TIMEOUT)
            raw = sock.recv(1024)
            if raw:
                return raw.decode("utf-8", errors="replace").strip()
    except (OSError, TimeoutError):
        pass
    except Exception as exc:  # noqa: BLE001
        logger.debug("probe_banner %s:%d unexpected error: %s", ip, port, exc)
    return None


# ---------------------------------------------------------------------------
# Service probe router
# ---------------------------------------------------------------------------

_HTTP_SERVICES = {"http", "http-alt", "http-proxy", "webcache"}
_HTTPS_SERVICES = {"https", "https-alt", "ssl/http"}
_BANNER_PORTS = {21, 22, 23, 25, 110, 143}


def probe_service(ip: str, port: int, service: str) -> dict:
    """Route a single port/service to the appropriate probe function.

    Args:
        ip: Target IP address.
        port: TCP port number.
        service: nmap service name (e.g. "http", "ssh", "ftp").

    Returns:
        Probe result dict.  Empty dict when no probe applies.
    """
    svc = service.lower()

    if svc in _HTTPS_SERVICES or port == 443:
        probe_result = probe_https(ip, port)
        probe_result["probe_type"] = "https"
        return probe_result

    if svc in _HTTP_SERVICES or port in {80, 8008, 8080, 8443, 9000}:
        probe_result = probe_http(ip, port)
        probe_result["probe_type"] = "http"
        # If HTTP probe found the port speaks HTTPS, retry properly
        if probe_result.get("https_valid"):
            https_result = probe_https(ip, port)
            https_result["probe_type"] = "https"
            return https_result
        return probe_result

    if port in _BANNER_PORTS:
        banner = probe_banner(ip, port)
        return {"probe_type": "banner", "banner": banner}

    return {}


# ---------------------------------------------------------------------------
# Device-level probe orchestration
# ---------------------------------------------------------------------------


def probe_device(ip: str, ports: list[int], services: list[str]) -> list[dict]:
    """Run probe_service for every open port on a device.

    Args:
        ip: Target IP address.
        ports: Open port numbers (parallel to services).
        services: nmap service names (parallel to ports).

    Returns:
        List of probe result dicts, one per port (empty dict = no probe ran).
    """
    results = []
    for port, service in zip(ports, services):
        try:
            result = probe_service(ip, port, service)
        except Exception as exc:  # noqa: BLE001
            logger.warning("probe_device %s:%d failed: %s", ip, port, exc)
            result = {}
        result["port"] = port
        results.append(result)
    return results
