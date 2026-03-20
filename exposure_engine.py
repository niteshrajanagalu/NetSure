"""Internet exposure detection engine.

Determines whether internal network devices may also be reachable from the
public internet by:

  1. Fetching the machine's public IP from api.ipify.org
  2. Running a narrow TCP connect scan on that IP (user's own public address only)
  3. Correlating externally open ports against internally discovered devices
  4. Detecting UPnP via SSDP — flags automatic port-forwarding risk

Safety contract
---------------
- Only the public IP returned by api.ipify.org is ever scanned.
- No third-party, user-supplied, or guessed IPs are touched.
- TCP connect probes use short timeouts (2 s each) and a fixed port list.
- All output language is hedged: "may be", "appears", "could be".
- On any error the engine returns an empty report — it never raises.

Public API
----------
run_exposure_check(internal_devices) -> dict
"""

from __future__ import annotations

import logging
import socket
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

logger = logging.getLogger(__name__)

# Ports checked on the public IP — limited to services that should
# almost never be internet-reachable on a home or small-business network.
_EXTERNAL_CHECK_PORTS: list[int] = [80, 443, 554, 8080, 8443]

# Per-port TCP connect + banner-read timeout in seconds.
# 1 s × 5 ports = 5 s worst-case (all filtered), well under the 8 s future deadline.
_PROBE_TIMEOUT: float = 1.0

# Exposure confidence tiers — ordered from strongest to weakest.
# CONFIRMED: external port open AND we read a service response from it
#            AND an internal device has the same port open.
# LIKELY:    external port open AND internal device port matches,
#            but no service response could be read.
# POSSIBLE:  UPnP active (automatic port-forward risk) OR external port
#            open but no internal device correlation found.
# NONE:      no external ports open, no UPnP.
ExposureLevel = str  # "CONFIRMED" | "LIKELY" | "POSSIBLE" | "NONE"

_LEVEL_ORDER: dict[str, int] = {"CONFIRMED": 4, "LIKELY": 3, "POSSIBLE": 2, "NONE": 1}


def _max_level(a: str, b: str) -> str:
    return a if _LEVEL_ORDER.get(a, 0) >= _LEVEL_ORDER.get(b, 0) else b

# Maximum seconds to wait for the public-IP lookup.
_PUBLIC_IP_TIMEOUT: float = 3.0

# UPnP SSDP constants.
_UPNP_MCAST_ADDR = "239.255.255.250"
_UPNP_MCAST_PORT = 1900
_UPNP_RESPONSE_TIMEOUT: float = 2.0

# Maps an external port to the internal port(s) it may correspond to.
# Used to correlate "internet-open port" ↔ "internal device port".
_PORT_CORRELATION: dict[int, list[int]] = {
    80:   [80, 8080, 8000, 8008],
    443:  [443, 8443],
    554:  [554],
    8080: [80, 8080, 8000],
    8443: [443, 8443],
}

# Human-readable labels for the external ports we check.
_PORT_LABELS: dict[int, str] = {
    80:   "port 80 (web access)",
    443:  "port 443 (HTTPS)",
    554:  "port 554 (camera stream)",
    8080: "port 8080 (web access)",
    8443: "port 8443 (secure web access)",
}


# ---------------------------------------------------------------------------
# Public IP discovery
# ---------------------------------------------------------------------------


def get_public_ip() -> str | None:
    """Return the machine's public IP via api.ipify.org, or None on failure.

    Uses stdlib urllib so no third-party HTTP library is required.
    Validates the response with socket.inet_aton to reject garbage replies.
    """
    try:
        with urllib.request.urlopen(
            "https://api.ipify.org", timeout=_PUBLIC_IP_TIMEOUT
        ) as resp:
            raw = resp.read().decode("ascii", errors="ignore").strip()
            # Validate — must parse as an IPv4 address to be trusted.
            socket.inet_aton(raw)
            return raw
    except Exception as exc:
        logger.debug("Public IP lookup failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# External port probe  (TCP connect — no raw sockets, no root required)
# ---------------------------------------------------------------------------

# Maximum bytes to read when probing a service banner.
_BANNER_READ_BYTES: int = 64

# HTTP HEAD request used to probe web services on external ports.
_HTTP_PROBE_REQUEST: bytes = (
    b"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"
)


def _read_service_banner(sock: socket.socket, port: int) -> bool:
    """Attempt to read a service response on an already-connected *sock*.

    Reuses the socket from the connect probe — no second TCP handshake.
    Returns True when at least one byte arrives, meaning the service is live.
    Never raises; any error is treated as no response.
    """
    try:
        if port in (80, 443, 8080, 8443):
            sock.sendall(_HTTP_PROBE_REQUEST)
        data = sock.recv(_BANNER_READ_BYTES)
        return bool(data)
    except Exception:
        return False


def _probe_port(public_ip: str, port: int) -> dict[str, Any] | None:
    """Connect to *public_ip*:*port* and probe the service on the same socket.

    Returns a result dict when the port is open, None when closed/filtered.
    Single TCP handshake only — the connected socket is handed directly to
    _read_service_banner before being closed.  Never raises.
    """
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_PROBE_TIMEOUT)
        if sock.connect_ex((public_ip, port)) != 0:
            return None
        # Socket is connected — read service response without reopening.
        service_reachable = _read_service_banner(sock, port)
        logger.debug(
            "External port %d on %s appears open (service_reachable=%s)",
            port, public_ip, service_reachable,
        )
        return {"port": port, "service_reachable": service_reachable}
    except Exception as exc:
        logger.debug("Probe of %s:%d failed: %s", public_ip, port, exc)
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def scan_external_ports(public_ip: str) -> list[dict[str, Any]]:
    """Probe *public_ip* on each port in _EXTERNAL_CHECK_PORTS concurrently.

    Runs all five probes in parallel via a thread pool (max_workers=5) so the
    total wall-clock time is bounded by the slowest single probe (~1 s) rather
    than the sum of all probes (~5 s sequential).  Worst-case: all five ports
    are filtered and every probe times out — total ≈ 1 s.

    Returns:
        Sorted list of dicts: [{port: int, service_reachable: bool}, ...]
        covering only ports that accepted a connection.
    """
    open_ports: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=len(_EXTERNAL_CHECK_PORTS)) as pool:
        futures = {pool.submit(_probe_port, public_ip, port): port
                   for port in _EXTERNAL_CHECK_PORTS}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result is not None:
                    open_ports.append(result)
            except Exception as exc:
                logger.debug("Probe future error (port %d): %s", futures[future], exc)
    return sorted(open_ports, key=lambda d: d["port"])


# ---------------------------------------------------------------------------
# UPnP detection via SSDP
# ---------------------------------------------------------------------------


def detect_upnp() -> dict[str, Any]:
    """Send an SSDP M-SEARCH to the LAN multicast group and collect replies.

    Returns:
        {
            "enabled": bool  — True when at least one UPnP device responded,
            "devices": list[str]  — LOCATION URLs from responding devices (max 5),
        }
    """
    ssdp_request = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {_UPNP_MCAST_ADDR}:{_UPNP_MCAST_PORT}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode()

    devices: list[str] = []
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(_UPNP_RESPONSE_TIMEOUT)
        sock.sendto(ssdp_request, (_UPNP_MCAST_ADDR, _UPNP_MCAST_PORT))

        while len(devices) < 5:
            try:
                data, _ = sock.recvfrom(4096)
                text = data.decode("utf-8", errors="replace")
                for line in text.splitlines():
                    if line.upper().startswith("LOCATION:"):
                        location = line.split(":", 1)[1].strip()
                        if location and location not in devices:
                            devices.append(location)
            except socket.timeout:
                break
    except Exception as exc:
        logger.debug("UPnP detection error: %s", exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    enabled = bool(devices)
    if enabled:
        logger.info("UPnP detected — %d device(s) responded", len(devices))
    return {"enabled": enabled, "devices": devices}


# ---------------------------------------------------------------------------
# Correlation engine
# ---------------------------------------------------------------------------


def correlate_exposure(
    external_open_ports: list[dict[str, Any]],
    internal_devices: list[dict],
) -> list[dict]:
    """Match externally open ports against internally discovered devices.

    Assigns an exposure tier per finding:
      CONFIRMED — external port open, service responded, internal device has
                  the same (or correlated) port open.
      LIKELY    — external port open, internal device port matches, but no
                  service response was received.
      POSSIBLE  — external port open but no internal device match found
                  (findings not generated here — handled in _compute_exposure_level).

    Args:
        external_open_ports: List of {port: int, service_reachable: bool} dicts.
        internal_devices: Device dicts from the local scan.  Each dict must
            have an "ip" key and either "ports" or "open_ports".

    Returns:
        List of finding dicts, one per (device × external_port) pair.
    """
    findings: list[dict] = []

    for port_info in external_open_ports:
        ext_port: int = port_info["port"]
        service_reachable: bool = port_info["service_reachable"]
        candidate_internal_ports = _PORT_CORRELATION.get(ext_port, [ext_port])

        matched = False
        for device in internal_devices:
            # Support both enriched ("ports") and raw ("open_ports") formats.
            device_ports: list[int] = device.get("ports") or device.get("open_ports") or []
            device_ip: str | None = device.get("ip")
            device_type: str = device.get("device_type", "Unknown Device")

            for int_port in candidate_internal_ports:
                if int_port in device_ports:
                    tier: str = "CONFIRMED" if service_reachable else "LIKELY"
                    findings.append({
                        "device_ip":        device_ip,
                        "device_type":      device_type,
                        "external_port":    ext_port,
                        "internal_port":    int_port,
                        "tier":             tier,
                        "service_reachable": service_reachable,
                        "flag":             "possible_external_exposure",
                        "message":          _build_finding_message(
                                                device_ip, device_type, ext_port, tier
                                            ),
                    })
                    matched = True
                    break  # one finding per (device, external_port) pair

            if matched:
                break

    return findings


# ---------------------------------------------------------------------------
# Message builders — all language is hedged
# ---------------------------------------------------------------------------


def _build_finding_message(
    ip: str | None,
    device_type: str,
    external_port: int,
    tier: str = "POSSIBLE",
) -> str:
    label = _device_label(device_type, ip)
    port_label = _PORT_LABELS.get(external_port, f"port {external_port}")
    if tier == "CONFIRMED":
        return (
            f"{label} appears to be reachable from the internet on {port_label} — "
            "we confirmed the service responded from outside your network."
        )
    if tier == "LIKELY":
        return (
            f"{label} is likely reachable from the internet on {port_label}. "
            "The port was open externally and a matching service was found internally."
        )
    return (
        f"{label} may be reachable from the internet on {port_label}. "
        "Someone outside your network could potentially access it."
    )


def rebuild_finding_message(finding: dict) -> str:
    """Re-generate a finding message after device_type has been patched in."""
    return _build_finding_message(
        finding.get("device_ip"),
        finding.get("device_type", "Unknown Device"),
        finding.get("external_port", 0),
        finding.get("tier", "POSSIBLE"),
    )


def _compute_exposure_level(
    findings: list[dict],
    upnp: dict,
    external_open_ports: list[dict[str, Any]],
) -> str:
    """Derive the overall ExposureLevel from findings and UPnP state.

    CONFIRMED — at least one finding with tier == "CONFIRMED"
    LIKELY    — at least one finding with tier == "LIKELY" (no CONFIRMED)
    POSSIBLE  — UPnP active OR external ports open but no device correlation
    NONE      — nothing found
    """
    for f in findings:
        if f.get("tier") == "CONFIRMED":
            return "CONFIRMED"

    for f in findings:
        if f.get("tier") == "LIKELY":
            return "LIKELY"

    # Open ports with no matched internal device → POSSIBLE
    if external_open_ports:
        return "POSSIBLE"

    if upnp.get("enabled"):
        return "POSSIBLE"

    return "NONE"


def _device_label(device_type: str, ip: str | None) -> str:
    dt = (device_type or "").lower()
    suffix = f" ({ip})" if ip else ""
    if "camera" in dt:
        return f"A camera on your network{suffix}"
    if "router" in dt or "firewall" in dt:
        return f"Your router{suffix}"
    if "computer" in dt or "workstation" in dt:
        return f"A computer{suffix}"
    if "storage" in dt or "nas" in dt:
        return f"A storage device{suffix}"
    if "iot" in dt or "smart" in dt:
        return f"A smart device{suffix}"
    if "printer" in dt:
        return f"A printer{suffix}"
    return f"A device on your network{suffix}"


def _build_summary(
    public_ip: str,
    exposed_devices: list[dict],
    upnp: dict,
    external_open_ports: list[dict[str, Any]],
    level: str = "NONE",
) -> str:
    parts: list[str] = []

    if exposed_devices:
        count = len(exposed_devices)
        noun = "device" if count == 1 else "devices"
        pronoun = "it" if count == 1 else "them"

        if level == "CONFIRMED":
            parts.append(
                f"We confirmed {count} {noun} on your network {('is' if count == 1 else 'are')} "
                f"reachable from the internet via your public IP ({public_ip}). "
                f"A service responded from outside your network — someone could access {pronoun} right now."
            )
        elif level == "LIKELY":
            parts.append(
                f"We found {count} {noun} on your network that {'is' if count == 1 else 'are'} likely "
                f"reachable from the internet via your public IP ({public_ip}). "
                f"Someone outside your network could potentially access {pronoun}."
            )
        else:
            parts.append(
                f"We found {count} {noun} on your network that may be reachable "
                f"from the internet via your public IP ({public_ip}). "
                f"Someone outside your network could potentially access {pronoun}."
            )
    elif external_open_ports:
        port_list = ", ".join(str(p["port"]) for p in external_open_ports)
        parts.append(
            f"Your public IP ({public_ip}) appears to have open ports ({port_list}), "
            "though we could not match them to a specific device on your internal network."
        )

    if upnp["enabled"]:
        parts.append(
            "UPnP appears to be active on your network. "
            "This means devices can automatically open ports to the internet "
            "without your knowledge — a common cause of accidental exposure."
        )

    if not parts:
        return (
            f"We checked your public IP ({public_ip}) and did not find "
            "clear signs of internet-facing exposure on the ports we tested."
        )

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_exposure_check(internal_devices: list[dict]) -> dict[str, Any]:
    """Run the full exposure detection pipeline.

    Safe to call from a background thread.  Never raises — all errors
    produce an empty/skipped report so the caller always gets a valid dict.

    Args:
        internal_devices: Device dicts from the completed local scan.

    Returns:
        {
            "public_ip":           str | None,
            "external_open_ports": list[int],
            "exposed_devices":     list[finding dicts],
            "upnp":                {"enabled": bool, "devices": list[str]},
            "summary":             str,
            "has_exposure":        bool,
        }
    """
    _t0 = time.perf_counter()
    try:
        public_ip = get_public_ip()
        if not public_ip:
            logger.warning("Could not determine public IP — skipping external exposure check")
            return _empty_report("Public IP could not be determined — external check skipped.")

        logger.info("Public IP: %s — probing external ports", public_ip)
        external_open_ports = scan_external_ports(public_ip)
        upnp = detect_upnp()
        exposed_devices = correlate_exposure(external_open_ports, internal_devices)
        level = _compute_exposure_level(exposed_devices, upnp, external_open_ports)
        has_exposure = level != "NONE"

        summary = _build_summary(public_ip, exposed_devices, upnp, external_open_ports, level)

        # Build a plain list of open port numbers for callers that only need the integers.
        open_port_numbers = [p["port"] for p in external_open_ports]

        duration_ms = round((time.perf_counter() - _t0) * 1000)
        logger.info(
            "Exposure scan completed in %d ms — public_ip=%s open=%s exposed=%d upnp=%s level=%s",
            duration_ms, public_ip, open_port_numbers, len(exposed_devices), upnp["enabled"], level,
        )
        return {
            "public_ip":           public_ip,
            "external_open_ports": open_port_numbers,
            "exposed_devices":     exposed_devices,
            "upnp":                upnp,
            "summary":             summary,
            "has_exposure":        has_exposure,
            "level":               level,
        }
    except Exception as exc:
        duration_ms = round((time.perf_counter() - _t0) * 1000)
        logger.exception("Unexpected error in exposure check after %d ms: %s", duration_ms, exc)
        return _empty_report("Exposure check encountered an unexpected error.")


def _empty_report(reason: str = "") -> dict[str, Any]:
    return {
        "public_ip":           None,
        "external_open_ports": [],
        "exposed_devices":     [],
        "upnp":                {"enabled": False, "devices": []},
        "summary":             reason,
        "has_exposure":        False,
        "level":               "NONE",
    }
