"""Context-aware security intelligence engine.

Turns raw port/service data into actionable device fingerprints,
configuration summaries, and prioritised security issues.

Extending the rule set requires only edits to the data structures
at the top of this module — no logic changes needed.
"""

from __future__ import annotations

import re
from typing import Callable, TypedDict


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class SecurityIssue(TypedDict):
    """A single actionable security finding for a device."""

    title: str
    severity: str          # "HIGH" | "MEDIUM" | "LOW"
    description: str
    recommendation: str


class KnownExploit(TypedDict):
    """A known public exploit pattern associated with a service or port."""

    name: str
    severity: str   # "HIGH" | "MEDIUM" | "LOW"
    note: str


class DeviceIntelligence(TypedDict):
    """Full intelligence report for one scanned host."""

    inferred_device_type: str
    confidence: float
    reasoning: str                    # human-readable classification explanation
    exposure: str
    configuration_summary: str
    issues: list[SecurityIssue]
    primary_issue: SecurityIssue | None
    known_exploits: list[KnownExploit]
    exploit_risk_level: str           # "HIGH" | "MEDIUM" | "LOW"
    primary_exploit: KnownExploit | None
    lateral_movement: dict            # can_be_entry, can_be_pivot, blast_radius, reasoning


# ---------------------------------------------------------------------------
# Internal rule types
# ---------------------------------------------------------------------------


class _Rule(TypedDict):
    condition: Callable[[list[int]], bool]
    title: str
    severity: str
    description: str
    recommendation: str


# ---------------------------------------------------------------------------
# Device fingerprinting
# ---------------------------------------------------------------------------

# Each entry: (label, port_predicate, service_predicate, base_confidence).
# port_predicate:    Callable[[list[int]], bool]
# service_predicate: Callable[[list[str]], bool] | None  (None = ignore services)
# base_confidence:   float — boosted when both port + service predicates match.
#
# Evaluated top-to-bottom; first match wins for device_type.
_FINGERPRINTS: list[tuple[str, Callable[[list[int]], bool], Callable[[list[str]], bool] | None, float]] = [
    (
        "IP Camera",
        lambda p: 554 in p,
        lambda s: "rtsp" in s,
        0.9,
    ),
    (
        "IP Camera",
        lambda p: 554 in p,
        None,
        0.75,
    ),
    # IoT device with web + telnet (more specific than plain Router/Firewall)
    (
        "IoT Device",
        lambda p: 23 in p and (80 in p or 8080 in p),
        lambda s: "telnet" in s and ("http" in s or "http-alt" in s),
        0.85,
    ),
    (
        "IoT Device",
        lambda p: 23 in p and (80 in p or 8080 in p),
        None,
        0.7,
    ),
    (
        "Windows Machine",
        lambda p: 445 in p,
        lambda s: "microsoft-ds" in s or "netbios-ssn" in s,
        0.95,
    ),
    (
        "Windows Machine",
        lambda p: 445 in p,
        None,
        0.8,
    ),
    (
        "Remote Desktop Host",
        lambda p: 3389 in p,
        lambda s: "ms-wbt-server" in s,
        0.95,
    ),
    (
        "Remote Desktop Host",
        lambda p: 3389 in p,
        None,
        0.8,
    ),
    (
        "Network Printer",
        lambda p: 9100 in p or 515 in p,
        lambda s: "ipp" in s or "jetdirect" in s,
        0.95,
    ),
    (
        "Network Printer",
        lambda p: 9100 in p or 515 in p,
        None,
        0.75,
    ),
    (
        "Router / Firewall",
        lambda p: 161 in p or (23 in p and 22 not in p),
        lambda s: "snmp" in s or "telnet" in s,
        0.9,
    ),
    (
        "Router / Firewall",
        lambda p: 161 in p or (23 in p and 22 not in p),
        None,
        0.75,
    ),
    (
        "Database Server",
        lambda p: any(q in p for q in (3306, 5432, 1433, 27017)),
        lambda s: any(svc in s for svc in ("mysql", "postgresql", "ms-sql-s", "mongodb")),
        0.95,
    ),
    (
        "Database Server",
        lambda p: any(q in p for q in (3306, 5432, 1433, 27017)),
        None,
        0.8,
    ),
    (
        "Mail Server",
        lambda p: any(q in p for q in (25, 143, 110, 993, 465)),
        lambda s: any(svc in s for svc in ("smtp", "imap", "pop3", "imaps", "smtps")),
        0.95,
    ),
    (
        "Mail Server",
        lambda p: any(q in p for q in (25, 143, 110, 993, 465)),
        None,
        0.75,
    ),
    (
        "Web Server",
        lambda p: (80 in p or 443 in p) and 22 in p,
        lambda s: "http" in s or "https" in s,
        0.85,
    ),
    (
        "Web Server",
        lambda p: (80 in p or 443 in p) and 22 in p,
        None,
        0.7,
    ),
    (
        "Linux / Unix Server",
        lambda p: 22 in p,
        lambda s: "ssh" in s,
        0.75,
    ),
    (
        "Linux / Unix Server",
        lambda p: 22 in p,
        None,
        0.6,
    ),
    # Service-driven media detection — high confidence when xmpp/cslistener present
    (
        "Media / Streaming Device",
        lambda p: any(port in p for port in (8008, 8009, 8010, 8443, 9000, 1900)),
        lambda s: any(svc in s for svc in ("xmpp", "cslistener", "googlecast")),
        0.95,
    ),
    (
        "Media / Streaming Device",
        lambda p: any(port in p for port in (8008, 8009, 8010, 8443, 9000, 1900)),
        None,
        0.7,
    ),
    (
        "Network Device / Router",
        lambda p: (80 in p or 443 in p) and 22 not in p and 554 not in p,
        lambda s: "http" in s or "https" in s,
        0.65,
    ),
    (
        "Network Device / Router",
        lambda p: (80 in p or 443 in p) and 22 not in p and 554 not in p,
        None,
        0.5,
    ),
    # VoIP
    (
        "VoIP Device",
        lambda p: 5060 in p or 5061 in p,
        lambda s: "sip" in s,
        0.95,
    ),
    (
        "VoIP Device",
        lambda p: 5060 in p or 5061 in p,
        None,
        0.75,
    ),
    # Smart home / IoT hub (MQTT)
    (
        "Smart Home Hub",
        lambda p: 1883 in p or 8883 in p,
        lambda s: "mqtt" in s,
        0.95,
    ),
    (
        "Smart Home Hub",
        lambda p: 1883 in p or 8883 in p,
        None,
        0.80,
    ),
    # NAS / Network Storage (AFP, NFS, or SMB+NFS combo)
    (
        "NAS / Storage Device",
        lambda p: 548 in p or (2049 in p and 445 in p),
        None,
        0.80,
    ),
    # In-memory / NoSQL databases exposed directly
    (
        "Database Server",
        lambda p: any(q in p for q in (6379, 9200, 9300, 11211, 5984)),
        None,
        0.75,
    ),
    # Development / test server: 8080 alone without SSH or DB ports
    (
        "Development Server",
        lambda p: 8080 in p and 22 not in p and not any(
            q in p for q in (3306, 5432, 1433, 27017, 445, 3389)
        ),
        lambda s: "http" in s,
        0.70,
    ),
    (
        "Development Server",
        lambda p: 8080 in p and 22 not in p and not any(
            q in p for q in (3306, 5432, 1433, 27017, 445, 3389)
        ),
        None,
        0.55,
    ),
]


# All service keywords that participate in fingerprint matching — used for reasoning strings.
_SERVICE_KEYWORDS: frozenset[str] = frozenset({
    "rtsp", "http", "https", "ssh", "ftp", "telnet", "smtp", "imap", "pop3",
    "mysql", "postgresql", "ms-sql-s", "mongodb", "microsoft-ds", "netbios-ssn",
    "ms-wbt-server", "snmp", "ipp", "jetdirect", "xmpp", "cslistener",
    "googlecast", "sip", "mqtt", "ajp13",
})


def _match_fingerprint(
    ports: list[int],
    services: list[str],
) -> tuple[str, float, str]:
    """Return (device_type, confidence, reasoning) for the best matching fingerprint.

    Tries port+service predicates first (higher confidence), then
    port-only predicates.  First match wins within each priority tier.
    Returns (None, 0.0, "") when no fingerprint matches — caller handles fallback.
    """
    svc_set = {s.lower() for s in services}

    # First pass: port + service match (highest confidence)
    for label, port_pred, svc_pred, confidence in _FINGERPRINTS:
        if svc_pred is not None and port_pred(ports) and svc_pred(svc_set):
            reason = (
                f"Matched on port pattern and nmap service name "
                f"(ports={ports}, services={list(svc_set & _SERVICE_KEYWORDS)})"
            )
            return label, confidence, reason

    # Second pass: port-only match
    for label, port_pred, svc_pred, confidence in _FINGERPRINTS:
        if svc_pred is None and port_pred(ports):
            reason = (
                f"Matched on port pattern only — nmap service name did not confirm "
                f"(ports={ports})"
            )
            return label, confidence, reason

    return "", 0.0, ""  # caller will invoke probabilistic classifier


def infer_device_type(ports: list[int], services: list[str]) -> str:
    """Return a human-readable device type based on open ports and services."""
    label, _, _ = _match_fingerprint(ports, services)
    return label or "Unknown Device"


# ---------------------------------------------------------------------------
# Part 2 — Service validation (nmap misidentification correction)
# ---------------------------------------------------------------------------

# HTTP-family ports that nmap sometimes misreports as rtsp
_HTTP_PORTS:  frozenset[int] = frozenset({80, 8000, 8008, 8080, 8888})
_HTTPS_PORTS: frozenset[int] = frozenset({443, 8443})
# Canonical RTSP port — even if nmap says http here, keep rtsp context
_RTSP_PORT = 554


def validate_service(
    ports: list[int],
    services: list[str],
    probes: list[dict],
) -> tuple[list[str], list[str]]:
    """Correct nmap service misidentifications using probe data.

    Rules applied (in priority order):
      1. HTTP port (80/8000/8008/8080/8888) labeled 'rtsp' and HTTP probe
         confirms reachability → override service to 'http'.
      2. HTTPS port (443/8443) labeled 'rtsp' and HTTPS probe confirms
         reachability → override service to 'https'.
      3. Port 554 labeled 'http'/'https' → revert to 'rtsp' (trust port
         semantics for the canonical RTSP port).
      4. Any port where a working HTTP/HTTPS probe exists but nmap returned
         an empty service string → fill in 'http' or 'https'.

    Args:
        ports:    Open port numbers from nmap (parallel to services).
        services: Service name strings from nmap.
        probes:   Probe result dicts from probe_engine.

    Returns:
        (corrected_services, corrections) — corrected list (same length) and
        a human-readable list of changes made (empty when nothing changed).
    """
    # Build probe lookup: port → probe dict (empty when no probes provided)
    probe_by_port: dict[int, dict] = {}
    for p in probes:
        port = p.get("port")
        if port is not None:
            # Prefer reachable probes; last probe wins per port
            if p.get("reachable") or port not in probe_by_port:
                probe_by_port[port] = p

    corrected = list(services)
    corrections: list[str] = []

    for idx, (port, svc) in enumerate(zip(ports, services)):
        svc_lower = svc.lower()
        probe = probe_by_port.get(port)

        # Rule 1: HTTP port mis-labeled as rtsp
        if port in _HTTP_PORTS and "rtsp" in svc_lower:
            if probe and probe.get("probe_type") == "http" and probe.get("reachable"):
                corrected[idx] = "http"
                corrections.append(
                    f"port {port}: overrode nmap service 'rtsp' → 'http' "
                    f"(HTTP probe confirmed reachable)"
                )

        # Rule 2: HTTPS port mis-labeled as rtsp
        elif port in _HTTPS_PORTS and "rtsp" in svc_lower:
            if probe and probe.get("probe_type") == "https" and probe.get("reachable"):
                corrected[idx] = "https"
                corrections.append(
                    f"port {port}: overrode nmap service 'rtsp' → 'https' "
                    f"(HTTPS probe confirmed reachable)"
                )

        # Rule 3: Port 554 mis-labeled as http/https → restore rtsp
        elif port == _RTSP_PORT and svc_lower in ("http", "https", "http-alt"):
            corrected[idx] = "rtsp"
            corrections.append(
                f"port {port}: overrode nmap service '{svc}' → 'rtsp' "
                f"(port 554 is the canonical RTSP port)"
            )

        # Rule 4: Empty service but probe succeeded → fill in service name
        elif not svc_lower and probe and probe.get("reachable"):
            pt = probe.get("probe_type", "")
            if pt in ("http", "https"):
                corrected[idx] = pt
                corrections.append(
                    f"port {port}: filled missing service name → '{pt}' "
                    f"(probe confirmed reachable)"
                )

        # Rule 5: Port 8009 labeled 'ajp13' → override to 'castv2'
        # nmap guesses AJP (Apache Tomcat) on 8009, but this port is used by
        # Chromecast and other media devices. Prevents Ghostcat false positives.
        elif port == 8009 and "ajp" in svc_lower:
            corrected[idx] = "castv2"
            corrections.append(
                f"port {port}: overrode nmap service 'ajp13' → 'castv2' "
                f"(port 8009 is used by Cast protocol, not Apache Tomcat AJP)"
            )

    return corrected, corrections


# ---------------------------------------------------------------------------
# Part 1 — Probabilistic classifier (replaces "Unknown Device")
# ---------------------------------------------------------------------------

# Weak signal tables: (port-or-service, candidate_type, score)
_PROB_PORT_HINTS: dict[int, tuple[str, float]] = {
    631:   ("Network Printer",         0.55),  # IPP — very specific
    9100:  ("Network Printer",         0.40),  # JetDirect raw
    515:   ("Network Printer",         0.35),  # LPD
    5060:  ("VoIP Device",            0.55),
    5061:  ("VoIP Device",            0.45),
    1883:  ("Smart Home Hub",         0.55),
    8883:  ("Smart Home Hub",         0.50),
    1900:  ("Smart Home Hub",         0.30),  # UPnP
    5683:  ("Smart Home Hub",         0.35),  # CoAP
    548:   ("NAS / Storage Device",   0.55),  # AFP
    2049:  ("NAS / Storage Device",   0.40),  # NFS
    111:   ("NAS / Storage Device",   0.30),  # rpcbind
    9200:  ("Database Server",        0.50),  # Elasticsearch
    9300:  ("Database Server",        0.45),
    6379:  ("Database Server",        0.55),  # Redis
    11211: ("Database Server",        0.50),  # Memcached
    5984:  ("Database Server",        0.50),  # CouchDB
    8008:  ("Media / Streaming Device", 0.40),
    8009:  ("Media / Streaming Device", 0.45),
    8010:  ("Media / Streaming Device", 0.35),
    7000:  ("Media / Streaming Device", 0.30),  # AirPlay
    3689:  ("Media / Streaming Device", 0.40),  # DAAP/iTunes
    8080:  ("Development Server",     0.25),  # too common to be strong alone
    8000:  ("Development Server",     0.25),
    4443:  ("Development Server",     0.25),
    3000:  ("Development Server",     0.35),  # Node/Rails dev
    5000:  ("Development Server",     0.35),  # Flask/dev
    4000:  ("Development Server",     0.30),
}

_PROB_SERVICE_HINTS: dict[str, tuple[str, float]] = {
    "ipp":         ("Network Printer",         0.50),
    "jetdirect":   ("Network Printer",         0.45),
    "sip":         ("VoIP Device",            0.55),
    "sip-tls":     ("VoIP Device",            0.50),
    "mqtt":        ("Smart Home Hub",         0.55),
    "upnp":        ("Smart Home Hub",         0.35),
    "nfs":         ("NAS / Storage Device",   0.45),
    "afp":         ("NAS / Storage Device",   0.55),
    "xmpp":        ("Media / Streaming Device", 0.45),
    "cslistener":  ("Media / Streaming Device", 0.50),
    "googlecast":  ("Media / Streaming Device", 0.60),
    "daap":        ("Media / Streaming Device", 0.50),
    "elasticsearch": ("Database Server",      0.55),
    "redis":       ("Database Server",        0.55),
    "memcache":    ("Database Server",        0.50),
}

# Probe title/server substrings → candidate type
_PROB_TITLE_HINTS: list[tuple[str, str, float]] = [
    ("index of",        "Development Server",      0.55),
    ("directory listing","Development Server",     0.55),
    ("django",          "Development Server",      0.50),
    ("flask",           "Development Server",      0.50),
    ("webpack",         "Development Server",      0.45),
    ("localhost",       "Development Server",      0.25),
    ("printer",         "Network Printer",         0.55),
    ("print server",    "Network Printer",         0.60),
    ("cups",            "Network Printer",         0.55),
    ("camera",          "IP Camera",               0.55),
    ("ipcam",           "IP Camera",               0.60),
    ("nvr",             "IP Camera",               0.50),
    ("dvr",             "IP Camera",               0.50),
    ("synology",        "NAS / Storage Device",   0.70),
    ("qnap",            "NAS / Storage Device",   0.70),
    ("freenas",         "NAS / Storage Device",   0.65),
    ("truenas",         "NAS / Storage Device",   0.65),
    ("chromecast",      "Media / Streaming Device", 0.80),
    ("google cast",     "Media / Streaming Device", 0.75),
    ("roku",            "Media / Streaming Device", 0.70),
    ("plex",            "Media / Streaming Device", 0.60),
    ("kodi",            "Media / Streaming Device", 0.55),
    ("voip",            "VoIP Device",            0.55),
    ("asterisk",        "VoIP Device",            0.70),
    ("cisco phone",     "VoIP Device",            0.65),
    ("home assistant",  "Smart Home Hub",         0.80),
    ("openhab",         "Smart Home Hub",         0.75),
    ("hubitat",         "Smart Home Hub",         0.75),
    ("router",          "Network Device / Router", 0.55),
    ("gateway",         "Network Device / Router", 0.50),
    ("modem",           "Network Device / Router", 0.55),
    ("admin panel",     "Network Device / Router", 0.35),
]

_PROB_SERVER_HINTS: list[tuple[str, str, float]] = [
    ("cups",        "Network Printer",          0.50),
    ("asterisk",    "VoIP Device",             0.65),
    ("synology",    "NAS / Storage Device",    0.70),
    ("qnap",        "NAS / Storage Device",    0.70),
    ("plex",        "Media / Streaming Device", 0.55),
    ("werkzeug",    "Development Server",       0.60),
    ("gunicorn",    "Development Server",       0.55),
    ("uvicorn",     "Development Server",       0.55),
    ("node",        "Development Server",       0.40),
    ("python",      "Development Server",       0.45),
    ("ruby",        "Development Server",       0.40),
]


def _probabilistic_classify(
    ports: list[int],
    services: list[str],
    probes: list[dict],
) -> tuple[str, float, str]:
    """Classify a device probabilistically when no fingerprint matches.

    Accumulates weak signals from ports, service names, and probe data
    into per-candidate scores.  Returns the best candidate if its score
    meets a minimum threshold, otherwise returns a generic fallback.

    Returns:
        (device_type, confidence, reasoning)
    """
    scores: dict[str, float] = {}

    # Port signals
    for port in ports:
        hint = _PROB_PORT_HINTS.get(port)
        if hint:
            candidate, weight = hint
            scores[candidate] = scores.get(candidate, 0.0) + weight

    # Service signals
    svc_set = {s.lower() for s in services if s}
    for svc in svc_set:
        hint = _PROB_SERVICE_HINTS.get(svc)
        if hint:
            candidate, weight = hint
            scores[candidate] = scores.get(candidate, 0.0) + weight

    # Probe signals
    for probe in probes:
        title  = (probe.get("title")  or "").lower()
        server = (probe.get("server") or "").lower()
        banner = (probe.get("banner") or "").lower()

        for keyword, candidate, weight in _PROB_TITLE_HINTS:
            if keyword in title:
                scores[candidate] = scores.get(candidate, 0.0) + weight

        for keyword, candidate, weight in _PROB_SERVER_HINTS:
            if keyword in server:
                scores[candidate] = scores.get(candidate, 0.0) + weight

        # Banner signals (lower weight — less reliable)
        if "asterisk" in banner:
            scores["VoIP Device"] = scores.get("VoIP Device", 0.0) + 0.40
        if "cups" in banner or "printer" in banner:
            scores["Network Printer"] = scores.get("Network Printer", 0.0) + 0.35
        if "synology" in banner or "qnap" in banner:
            scores["NAS / Storage Device"] = scores.get("NAS / Storage Device", 0.0) + 0.50

    if not scores:
        return (
            "Unidentified Device",
            0.15,
            f"No recognizable service patterns detected on ports {ports}",
        )

    best = max(scores, key=lambda k: scores[k])
    raw_score = scores[best]

    # Require a minimum evidence threshold
    if raw_score < 0.30:
        return (
            "Unidentified Device",
            round(min(0.20, raw_score), 2),
            f"Weak signals detected (best candidate: {best}, score={raw_score:.2f}) — "
            f"insufficient evidence for confident classification",
        )

    confidence = round(min(0.70, raw_score), 2)  # cap probabilistic confidence at 0.70
    all_signals = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    signal_summary = ", ".join(f"{k}={v:.2f}" for k, v in all_signals[:3])
    reasoning = (
        f"Probabilistic classification from weak signals "
        f"(ports={ports}, services={sorted(svc_set)}) — "
        f"candidate scores: {signal_summary}"
    )
    return best, confidence, reasoning


# ---------------------------------------------------------------------------
# Configuration summary
# ---------------------------------------------------------------------------

# Each entry: (predicate, summary fragment).  All matching fragments are joined.
_CONFIG_FRAGMENTS: list[tuple[Callable[[list[int]], bool], str]] = [
    (lambda p: 23 in p,    "Telnet service exposed with no encryption"),
    (lambda p: 554 in p,   "RTSP streaming enabled and accessible over network"),
    (lambda p: 445 in p,   "SMB file sharing exposed"),
    (lambda p: 3389 in p,  "Remote Desktop (RDP) accessible over network"),
    (lambda p: 80 in p,    "Web interface accessible over HTTP (unencrypted)"),
    (lambda p: 8080 in p,  "Secondary HTTP interface accessible"),
    (lambda p: 443 in p,   "HTTPS interface present"),
    (lambda p: 22 in p,    "SSH remote access enabled"),
    (lambda p: 21 in p,    "FTP service exposed (plaintext transfer)"),
    (lambda p: 3306 in p,  "MySQL database port exposed"),
    (lambda p: 5432 in p,  "PostgreSQL database port exposed"),
    (lambda p: 27017 in p, "MongoDB database port exposed"),
    (lambda p: 1433 in p,  "MSSQL database port exposed"),
    (lambda p: 161 in p,   "SNMP management interface enabled"),
    (lambda p: 9100 in p,  "Network printing service exposed"),
    (lambda p: 8008 in p,  "Media streaming/control interface detected"),
    (lambda p: 8009 in p,  "Device control channel exposed"),
    (lambda p: 8443 in p,  "Alternate HTTPS interface available"),
    (lambda p: any(port in p for port in (8008, 8009, 8010)), "IoT/media service ports detected"),
]


def _build_configuration_summary(ports: list[int]) -> str:
    """Compose a human-readable configuration summary from matching fragments.

    Args:
        ports: Open port numbers found on the host.

    Returns:
        Semicolon-joined description of active services, or a generic fallback.
    """
    fragments = [text for pred, text in _CONFIG_FRAGMENTS if pred(ports)]
    return "; ".join(fragments) if fragments else "Unrecognized service pattern — possible IoT or proprietary device"


# ---------------------------------------------------------------------------
# Exposure scoring
# ---------------------------------------------------------------------------

_HIGH_EXPOSURE_PORTS: frozenset[int] = frozenset({23, 445, 3389, 554, 21, 3306, 5432, 1433, 27017})
_MEDIUM_EXPOSURE_PORTS: frozenset[int] = frozenset({80, 8008, 8009, 8010, 8080, 8443, 161, 22})


def _compute_exposure(ports: list[int]) -> str:
    """Return an exposure level based on which ports are open.

    HIGH:   any critically dangerous port (Telnet, SMB, RDP, database, FTP, RTSP)
    MEDIUM: web interfaces, media control, SSH, SNMP
    LOW:    only HTTPS or other low-risk ports

    Args:
        ports: Open port numbers found on the host.

    Returns:
        "HIGH", "MEDIUM", or "LOW".
    """
    port_set = set(ports)
    if port_set & _HIGH_EXPOSURE_PORTS:
        return "HIGH"
    if port_set & _MEDIUM_EXPOSURE_PORTS:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Issue rules
# ---------------------------------------------------------------------------

DEVICE_RULES: dict[str, list[_Rule]] = {
    "IP Camera": [
        {
            "condition": lambda p: 554 in p,
            "title": "RTSP stream exposed",
            "severity": "HIGH",
            "description": (
                "Live video feed may be accessed without authentication. "
                "Unauthenticated RTSP streams are indexed by search engines "
                "such as Shodan."
            ),
            "recommendation": "Disable RTSP or restrict access via VLAN/firewall rules.",
        },
        {
            "condition": lambda p: 80 in p or 8080 in p,
            "title": "Camera web interface exposed",
            "severity": "MEDIUM",
            "description": "Camera admin panel is reachable from the network over HTTP.",
            "recommendation": "Enable HTTPS, disable HTTP, and restrict access by IP.",
        },
        {
            "condition": lambda p: 23 in p,
            "title": "Telnet enabled on camera",
            "severity": "HIGH",
            "description": "Many IoT cameras ship with default Telnet credentials.",
            "recommendation": "Disable Telnet immediately; use SSH if remote CLI is required.",
        },
    ],
    "IoT Device": [
        {
            "condition": lambda p: 23 in p,
            "title": "Telnet enabled",
            "severity": "HIGH",
            "description": (
                "Device allows insecure remote access over Telnet. "
                "Credentials travel in plaintext and are trivially intercepted."
            ),
            "recommendation": "Disable Telnet and replace with SSH.",
        },
        {
            "condition": lambda p: 80 in p or 8080 in p,
            "title": "Unencrypted web interface exposed",
            "severity": "MEDIUM",
            "description": "Admin interface served over HTTP allows credential interception.",
            "recommendation": "Enable HTTPS and restrict web interface access to management VLAN.",
        },
    ],
    "Windows Machine": [
        {
            "condition": lambda p: 445 in p,
            "title": "SMB exposed",
            "severity": "HIGH",
            "description": (
                "SMB exposure enables lateral movement, credential relay attacks "
                "(NTLM relay), and ransomware propagation (e.g. EternalBlue)."
            ),
            "recommendation": "Block SMB at the perimeter; restrict to required hosts only.",
        },
        {
            "condition": lambda p: 3389 in p,
            "title": "RDP exposed",
            "severity": "HIGH",
            "description": (
                "Remote Desktop is a primary target for brute-force and "
                "credential-stuffing attacks."
            ),
            "recommendation": "Restrict RDP behind VPN or firewall; enable Network Level Authentication.",
        },
    ],
    "Remote Desktop Host": [
        {
            "condition": lambda p: 3389 in p,
            "title": "RDP exposed",
            "severity": "HIGH",
            "description": (
                "Remote Desktop is a primary target for brute-force and "
                "credential-stuffing attacks."
            ),
            "recommendation": "Restrict RDP behind VPN; enforce MFA; enable account lockout.",
        },
    ],
    "Linux / Unix Server": [
        {
            "condition": lambda p: 22 in p,
            "title": "SSH exposed to network",
            "severity": "LOW",
            "description": "SSH is encrypted but exposes the server to brute-force attacks.",
            "recommendation": "Disable password auth; use key-based login; restrict source IPs.",
        },
        {
            "condition": lambda p: 21 in p,
            "title": "FTP service detected",
            "severity": "MEDIUM",
            "description": "FTP transfers credentials and data in plaintext.",
            "recommendation": "Replace FTP with SFTP or SCP.",
        },
    ],
    "Web Server": [
        {
            "condition": lambda p: 80 in p,
            "title": "HTTP without HTTPS",
            "severity": "MEDIUM",
            "description": "HTTP port exposed; traffic can be intercepted or downgraded even when HTTPS is available.",
            "recommendation": "Install a TLS certificate and redirect HTTP → HTTPS.",
        },
        {
            "condition": lambda p: 22 in p,
            "title": "SSH exposed to network",
            "severity": "LOW",
            "description": "SSH is encrypted but exposes the server to brute-force attacks.",
            "recommendation": "Disable password auth; use key-based login; restrict source IPs.",
        },
    ],
    "Database Server": [
        {
            "condition": lambda p: any(q in p for q in (3306, 5432, 1433, 27017)),
            "title": "Database port directly exposed",
            "severity": "HIGH",
            "description": (
                "Database services should never be reachable from untrusted networks. "
                "Direct exposure enables brute-force, injection, and data exfiltration."
            ),
            "recommendation": "Bind database to localhost; use an application layer or VPN for remote access.",
        },
    ],
    "Mail Server": [
        {
            "condition": lambda p: 25 in p,
            "title": "SMTP port exposed",
            "severity": "MEDIUM",
            "description": "Open SMTP may be abused as an open relay for spam.",
            "recommendation": "Enforce relay restrictions; require SMTP AUTH; consider port 587.",
        },
    ],
    "Router / Firewall": [
        {
            "condition": lambda p: 23 in p,
            "title": "Telnet management interface exposed",
            "severity": "HIGH",
            "description": "Network device management over Telnet is plaintext and easily intercepted.",
            "recommendation": "Disable Telnet; manage device exclusively over SSH.",
        },
        {
            "condition": lambda p: 161 in p,
            "title": "SNMP exposed",
            "severity": "MEDIUM",
            "description": "SNMP v1/v2 uses community strings instead of real authentication.",
            "recommendation": "Use SNMPv3 with AuthPriv; restrict SNMP to the management VLAN.",
        },
    ],
    "Media / Streaming Device": [
        {
            "condition": lambda p: 8008 in p,
            "title": "Media control port exposed",
            "severity": "MEDIUM",
            "description": "Device control interface may be accessible over the network.",
            "recommendation": "Restrict access via network segmentation or firewall.",
        },
        {
            "condition": lambda p: 8443 in p,
            "title": "Alternate HTTPS port exposed",
            "severity": "LOW",
            "description": "Service is exposed on a non-standard HTTPS port.",
            "recommendation": "Ensure proper authentication and restrict unnecessary exposure.",
        },
    ],
    "Network Device / Router": [
        {
            "condition": lambda p: 80 in p,
            "title": "HTTP without HTTPS",
            "severity": "MEDIUM",
            "description": "HTTP port exposed; traffic can be intercepted or downgraded even when HTTPS is available.",
            "recommendation": "Disable HTTP access; enforce HTTPS-only management interface.",
        },
        {
            "condition": lambda p: 443 in p and 80 not in p,
            "title": "Web management interface exposed",
            "severity": "LOW",
            "description": "Device management interface is reachable from the network over HTTPS.",
            "recommendation": "Restrict management interface access to a dedicated management VLAN.",
        },
    ],
    "Unknown Device": [
        {
            "condition": lambda p: 23 in p,
            "title": "Telnet enabled on unidentified device",
            "severity": "HIGH",
            "description": "Telnet exposes credentials in plaintext on an unknown device.",
            "recommendation": "Identify the device and disable Telnet immediately.",
        },
        {
            "condition": lambda p: any(q in p for q in (3306, 5432, 1433, 27017)),
            "title": "Database port exposed on unidentified device",
            "severity": "HIGH",
            "description": "A database port is reachable from an unidentified host.",
            "recommendation": "Identify the device and restrict database access.",
        },
    ],
    "Unidentified Device": [
        {
            "condition": lambda p: 23 in p,
            "title": "Telnet enabled on unidentified device",
            "severity": "HIGH",
            "description": "Telnet exposes credentials in plaintext on an unknown device.",
            "recommendation": "Identify the device and disable Telnet immediately.",
        },
        {
            "condition": lambda p: any(q in p for q in (3306, 5432, 1433, 27017)),
            "title": "Database port exposed on unidentified device",
            "severity": "HIGH",
            "description": "A database port is reachable from an unidentified host.",
            "recommendation": "Identify the device and restrict database access.",
        },
        {
            "condition": lambda p: bool(p),
            "title": "Unrecognized device with open ports",
            "severity": "MEDIUM",
            "description": (
                "This device could not be classified. Open ports represent an unknown "
                "attack surface that cannot be assessed without device identification."
            ),
            "recommendation": "Identify this device and audit its running services.",
        },
    ],
    "VoIP Device": [
        {
            "condition": lambda p: 5060 in p,
            "title": "SIP port exposed",
            "severity": "MEDIUM",
            "description": (
                "SIP (Session Initiation Protocol) on port 5060 is unencrypted. "
                "Credentials and call metadata can be intercepted. SIP scanners "
                "target this port for toll fraud and eavesdropping."
            ),
            "recommendation": "Use SIP-TLS (port 5061) and restrict SIP to authorised hosts.",
        },
    ],
    "Smart Home Hub": [
        {
            "condition": lambda p: 1883 in p,
            "title": "MQTT broker exposed without TLS",
            "severity": "HIGH",
            "description": (
                "MQTT on port 1883 transmits messages in plaintext. "
                "An attacker on the network can subscribe to all topics, "
                "intercept sensor data, and publish malicious commands to "
                "connected smart home devices."
            ),
            "recommendation": "Require TLS on port 8883; restrict MQTT access to localhost or trusted clients.",
        },
    ],
    "NAS / Storage Device": [
        {
            "condition": lambda p: 548 in p,
            "title": "Apple Filing Protocol exposed",
            "severity": "MEDIUM",
            "description": "AFP (port 548) exposes network file shares. Older AFP versions have known authentication weaknesses.",
            "recommendation": "Disable AFP if unused; restrict to authorised hosts; use SMB with encryption instead.",
        },
        {
            "condition": lambda p: 2049 in p,
            "title": "NFS share exposed",
            "severity": "HIGH",
            "description": (
                "NFS exports may be accessible without authentication depending on "
                "export configuration. This can expose all files on the share."
            ),
            "recommendation": "Restrict NFS exports to specific trusted IP addresses; require Kerberos auth.",
        },
    ],
    "Development Server": [
        {
            "condition": lambda p: 8080 in p or 8000 in p or 3000 in p or 5000 in p,
            "title": "Development server exposed on network",
            "severity": "MEDIUM",
            "description": (
                "A development or test server is reachable from the network. "
                "Dev servers typically run without authentication, may expose "
                "debug endpoints, and often contain sensitive application source code or credentials."
            ),
            "recommendation": "Bind development servers to localhost (127.0.0.1) only; never expose to LAN without authentication.",
        },
    ],
}

# Generic rules applied to every device regardless of type
_GENERIC_RULES: list[_Rule] = [
    {
        "condition": lambda p: 21 in p,
        "title": "FTP service detected",
        "severity": "MEDIUM",
        "description": "FTP transfers credentials and data in plaintext.",
        "recommendation": "Replace FTP with SFTP or SCP.",
    },
    {
        "condition": lambda p: 9100 in p,
        "title": "Network printing port exposed",
        "severity": "LOW",
        "description": "Raw printing port can be used to intercept or inject print jobs.",
        "recommendation": "Restrict port 9100 to authorised print clients only.",
    },
    {
        "condition": lambda p: 8008 in p,
        "title": "Media control port exposed",
        "severity": "MEDIUM",
        "description": "Device control interface may be accessible over the network.",
        "recommendation": "Restrict access via network segmentation or firewall.",
    },
    {
        "condition": lambda p: 8443 in p,
        "title": "Alternate HTTPS port exposed",
        "severity": "LOW",
        "description": "Service is exposed on a non-standard HTTPS port.",
        "recommendation": "Ensure proper authentication and restrict unnecessary exposure.",
    },
]


def _collect_issues(device_type: str, ports: list[int]) -> list[SecurityIssue]:
    """Evaluate all applicable rules and return matching security issues.

    Applies device-type-specific rules first, then generic rules.
    Deduplicates by issue title so a single issue is never listed twice.

    Args:
        device_type: Label returned by infer_device_type().
        ports: Open port numbers found on the host.

    Returns:
        Ordered list of SecurityIssue dicts for all matching rules.
    """
    seen: set[str] = set()
    results: list[SecurityIssue] = []

    rule_sets = [
        DEVICE_RULES.get(device_type, []),
        _GENERIC_RULES,
    ]
    for rule_set in rule_sets:
        for rule in rule_set:
            if rule["title"] in seen:
                continue
            if rule["condition"](ports):
                seen.add(rule["title"])
                results.append(
                    SecurityIssue(
                        title=rule["title"],
                        severity=rule["severity"],
                        description=rule["description"],
                        recommendation=rule["recommendation"],
                    )
                )

    return results


def _pick_primary_issue(issues: list[SecurityIssue]) -> SecurityIssue | None:
    """Return the first HIGH severity issue, or the first issue, or None."""
    for issue in issues:
        if issue["severity"] == "HIGH":
            return issue
    return issues[0] if issues else None


# ---------------------------------------------------------------------------
# Known exploit intelligence (local dataset — no external API calls)
# ---------------------------------------------------------------------------

# Keyed by service name (lowercase, as returned by nmap).
# Each entry is a list of known public exploit patterns for that service class.
# Disclaimer applied uniformly in lookup_exploits(); not duplicated here.
_EXPLOIT_DB_BY_SERVICE: dict[str, list[dict[str, str]]] = {
    "ftp": [
        {"name": "vsFTPd 2.3.4 Backdoor (CVE-2011-2523)", "severity": "HIGH"},
        {"name": "ProFTPD mod_copy Unauthenticated File Copy (CVE-2015-3306)", "severity": "HIGH"},
        {"name": "Anonymous FTP Login", "severity": "MEDIUM"},
    ],
    "telnet": [
        {"name": "Telnet Plaintext Credential Interception", "severity": "HIGH"},
        {"name": "Mirai Botnet Default Credential Brute-Force", "severity": "HIGH"},
    ],
    "smtp": [
        {"name": "Sendmail / Postfix Open Relay Abuse", "severity": "MEDIUM"},
        {"name": "SMTP User Enumeration (VRFY/EXPN)", "severity": "LOW"},
    ],
    "http": [
        {"name": "Common Web Misconfigurations (directory listing, default creds)", "severity": "MEDIUM"},
        {"name": "HTTP TRACE / TRACK Method Enabled (XST)", "severity": "LOW"},
        {"name": "Slowloris DoS (CVE-2007-6750)", "severity": "MEDIUM"},
    ],
    "https": [
        {"name": "POODLE – SSLv3 Padding Oracle (CVE-2014-3566)", "severity": "MEDIUM"},
        {"name": "BEAST – TLS 1.0 CBC Vulnerability (CVE-2011-3389)", "severity": "LOW"},
        {"name": "Heartbleed – OpenSSL Buffer Over-read (CVE-2014-0160)", "severity": "HIGH"},
    ],
    "https-alt": [
        {"name": "Heartbleed – OpenSSL Buffer Over-read (CVE-2014-0160)", "severity": "HIGH"},
        {"name": "Non-standard HTTPS Port – Possible Misconfiguration", "severity": "LOW"},
    ],
    "microsoft-ds": [
        {"name": "EternalBlue SMB RCE (MS17-010 / CVE-2017-0144)", "severity": "HIGH"},
        {"name": "SMBGhost RCE (CVE-2020-0796)", "severity": "HIGH"},
        {"name": "NTLM Relay Attack via SMB", "severity": "HIGH"},
        {"name": "WannaCry Ransomware Propagation Vector", "severity": "HIGH"},
    ],
    "netbios-ssn": [
        {"name": "EternalBlue SMB RCE (MS17-010 / CVE-2017-0144)", "severity": "HIGH"},
        {"name": "NetBIOS Name Service Spoofing", "severity": "MEDIUM"},
    ],
    "ms-wbt-server": [
        {"name": "BlueKeep RDP RCE (CVE-2019-0708)", "severity": "HIGH"},
        {"name": "DejaBlue RDP RCE (CVE-2019-1181/1182)", "severity": "HIGH"},
        {"name": "RDP Credential Brute-Force", "severity": "HIGH"},
        {"name": "RDP Man-in-the-Middle (NLA disabled)", "severity": "MEDIUM"},
    ],
    "ssh": [
        {"name": "OpenSSH Username Enumeration (CVE-2018-15473)", "severity": "LOW"},
        {"name": "SSH Brute-Force / Credential Stuffing", "severity": "MEDIUM"},
        {"name": "Libssh Authentication Bypass (CVE-2018-10933)", "severity": "HIGH"},
    ],
    "mysql": [
        {"name": "MySQL Unauthenticated Remote Root (CVE-2012-2122)", "severity": "HIGH"},
        {"name": "MySQL Remote Code Execution via UDF", "severity": "HIGH"},
    ],
    "postgresql": [
        {"name": "PostgreSQL COPY TO/FROM PROGRAM RCE (CVE-2019-9193)", "severity": "HIGH"},
    ],
    "ms-sql-s": [
        {"name": "MSSQL xp_cmdshell Remote Command Execution", "severity": "HIGH"},
        {"name": "MSSQL Brute-Force (sa account)", "severity": "HIGH"},
    ],
    "mongodb": [
        {"name": "MongoDB No-Auth Remote Access (default config)", "severity": "HIGH"},
    ],
    "rtsp": [
        {"name": "Unauthenticated RTSP Stream Access", "severity": "HIGH"},
        {"name": "IP Camera Default Credentials (Shodan-indexed)", "severity": "HIGH"},
    ],
    "snmp": [
        {"name": "SNMP Community String Brute-Force (v1/v2c)", "severity": "MEDIUM"},
        {"name": "SNMP Information Disclosure (device config leak)", "severity": "MEDIUM"},
    ],
    "imap": [
        {"name": "IMAP Credential Brute-Force", "severity": "MEDIUM"},
    ],
    "pop3": [
        {"name": "POP3 Credential Brute-Force", "severity": "MEDIUM"},
    ],
    "ipp": [
        {"name": "CUPS IPP Remote Code Execution (CVE-2024-47176)", "severity": "HIGH"},
    ],
    "jetdirect": [
        {"name": "HP JetDirect Unauthorized Access / Print Job Interception", "severity": "MEDIUM"},
    ],
    "xmpp": [
        {"name": "XMPP Cleartext Credential Exposure (STARTTLS not enforced)", "severity": "MEDIUM"},
    ],
    "ajp13": [
        {"name": "Apache Ghostcat AJP File Inclusion (CVE-2020-1938)", "severity": "HIGH"},
    ],
}

# Fallback: port-number → exploit list, used when service name is unrecognised.
_EXPLOIT_DB_BY_PORT: dict[int, list[dict[str, str]]] = {
    21:    _EXPLOIT_DB_BY_SERVICE["ftp"],
    22:    _EXPLOIT_DB_BY_SERVICE["ssh"],
    23:    _EXPLOIT_DB_BY_SERVICE["telnet"],
    25:    _EXPLOIT_DB_BY_SERVICE["smtp"],
    80:    _EXPLOIT_DB_BY_SERVICE["http"],
    110:   _EXPLOIT_DB_BY_SERVICE["pop3"],
    143:   _EXPLOIT_DB_BY_SERVICE["imap"],
    443:   _EXPLOIT_DB_BY_SERVICE["https"],
    445:   _EXPLOIT_DB_BY_SERVICE["microsoft-ds"],
    554:   _EXPLOIT_DB_BY_SERVICE["rtsp"],
    1433:  _EXPLOIT_DB_BY_SERVICE["ms-sql-s"],
    3306:  _EXPLOIT_DB_BY_SERVICE["mysql"],
    3389:  _EXPLOIT_DB_BY_SERVICE["ms-wbt-server"],
    5432:  _EXPLOIT_DB_BY_SERVICE["postgresql"],
    8008:  _EXPLOIT_DB_BY_SERVICE["http"],
    8080:  _EXPLOIT_DB_BY_SERVICE["http"],
    8443:  _EXPLOIT_DB_BY_SERVICE["https-alt"],
    9100:  _EXPLOIT_DB_BY_SERVICE["jetdirect"],
    27017: _EXPLOIT_DB_BY_SERVICE["mongodb"],
}

_EXPLOIT_NOTE = (
    "Similar services have known vulnerabilities; "
    "risk depends on device version and configuration."
)

_SEVERITY_ORDER: dict[str, int] = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def lookup_exploits(ports: list[int], services: list[str]) -> list[KnownExploit]:
    """Return up to 3 known public exploit patterns for the detected services.

    Matches by service name first (preferred — more precise), then falls back
    to port number for services nmap could not identify.  Candidates are
    deduplicated by name, sorted HIGH → MEDIUM → LOW, and capped at 3 entries
    (HIGH priority; LOW entries are dropped when the list is already long).

    Does NOT call any external API.  All data is from the local _EXPLOIT_DB_*
    datasets seeded from public sources (Exploit-DB, NVD, CVE advisories).

    Args:
        ports: Open port numbers discovered by the scanner.
        services: Service name strings corresponding to each port (parallel list).

    Returns:
        Prioritised, deduplicated list of up to 3 KnownExploit dicts.
        Empty list when no known patterns apply.
    """
    seen: set[str] = set()
    candidates: list[dict[str, str]] = []

    # Pass 1: match by service name
    for service in services:
        for entry in _EXPLOIT_DB_BY_SERVICE.get(service.lower(), []):
            if entry["name"] not in seen:
                seen.add(entry["name"])
                candidates.append(entry)

    # Pass 2: fallback to port number for unmatched ports
    for port, service in zip(ports, services):
        if service.lower() in _EXPLOIT_DB_BY_SERVICE:
            continue
        for entry in _EXPLOIT_DB_BY_PORT.get(port, []):
            if entry["name"] not in seen:
                seen.add(entry["name"])
                candidates.append(entry)

    # Sort HIGH → MEDIUM → LOW, then keep at most 3 (prefer HIGH; drop LOW if full)
    candidates.sort(key=lambda e: _SEVERITY_ORDER.get(e["severity"], 0), reverse=True)
    selected: list[dict[str, str]] = []
    for entry in candidates:
        if len(selected) >= 3:
            break
        if len(selected) == 2 and entry["severity"] == "LOW":
            continue
        selected.append(entry)

    return [
        KnownExploit(name=e["name"], severity=e["severity"], note=_EXPLOIT_NOTE)
        for e in selected
    ]


def _exploit_risk_level(exploits: list[KnownExploit]) -> str:
    """Return overall exploit risk level from the collected exploit list."""
    for e in exploits:
        if e["severity"] == "HIGH":
            return "HIGH"
    for e in exploits:
        if e["severity"] == "MEDIUM":
            return "MEDIUM"
    return "LOW"


def _primary_exploit(exploits: list[KnownExploit]) -> KnownExploit | None:
    """Return first HIGH exploit, else first exploit, else None."""
    for e in exploits:
        if e["severity"] == "HIGH":
            return e
    return exploits[0] if exploits else None


# ---------------------------------------------------------------------------
# Device role inference
# ---------------------------------------------------------------------------

_ROLE_MAP: dict[str, str] = {
    "Router / Firewall":        "GATEWAY",
    "Network Device / Router":  "GATEWAY",
    "IP Camera":                "OBSERVER",
    "Media / Streaming Device": "EDGE_DEVICE",
    "IoT Device":               "EDGE_DEVICE",
    "Windows Machine":          "COMPUTE",
    "Remote Desktop Host":      "COMPUTE",
    "Linux / Unix Server":      "COMPUTE",
    "Web Server":               "COMPUTE",
    "Database Server":          "COMPUTE",
    "Mail Server":              "COMPUTE",
    "Network Printer":          "EDGE_DEVICE",
    "VoIP Device":              "EDGE_DEVICE",
    "Smart Home Hub":           "EDGE_DEVICE",
    "NAS / Storage Device":     "COMPUTE",
    "Development Server":       "COMPUTE",
    "Unknown Device":           "UNKNOWN",
    "Unidentified Device":      "UNKNOWN",
}


# ---------------------------------------------------------------------------
# Part 3 — Lateral movement intelligence
# ---------------------------------------------------------------------------

_ENTRY_PORTS: frozenset[int] = frozenset({
    21, 22, 23, 25, 80, 443, 445, 554, 1883, 3306, 3389, 5060,
    5432, 8008, 8080, 8443, 9100, 27017,
})
_PIVOT_PORTS: frozenset[int] = frozenset({22, 23, 80, 445, 3389, 8080})


def _compute_lateral_movement(
    role: str,
    ports: list[int],
    exploit_risk_level: str,
) -> dict:
    """Compute lateral movement attributes for a device.

    Args:
        role:               Network role from infer_device_role().
        ports:              Open port numbers.
        exploit_risk_level: Overall exploit risk ("HIGH"/"MEDIUM"/"LOW").

    Returns:
        Dict with can_be_entry (bool), can_be_pivot (bool),
        blast_radius (int 0-10), and reasoning (str).
    """
    port_set = set(ports)

    # Entry point: device is directly exploitable
    can_be_entry = bool(port_set & _ENTRY_PORTS) or exploit_risk_level == "HIGH"

    # Pivot potential and blast radius by role
    if role == "GATEWAY":
        can_be_pivot = True
        blast_radius  = 10
        lm_reasoning  = (
            "Gateway device with full network visibility — compromise gives attacker "
            "traffic interception and routing control over all connected devices."
        )
    elif role == "COMPUTE":
        pivot_ports = port_set & _PIVOT_PORTS
        can_be_pivot = len(pivot_ports) >= 1 or exploit_risk_level in ("HIGH", "MEDIUM")
        blast_radius  = 6 if can_be_pivot else 3
        lm_reasoning  = (
            f"Compute device with {len(port_set)} open service(s). "
            + (
                "Multiple accessible services enable lateral movement to adjacent systems."
                if can_be_pivot
                else "Limited pivot surface; compromise mainly affects this host."
            )
        )
    elif role == "EDGE_DEVICE":
        control_ports = port_set & {23, 80, 8008, 8080, 1883}
        can_be_pivot  = bool(control_ports)
        blast_radius   = 4 if can_be_pivot else 1
        lm_reasoning   = (
            "IoT/edge device — "
            + (
                f"open control port(s) {sorted(control_ports)} enable pivot "
                "to other devices on the network if compromised."
                if can_be_pivot
                else "limited pivot potential; no control ports detected."
            )
        )
    elif role == "OBSERVER":
        can_be_pivot = False
        blast_radius  = 1
        lm_reasoning  = (
            "Monitoring/camera device — primary risk is data exposure (video feed). "
            "Limited pivot capability; no typical lateral movement ports open."
        )
    else:
        # UNKNOWN / Unidentified
        can_be_pivot = bool(port_set & _PIVOT_PORTS)
        blast_radius  = 3 if can_be_pivot else 1
        lm_reasoning  = (
            "Device role unknown — pivot capability cannot be fully assessed. "
            + (
                f"Port(s) {sorted(port_set & _PIVOT_PORTS)} suggest possible lateral movement."
                if can_be_pivot
                else "No typical pivot ports detected."
            )
        )

    # Exploit risk amplifies blast radius
    if exploit_risk_level == "HIGH" and blast_radius < 8:
        blast_radius = min(10, blast_radius + 2)

    return {
        "can_be_entry":  can_be_entry,
        "can_be_pivot":  can_be_pivot,
        "blast_radius":  blast_radius,
        "reasoning":     lm_reasoning,
    }


def infer_device_role(device_type: str) -> str:
    """Map a device type label to a network role.

    Args:
        device_type: Label returned by infer_device_type().

    Returns:
        One of "GATEWAY", "OBSERVER", "EDGE_DEVICE", "COMPUTE", "UNKNOWN".
    """
    return _ROLE_MAP.get(device_type, "UNKNOWN")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _enrich_from_probes(
    issues: list[SecurityIssue],
    config_summary: str,
    confidence: float,
    probes: list[dict],
) -> tuple[list[SecurityIssue], str, float]:
    """Apply probe results to upgrade issues, config summary, and confidence.

    Args:
        issues: Issues already collected from port/service rules.
        config_summary: Configuration summary built from port fragments.
        confidence: Base confidence from fingerprint matching.
        probes: Probe results from probe_engine.probe_device().

    Returns:
        Updated (issues, config_summary, confidence) tuple.
    """
    seen_titles = {i["title"] for i in issues}
    extra_fragments: list[str] = []
    extra_issues: list[SecurityIssue] = []

    for probe in probes:
        probe_type = probe.get("probe_type")

        # ── HTTP probe signals ─────────────────────────────────────────────
        if probe_type == "http" and probe.get("reachable"):
            port = probe.get("port")

            # HTTP reachable with no redirect → explicit issue
            if not probe.get("redirect_to_https"):
                title = "HTTP served without HTTPS redirect"
                if title not in seen_titles:
                    seen_titles.add(title)
                    extra_issues.append(SecurityIssue(
                        title=title,
                        severity="MEDIUM",
                        description=(
                            f"HTTP on port {port} is reachable and does not redirect to HTTPS. "
                            "Traffic is transmitted in plaintext and is susceptible to interception."
                        ),
                        recommendation="Configure a permanent redirect (301) from HTTP to HTTPS.",
                    ))

            # Server header disclosure
            server = probe.get("server")
            if server:
                extra_fragments.append(f"Server header: {server}")
                # Flag version disclosure if server contains digits (version string)
                if re.search(r"\d", server):
                    title = "Server version disclosed in HTTP header"
                    if title not in seen_titles:
                        seen_titles.add(title)
                        extra_issues.append(SecurityIssue(
                            title=title,
                            severity="LOW",
                            description=(
                                f"The Server header reveals version information: '{server}'. "
                                "Version disclosure aids targeted attack research."
                            ),
                            recommendation="Configure the web server to suppress or genericise the Server header.",
                        ))
            else:
                extra_fragments.append("No Server header present")

            # Page title
            title_text = probe.get("title")
            if title_text:
                extra_fragments.append(f"Page title: {title_text!r}")

        # ── HTTPS probe signals ────────────────────────────────────────────
        if probe_type == "https" and probe.get("reachable"):
            server = probe.get("server")
            if server and re.search(r"\d", server):
                title = "Server version disclosed in HTTPS header"
                if title not in seen_titles:
                    seen_titles.add(title)
                    extra_issues.append(SecurityIssue(
                        title=title,
                        severity="LOW",
                        description=(
                            f"The Server header on the HTTPS endpoint reveals version info: '{server}'."
                        ),
                        recommendation="Suppress the Server header in TLS responses.",
                    ))
            if probe.get("tls_ok"):
                extra_fragments.append("TLS endpoint confirmed reachable")

        # ── Banner probe signals ───────────────────────────────────────────
        if probe_type == "banner":
            banner = probe.get("banner")
            port = probe.get("port")
            if banner:
                snippet = banner[:80].replace("\n", " ").replace("\r", "")
                extra_fragments.append(f"Port {port} banner: {snippet!r}")
                # Version string in banner
                if re.search(r"\d+\.\d+", banner):
                    title = f"Service version exposed in banner (port {port})"
                    if title not in seen_titles:
                        seen_titles.add(title)
                        extra_issues.append(SecurityIssue(
                            title=title,
                            severity="LOW",
                            description=(
                                f"The service on port {port} broadcasts version information in its "
                                f"connection banner: {snippet!r}"
                            ),
                            recommendation="Configure the service to suppress version disclosure in its banner.",
                        ))
                # Boost confidence when banner is non-empty (device is real and responsive)
                confidence = min(1.0, confidence + 0.05)

    merged_summary = config_summary
    if extra_fragments:
        merged_summary = config_summary + "; " + "; ".join(extra_fragments)

    return issues + extra_issues, merged_summary, confidence


def analyze_device(
    ports: list[int],
    services: list[str],
    probes: list[dict] | None = None,
) -> DeviceIntelligence:
    """Produce a full security intelligence report for a single scanned host.

    Pipeline:
      1. validate_service()     — correct nmap misidentifications using probe data
      2. _match_fingerprint()   — deterministic fingerprint matching
      3. _probabilistic_classify() — fallback when no fingerprint matches
      4. _collect_issues()      — rule-based security findings
      5. _enrich_from_probes()  — probe-derived issues and config fragments
      6. lookup_exploits()      — local exploit intelligence dataset
      7. _compute_lateral_movement() — entry/pivot/blast_radius analysis

    Args:
        ports:  Open port numbers discovered by the scanner.
        services: Service name strings corresponding to each port.
        probes: Optional probe results from probe_engine.probe_device().

    Returns:
        DeviceIntelligence with all intelligence fields populated.
    """
    _probes = probes or []

    # ── Step 1: correct nmap service misidentifications ─────────────────────
    corrected_services, corrections = validate_service(ports, services, _probes)

    # ── Step 2: deterministic fingerprint match ──────────────────────────────
    device_type, confidence, reasoning = _match_fingerprint(ports, corrected_services)

    # ── Step 3: probabilistic fallback when no fingerprint matched ───────────
    if not device_type:
        device_type, confidence, reasoning = _probabilistic_classify(
            ports, corrected_services, _probes
        )

    # Append any service-correction notes to reasoning
    if corrections:
        reasoning += " [service corrections: " + "; ".join(corrections) + "]"

    # ── Step 4: collect security issues ─────────────────────────────────────
    issues = _collect_issues(device_type, ports)
    config_summary = _build_configuration_summary(ports)

    # ── Step 5: enrich from probe data ───────────────────────────────────────
    if _probes:
        issues, config_summary, confidence = _enrich_from_probes(
            issues, config_summary, confidence, _probes
        )
        # Probe-confirmed development server upgrade
        for probe in _probes:
            title_text = (probe.get("title") or "").lower()
            if ("index of" in title_text or "directory listing" in title_text) and device_type not in (
                "Database Server", "Web Server", "Linux / Unix Server"
            ):
                if device_type in ("Unidentified Device", "Unknown Device", "Network Device / Router"):
                    device_type = "Development Server"
                    confidence = max(confidence, 0.65)
                    reasoning += " [probe title suggests directory listing — reclassified as Development Server]"
                    issues = _collect_issues(device_type, ports)

    # ── Step 6: exploit intelligence ────────────────────────────────────────
    exploits = lookup_exploits(ports, corrected_services)
    erl = _exploit_risk_level(exploits)

    base_exposure = _compute_exposure(ports)
    if erl == "HIGH" and base_exposure == "LOW":
        exposure = "MEDIUM"
    elif erl == "HIGH" and base_exposure == "MEDIUM":
        exposure = "HIGH"
    else:
        exposure = base_exposure

    # ── Step 7: lateral movement ─────────────────────────────────────────────
    role = infer_device_role(device_type)
    lateral = _compute_lateral_movement(role, ports, erl)

    return DeviceIntelligence(
        inferred_device_type=device_type,
        confidence=round(confidence, 2),
        reasoning=reasoning,
        exposure=exposure,
        configuration_summary=config_summary,
        issues=issues,
        primary_issue=_pick_primary_issue(issues),
        known_exploits=exploits,
        exploit_risk_level=erl,
        primary_exploit=_primary_exploit(exploits),
        lateral_movement=lateral,
    )
