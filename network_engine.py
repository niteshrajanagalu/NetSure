"""Network-level intelligence layer.

Reasons across ALL devices in a scan — not per-device — to produce:
  * a network graph (nodes + edges)
  * attack path narratives
  * plain-language impact statements
  * ranked risk list
  * top 3 prioritised actions

All logic is deterministic and dependency-free.

Public API
----------
build_network_graph(devices)     -> dict
generate_attack_paths(devices)   -> list[str]
generate_impact_statements(devices) -> list[str]
rank_network_risks(devices)      -> list[dict]
generate_top_actions(devices)    -> list[dict]
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Priority scoring
# ---------------------------------------------------------------------------

_SEVERITY_SCORE: dict[str, int] = {"HIGH": 40, "MEDIUM": 20, "LOW": 5}
_EXPOSURE_SCORE: dict[str, int] = {"HIGH": 30, "MEDIUM": 15, "LOW": 0}
_ROLE_SCORE: dict[str, int] = {
    "GATEWAY": 20,
    "COMPUTE": 10,
    "OBSERVER": 8,
    "EDGE_DEVICE": 8,
    "UNKNOWN": 5,
}
_EXPLOIT_BONUS: dict[str, int] = {"HIGH": 10, "MEDIUM": 5, "LOW": 0}


def _priority_score(device: dict) -> int:
    """Compute a 0–100 priority score for a single device dict.

    Inputs consumed: exposure, exploit_risk_level, role, primary_issue.
    """
    score = 0
    score += _EXPOSURE_SCORE.get(device.get("exposure", "LOW"), 0)
    score += _EXPLOIT_BONUS.get(device.get("exploit_risk_level", "LOW"), 0)
    score += _ROLE_SCORE.get(device.get("role", "UNKNOWN"), 0)
    pi = device.get("primary_issue")
    if pi:
        score += _SEVERITY_SCORE.get(pi.get("severity", "LOW"), 0)
    return min(score, 100)


# ---------------------------------------------------------------------------
# Network graph
# ---------------------------------------------------------------------------


def build_network_graph(devices: list[dict]) -> dict:
    """Build a simplified network graph from the device list.

    Every non-gateway device is connected to the gateway.  When no gateway
    is present, all devices are treated as peers on a flat network.

    Args:
        devices: List of enriched device dicts (must contain 'ip' and 'role').

    Returns:
        Dict with 'nodes' (list of node dicts) and 'edges' (list of edge dicts).
    """
    nodes = [
        {
            "id": d["ip"],
            "role": d.get("role", "UNKNOWN"),
            "device_type": d.get("device_type", "Unknown Device"),
            "exposure": d.get("exposure", "LOW"),
            "priority": _priority_score(d),
        }
        for d in devices
    ]

    gateways = [d["ip"] for d in devices if d.get("role") == "GATEWAY"]
    edges: list[dict] = []

    if gateways:
        hub = gateways[0]
        for d in devices:
            if d["ip"] != hub:
                edges.append({"source": hub, "target": d["ip"], "type": "routes_through"})
        # Additional gateways connect to primary gateway
        for gw in gateways[1:]:
            edges.append({"source": hub, "target": gw, "type": "peer_gateway"})
    else:
        # Flat network — connect every pair once
        ips = [d["ip"] for d in devices]
        for i, src in enumerate(ips):
            for dst in ips[i + 1 :]:
                edges.append({"source": src, "target": dst, "type": "peer"})

    return {"nodes": nodes, "edges": edges}


# ---------------------------------------------------------------------------
# Attack paths
# ---------------------------------------------------------------------------


def generate_attack_paths(devices: list[dict]) -> list[str]:
    """Generate human-readable attack path narratives across the network.

    Args:
        devices: List of enriched device dicts with role and priority_score.

    Returns:
        List of attack path strings. Empty when no significant paths exist.
    """
    paths: list[str] = []

    gateways = [d for d in devices if d.get("role") == "GATEWAY"]
    observers = [d for d in devices if d.get("role") == "OBSERVER"]
    edge_devices = [d for d in devices if d.get("role") == "EDGE_DEVICE"]
    compute = [d for d in devices if d.get("role") == "COMPUTE"]

    risky_gateways = [d for d in gateways if _priority_score(d) > 40]

    # Gateway compromise path
    for gw in risky_gateways:
        paths.append(
            f"Compromising the gateway ({gw['ip']}) would expose all devices on this network "
            f"to traffic interception, credential theft, and lateral movement."
        )

    # Observer reachable through gateway
    if observers and risky_gateways:
        ips = ", ".join(d["ip"] for d in observers)
        paths.append(
            f"Camera or monitoring device(s) at {ips} could be accessed through a compromised "
            f"gateway, exposing live video or sensor data."
        )

    # Edge device as entry point
    for ed in edge_devices:
        open_control = any(
            p in ed.get("ports", []) for p in (23, 80, 8008, 8009, 8010, 8080)
        )
        if open_control:
            paths.append(
                f"IoT/edge device at {ed['ip']} has open control ports and could be used as "
                f"an initial entry point into the network, then pivoted through to other devices."
            )

    # Exposed compute reaching database or sensitive services
    for dev in compute:
        if any(p in dev.get("ports", []) for p in (3306, 5432, 1433, 27017)):
            paths.append(
                f"The compute device at {dev['ip']} exposes a database port directly. "
                f"An attacker with network access could exfiltrate data without pivoting."
            )

    # High-exploit-risk device with no gateway protection
    if not gateways:
        high_risk = [d for d in devices if d.get("exploit_risk_level") == "HIGH"]
        if high_risk:
            ips = ", ".join(d["ip"] for d in high_risk)
            paths.append(
                f"No gateway device was detected. High-risk device(s) at {ips} are directly "
                f"reachable from the network with no chokepoint for traffic filtering."
            )

    return paths


# ---------------------------------------------------------------------------
# Impact statements
# ---------------------------------------------------------------------------


def generate_impact_statements(devices: list[dict]) -> list[str]:
    """Generate plain-language impact statements for the network as a whole.

    Args:
        devices: List of enriched device dicts.

    Returns:
        List of non-technical impact strings.
    """
    impacts: list[str] = []
    seen: set[str] = set()

    role_impacts: dict[str, str] = {
        "GATEWAY": "An attacker who controls your router can intercept or redirect all internet traffic on your network.",
        "OBSERVER": "Your camera feed or monitoring data may be exposed to anyone on the network or internet.",
        "EDGE_DEVICE": "Smart or IoT devices could be remotely controlled or used to spy on your network activity.",
        "COMPUTE": "A compromised computer could give an attacker access to files, passwords, and connected services.",
    }

    exploit_impact = (
        "One or more devices are running services commonly targeted by automated scanners and known exploits."
    )

    for dev in devices:
        role = dev.get("role", "UNKNOWN")
        msg = role_impacts.get(role)
        if msg and msg not in seen:
            seen.add(msg)
            impacts.append(msg)

    has_high_exploits = any(d.get("exploit_risk_level") == "HIGH" for d in devices)
    if has_high_exploits and exploit_impact not in seen:
        impacts.append(exploit_impact)

    if not impacts:
        impacts.append("No critical network-level risks identified for this scan.")

    return impacts


# ---------------------------------------------------------------------------
# Risk ranking
# ---------------------------------------------------------------------------


def rank_network_risks(devices: list[dict]) -> list[dict]:
    """Return the top 3 highest-priority devices with a reason string.

    Args:
        devices: List of enriched device dicts.

    Returns:
        Up to 3 dicts with keys: device (ip), priority (int), reason (str).
    """
    scored = sorted(devices, key=_priority_score, reverse=True)[:3]
    result = []
    for dev in scored:
        pi = dev.get("primary_issue")
        reason = pi["title"] if pi else "Multiple open ports detected"
        result.append(
            {
                "device": dev["ip"],
                "priority": _priority_score(dev),
                "reason": reason,
            }
        )
    return result


# ---------------------------------------------------------------------------
# Top actions
# ---------------------------------------------------------------------------

_ROLE_ACTION: dict[str, dict[str, str]] = {
    "GATEWAY": {
        "title": "Secure your router",
        "impact": "Protects every device on your network",
        "time": "10 min",
    },
    "OBSERVER": {
        "title": "Restrict camera access",
        "impact": "Prevents unauthorised viewing of your camera feed",
        "time": "5 min",
    },
    "EDGE_DEVICE": {
        "title": "Isolate IoT device on a separate network",
        "impact": "Limits blast radius if the device is compromised",
        "time": "15 min",
    },
    "COMPUTE": {
        "title": "Patch and harden the exposed computer",
        "impact": "Closes known exploit paths against this machine",
        "time": "20 min",
    },
    "UNKNOWN": {
        "title": "Identify and audit unknown device",
        "impact": "Removes blind spots from your network security posture",
        "time": "10 min",
    },
}

_ISSUE_ACTION_OVERRIDES: dict[str, dict[str, str]] = {
    "SMB exposed": {
        "title": "Disable SMB or restrict to trusted hosts",
        "impact": "Eliminates the most common ransomware propagation vector",
        "time": "5 min",
    },
    "RDP exposed": {
        "title": "Place RDP behind a VPN",
        "impact": "Stops brute-force attacks against Remote Desktop",
        "time": "10 min",
    },
    "Telnet management interface exposed": {
        "title": "Disable Telnet and enable SSH",
        "impact": "Removes plaintext credential exposure on your network device",
        "time": "5 min",
    },
    "Database port directly exposed": {
        "title": "Bind database to localhost only",
        "impact": "Prevents direct database access from the network",
        "time": "5 min",
    },
    "HTTP served without HTTPS redirect": {
        "title": "Enable HTTPS redirect",
        "impact": "Prevents credential interception over unencrypted HTTP",
        "time": "5 min",
    },
    "RTSP stream exposed": {
        "title": "Restrict RTSP stream access",
        "impact": "Prevents your camera feed being publicly accessible",
        "time": "5 min",
    },
}


def generate_top_actions(devices: list[dict]) -> list[dict]:
    """Return up to 3 prioritised remediation actions for the network.

    Selects actions based on the top-scored devices.  Issue-specific overrides
    take precedence over generic role-based actions.

    Args:
        devices: List of enriched device dicts.

    Returns:
        Up to 3 action dicts with keys: title, impact, time.
    """
    top = sorted(devices, key=_priority_score, reverse=True)[:3]
    actions: list[dict] = []
    seen_titles: set[str] = set()

    for dev in top:
        pi = dev.get("primary_issue")
        action: dict | None = None

        if pi:
            action = _ISSUE_ACTION_OVERRIDES.get(pi.get("title", ""))

        if action is None:
            action = _ROLE_ACTION.get(dev.get("role", "UNKNOWN"), _ROLE_ACTION["UNKNOWN"])

        if action["title"] not in seen_titles:
            seen_titles.add(action["title"])
            actions.append(dict(action))

    return actions
