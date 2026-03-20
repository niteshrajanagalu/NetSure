"""Attack Impact Simulation Engine.

Simulates realistic attack consequences grounded in detected ports,
services, and device roles.  All narratives are built from observed scan
data — no generic filler, no hallucinated exploits.

Public API
----------
simulate_attack_impact(devices: list[dict]) -> dict
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Priority scoring (mirrors network_engine to stay consistent)
# ---------------------------------------------------------------------------

_ROLE_SCORE: dict[str, int] = {
    "GATEWAY":     50,
    "COMPUTE":     30,
    "EDGE_DEVICE": 20,
    "OBSERVER":    15,
    "UNKNOWN":     10,
}
_EXPOSURE_SCORE: dict[str, int] = {"HIGH": 30, "MEDIUM": 15, "LOW": 0}
_EXPLOIT_SCORE: dict[str, int] = {"HIGH": 25, "MEDIUM": 10, "LOW": 0}
_ISSUE_SCORE: dict[str, int] = {"HIGH": 40, "MEDIUM": 20, "LOW": 5}


def _score(device: dict) -> int:
    s = _ROLE_SCORE.get(device.get("role", "UNKNOWN"), 10)
    s += _EXPOSURE_SCORE.get(device.get("exposure", "LOW"), 0)
    s += _EXPLOIT_SCORE.get(device.get("exploit_risk_level", "LOW"), 0)
    pi = device.get("primary_issue")
    if pi:
        s += _ISSUE_SCORE.get(pi.get("severity", "LOW"), 5)
    return s


# ---------------------------------------------------------------------------
# Entry point selection
# ---------------------------------------------------------------------------

def _pick_entry_point(devices: list[dict]) -> dict:
    """Select the most likely attacker entry point.

    Preference order:
      1. Highest-scoring GATEWAY
      2. Highest-scoring EDGE_DEVICE or OBSERVER (IoT pivot)
      3. Any device with HIGH exploit_risk_level
      4. Highest-scoring device overall
    """
    by_score = sorted(devices, key=_score, reverse=True)

    for d in by_score:
        if d.get("role") == "GATEWAY":
            return d

    for d in by_score:
        if d.get("role") in ("EDGE_DEVICE", "OBSERVER"):
            return d

    for d in by_score:
        if d.get("exploit_risk_level") == "HIGH":
            return d

    return by_score[0]


# ---------------------------------------------------------------------------
# Port / service → human label helpers
# ---------------------------------------------------------------------------

_PORT_LABELS: dict[int, str] = {
    21:    "FTP (port 21)",
    22:    "SSH (port 22)",
    23:    "Telnet (port 23)",
    25:    "SMTP (port 25)",
    80:    "HTTP (port 80)",
    110:   "POP3 (port 110)",
    143:   "IMAP (port 143)",
    443:   "HTTPS (port 443)",
    445:   "SMB (port 445)",
    554:   "RTSP (port 554)",
    1433:  "MSSQL (port 1433)",
    3306:  "MySQL (port 3306)",
    3389:  "RDP (port 3389)",
    5432:  "PostgreSQL (port 5432)",
    8008:  "Chromecast control (port 8008)",
    8009:  "device channel (port 8009)",
    8010:  "device stream (port 8010)",
    8080:  "HTTP alternate (port 8080)",
    8443:  "HTTPS alternate (port 8443)",
    9000:  "management (port 9000)",
    9100:  "raw print (port 9100)",
    27017: "MongoDB (port 27017)",
}


def _port_label(port: int, services: list[int] | None = None) -> str:
    return _PORT_LABELS.get(port, f"port {port}")


def _primary_port_label(device: dict) -> str:
    ports = device.get("ports", [])
    if not ports:
        return "an open port"
    return _port_label(ports[0])


# ---------------------------------------------------------------------------
# Step generators — each returns one narrative sentence grounded in real data
# ---------------------------------------------------------------------------

def _step_initial_access(entry: dict) -> str:
    role = entry.get("role", "UNKNOWN")
    ip = entry["ip"]
    ports = entry.get("ports", [])
    device_type = entry.get("device_type", "device")
    pi = entry.get("primary_issue")
    issue_title = pi.get("title", "") if pi else ""

    port_str = _port_label(ports[0]) if ports else "an exposed port"

    templates: dict[str, str] = {
        "GATEWAY": (
            f"An attacker on the local network connects to the router at {ip} "
            f"via {port_str}, which is reachable without a VPN or firewall restriction."
        ),
        "EDGE_DEVICE": (
            f"An attacker targets the {device_type} at {ip}, connecting to {port_str} "
            f"which accepts unauthenticated connections."
        ),
        "OBSERVER": (
            f"An attacker discovers the camera or monitoring device at {ip} "
            f"with {port_str} exposed, accessible from the local network."
        ),
        "COMPUTE": (
            f"An attacker connects to the computer at {ip} "
            f"via {port_str}, which is directly reachable on the network."
        ),
        "UNKNOWN": (
            f"An attacker finds an unidentified device at {ip} "
            f"with {port_str} open and attempts a connection."
        ),
    }
    return templates.get(role, templates["UNKNOWN"])


def _step_exploit(entry: dict) -> str:
    ip = entry["ip"]
    ports = entry.get("ports", [])
    pi = entry.get("primary_issue")
    issue_title = pi.get("title", "") if pi else ""
    erl = entry.get("exploit_risk_level", "LOW")

    issue_steps: dict[str, str] = {
        "HTTP without HTTPS": (
            f"Because the management interface at {ip} serves HTTP without forcing HTTPS, "
            f"the attacker intercepts the admin login in plaintext using a passive network tap."
        ),
        "HTTP served without HTTPS redirect": (
            f"The service at {ip} responds on HTTP without redirecting to HTTPS. "
            f"The attacker intercepts credentials submitted through the unencrypted interface."
        ),
        "Telnet management interface exposed": (
            f"The attacker connects to Telnet on {ip} and captures the admin username and "
            f"password in cleartext — Telnet sends all keystrokes without encryption."
        ),
        "Telnet enabled": (
            f"Telnet on {ip} transmits credentials in plaintext. "
            f"The attacker passively sniffs the session and recovers the login."
        ),
        "SMB exposed": (
            f"The attacker sends a crafted SMB packet to {ip} targeting the EternalBlue "
            f"(MS17-010) vulnerability, gaining remote code execution without valid credentials."
        ),
        "RDP exposed": (
            f"The attacker runs a credential brute-force against RDP on {ip}, "
            f"using a list of common passwords. After several attempts, access is granted."
        ),
        "Database port directly exposed": (
            f"The database on {ip} accepts connections from the network without requiring "
            f"VPN access. The attacker connects directly and begins enumerating tables."
        ),
        "RTSP stream exposed": (
            f"The RTSP stream at {ip} requires no authentication. "
            f"The attacker opens the stream URL and gains a live view of the camera feed."
        ),
        "Media control port exposed": (
            f"The attacker sends control commands to the media device at {ip} on port 8008, "
            f"which accepts them without authentication, gaining control of the device."
        ),
        "Server version disclosed in HTTP header": (
            f"The HTTP response from {ip} reveals the exact server version. "
            f"The attacker looks up known CVEs for that version and selects a matching exploit."
        ),
        "SNMP exposed": (
            f"The attacker queries SNMP on {ip} using the default community string 'public', "
            f"extracting the full network interface configuration and routing table."
        ),
        "FTP service detected": (
            f"The attacker connects to FTP on {ip} and attempts anonymous login, "
            f"which succeeds, granting read access to the exposed directory."
        ),
    }

    if issue_title in issue_steps:
        return issue_steps[issue_title]

    # Fallback grounded in exploit risk and ports
    if erl == "HIGH" and ports:
        port_str = _port_label(ports[0])
        return (
            f"The attacker exploits a known vulnerability against {port_str} on {ip}, "
            f"a service class with documented public exploits, and gains initial access."
        )

    return (
        f"The attacker probes open ports on {ip} and identifies a misconfiguration "
        f"that allows unauthorised access to the service."
    )


def _step_pivot(entry: dict, targets: list[dict]) -> str | None:
    """Describe lateral movement from entry point to other devices."""
    if not targets:
        return None
    ip = entry["ip"]
    role = entry.get("role", "UNKNOWN")

    if role == "GATEWAY":
        other_ips = [d["ip"] for d in targets if d["ip"] != ip]
        if not other_ips:
            return None
        device_list = ", ".join(other_ips)
        return (
            f"With the router under their control, the attacker has full visibility into "
            f"all traffic on the network. Every device — including {device_list} — now "
            f"communicates through the compromised router, exposing credentials, session "
            f"tokens, and unencrypted data from all of them simultaneously."
        )

    # Non-gateway pivot
    gateway = next((d for d in targets if d.get("role") == "GATEWAY"), None)
    if gateway:
        return (
            f"Using {ip} as a foothold, the attacker scans the local network and discovers "
            f"the router at {gateway['ip']}. They probe its management interface to attempt "
            f"privilege escalation to the network gateway."
        )

    if len(targets) > 1:
        peer = next((d for d in targets if d["ip"] != ip), None)
        if peer:
            return (
                f"From {ip}, the attacker scans the subnet and finds {peer['ip']} "
                f"({peer.get('device_type','another device')}) with open ports. "
                f"They attempt lateral movement using the same credentials or exploit."
            )

    return None


def _step_persistence(entry: dict) -> str:
    role = entry.get("role", "UNKNOWN")
    ip = entry["ip"]

    templates = {
        "GATEWAY": (
            f"The attacker installs a persistent DNS override on the router at {ip}, "
            f"silently redirecting banking and email domains to attacker-controlled servers "
            f"for all devices on the network — without any device being directly compromised."
        ),
        "COMPUTE": (
            f"The attacker drops a lightweight backdoor on {ip} that survives reboots, "
            f"giving persistent remote access to the machine and any files or credentials on it."
        ),
        "EDGE_DEVICE": (
            f"The attacker reprograms the firmware on {ip} to include a persistent "
            f"listener, ensuring continued access even after a device restart."
        ),
        "OBSERVER": (
            f"The attacker configures the device at {ip} to silently forward the video "
            f"stream to an external server, providing ongoing surveillance without "
            f"any visible indication on the local network."
        ),
        "UNKNOWN": (
            f"The attacker maintains access to {ip} by creating a scheduled task or "
            f"cron job that re-establishes the connection on a regular interval."
        ),
    }
    return templates.get(role, templates["UNKNOWN"])


# ---------------------------------------------------------------------------
# Compromised devices
# ---------------------------------------------------------------------------

def _compromised_devices(entry: dict, all_devices: list[dict]) -> list[str]:
    """Return IPs of devices considered compromised in this scenario."""
    if entry.get("role") == "GATEWAY":
        # All devices route through the gateway — all are affected
        return [d["ip"] for d in all_devices]

    compromised = [entry["ip"]]

    # Add any devices that are lower-scored (reachable via pivot)
    entry_score = _score(entry)
    for d in all_devices:
        if d["ip"] == entry["ip"]:
            continue
        # Devices with lower priority are more likely to fall to a pivot
        if _score(d) <= entry_score and d.get("role") != "GATEWAY":
            compromised.append(d["ip"])

    return compromised


# ---------------------------------------------------------------------------
# Data at risk
# ---------------------------------------------------------------------------

_ROLE_DATA: dict[str, list[str]] = {
    "GATEWAY":     ["All network traffic", "Admin credentials", "DNS queries", "VPN keys"],
    "COMPUTE":     ["Local files and documents", "Saved passwords", "Browser sessions", "Email"],
    "EDGE_DEVICE": ["Device control access", "Usage patterns", "Local network topology"],
    "OBSERVER":    ["Live camera feed", "Recorded footage", "Motion detection events"],
    "UNKNOWN":     ["Unknown data — device purpose not identified"],
}

_PORT_DATA: dict[int, str] = {
    3306:  "Database records and user data",
    5432:  "Database records and user data",
    1433:  "Database records and user data",
    27017: "Database records and user data",
    21:    "Files accessible via FTP",
    22:    "SSH keys and shell access",
    25:    "Email messages in transit",
    445:   "Network file shares and credentials",
    3389:  "Full desktop session and all local data",
}


def _data_at_risk(compromised_ips: list[str], all_devices: list[dict]) -> list[str]:
    seen: set[str] = set()
    data: list[str] = []

    for ip in compromised_ips:
        dev = next((d for d in all_devices if d["ip"] == ip), None)
        if not dev:
            continue

        for item in _ROLE_DATA.get(dev.get("role", "UNKNOWN"), []):
            if item not in seen:
                seen.add(item)
                data.append(item)

        for port in dev.get("ports", []):
            item = _PORT_DATA.get(port)
            if item and item not in seen:
                seen.add(item)
                data.append(item)

    return data


# ---------------------------------------------------------------------------
# Impact level
# ---------------------------------------------------------------------------

def _impact_level(entry: dict, compromised: list[str], all_devices: list[dict]) -> str:
    if entry.get("role") == "GATEWAY":
        return "HIGH"
    if len(compromised) >= max(2, len(all_devices) // 2):
        return "HIGH"
    if entry.get("exploit_risk_level") == "HIGH" or entry.get("exposure") == "HIGH":
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# User message
# ---------------------------------------------------------------------------

_USER_MSG: dict[str, str] = {
    "GATEWAY": (
        "An attacker who controls your router can see and intercept everything on your network — "
        "passwords, emails, banking sessions — without touching any individual device."
    ),
    "COMPUTE": (
        "An attacker could take over this computer, access your files, and use it to "
        "attack other devices on your network."
    ),
    "EDGE_DEVICE": (
        "An attacker could take control of this smart device and use it as a stepping stone "
        "to reach other devices and systems on your home or office network."
    ),
    "OBSERVER": (
        "An attacker could view your camera feed in real time and potentially use the "
        "camera to access other devices on your network."
    ),
    "UNKNOWN": (
        "An attacker could use this unidentified device to gain a foothold on your network "
        "and probe for more valuable targets."
    ),
}

_IMPACT_SUFFIX: dict[str, str] = {
    "HIGH":   " This scenario represents a critical risk to your entire network.",
    "MEDIUM": " This scenario represents a significant risk that should be addressed promptly.",
    "LOW":    " This scenario is limited in scope but still represents a real security gap.",
}


def _user_message(entry: dict, impact: str) -> str:
    base = _USER_MSG.get(entry.get("role", "UNKNOWN"), _USER_MSG["UNKNOWN"])
    return base + _IMPACT_SUFFIX.get(impact, "")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def simulate_attack_impact(devices: list[dict]) -> dict:
    """Simulate a realistic attack scenario grounded in scanned device data.

    Args:
        devices: List of enriched device dicts containing ip, role, ports,
                 services, exposure, exploit_risk_level, primary_issue,
                 device_type.

    Returns:
        Dict with entry_point, attack_story, compromised_devices,
        data_at_risk, impact_level, user_message.
        Returns a safe empty result when no devices are provided.
    """
    if not devices:
        return {
            "entry_point": None,
            "attack_story": "No devices were found in this scan — no attack scenario can be simulated.",
            "compromised_devices": [],
            "data_at_risk": [],
            "impact_level": "LOW",
            "user_message": "No devices were detected on this network segment.",
        }

    entry = _pick_entry_point(devices)
    other_devices = [d for d in devices if d["ip"] != entry["ip"]]

    # Build narrative steps — only include pivot and persistence if meaningful
    steps: list[str] = [
        _step_initial_access(entry),
        _step_exploit(entry),
    ]

    pivot = _step_pivot(entry, devices)
    if pivot:
        steps.append(pivot)

    steps.append(_step_persistence(entry))

    story = "\n\n".join(f"Step {i + 1}: {s}" for i, s in enumerate(steps))

    compromised = _compromised_devices(entry, devices)
    data = _data_at_risk(compromised, devices)
    level = _impact_level(entry, compromised, devices)
    msg = _user_message(entry, level)

    return {
        "entry_point": entry["ip"],
        "attack_story": story,
        "compromised_devices": compromised,
        "data_at_risk": data,
        "impact_level": level,
        "user_message": msg,
    }
