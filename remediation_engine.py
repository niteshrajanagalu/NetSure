"""Remediation Intelligence Layer.

Transforms per-device intelligence into a prioritised, human-readable
remediation plan that answers: "What should the user fix FIRST?"

All logic is deterministic and rule-based — no ML, no external calls.

Public API
----------
generate_remediation_plan(devices: list[dict]) -> dict
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Brand-specific admin panel URLs and navigation paths
# ---------------------------------------------------------------------------

# Each entry: list of step strings.  {ip} is substituted at runtime.
_BRAND_STEPS: dict[str, dict[str, list[str]]] = {
    "TP-Link": {
        "HTTP without HTTPS": [
            "Open http://{ip} in your browser",
            "Log in with your admin credentials",
            "Go to Advanced → System Tools → Administration",
            "Under 'Management', disable HTTP and enable HTTPS only",
            "Under 'Remote Management', ensure it is disabled",
            "Save and reboot the router",
        ],
        "Telnet management interface exposed": [
            "Open http://{ip} in your browser",
            "Log in with your admin credentials",
            "Go to Advanced → System Tools → Administration",
            "Disable Telnet access",
            "Enable SSH if CLI access is needed",
            "Save and reboot the router",
        ],
        "SNMP exposed": [
            "Open http://{ip} in your browser",
            "Log in with your admin credentials",
            "Go to Advanced → Network → SNMP",
            "Disable SNMPv1 and SNMPv2c",
            "If SNMP is required, configure SNMPv3 with a strong community string",
            "Save and apply",
        ],
        "_default": [
            "Open http://{ip} in your browser",
            "Log in with your admin credentials (default: admin / admin)",
            "Go to Advanced → System Tools",
            "Disable any management interfaces not in active use",
            "Update firmware under Advanced → System Tools → Firmware Upgrade",
            "Save and reboot the router",
        ],
    },
    "Netgear": {
        "HTTP without HTTPS": [
            "Open http://{ip} in your browser (or routerlogin.net)",
            "Log in with your admin credentials",
            "Go to Advanced → Administration → Remote Management",
            "Disable remote management and ensure HTTPS is selected",
            "Go to Advanced → Administration → NTP Settings to check for admin lockdown options",
            "Save and apply",
        ],
        "Telnet management interface exposed": [
            "Open http://{ip} in your browser (or routerlogin.net)",
            "Log in with your admin credentials",
            "Go to Advanced → Administration → Remote Management",
            "Disable Telnet access completely",
            "Apply and reboot",
        ],
        "_default": [
            "Open http://{ip} in your browser (or routerlogin.net)",
            "Log in with your admin credentials (default: admin / password)",
            "Go to Advanced → Administration",
            "Disable unused management interfaces",
            "Update firmware under Advanced → Administration → Firmware Update",
            "Apply and reboot",
        ],
    },
    "D-Link": {
        "HTTP without HTTPS": [
            "Open http://{ip} in your browser",
            "Log in with your admin credentials",
            "Go to Tools → Admin",
            "Enable HTTPS management and disable HTTP",
            "Disable remote management if not required",
            "Save settings",
        ],
        "Telnet management interface exposed": [
            "Open http://{ip} in your browser",
            "Log in with your admin credentials",
            "Go to Tools → Admin → Management",
            "Disable Telnet",
            "Save settings and reboot",
        ],
        "_default": [
            "Open http://{ip} in your browser",
            "Log in with your admin credentials (default: admin / blank password)",
            "Go to Tools → Admin",
            "Disable unused remote access options",
            "Update firmware under Tools → Firmware",
            "Save and reboot",
        ],
    },
    "MikroTik": {
        "HTTP without HTTPS": [
            "Open Winbox or http://{ip} in your browser",
            "Log in with your admin credentials",
            "Go to IP → Services",
            "Disable the 'www' (HTTP) service or restrict its allowed addresses",
            "Ensure 'www-ssl' (HTTPS) is enabled with a valid certificate",
            "Apply changes",
        ],
        "Telnet management interface exposed": [
            "Open Winbox or ssh admin@{ip}",
            "Run: /ip service disable telnet",
            "Ensure SSH is enabled: /ip service enable ssh",
            "Restrict SSH to trusted IP ranges: /ip service set ssh address=192.168.0.0/24",
            "Apply and verify with: /ip service print",
        ],
        "SNMP exposed": [
            "Open Winbox or ssh admin@{ip}",
            "Go to IP → SNMP",
            "Disable SNMPv1/v2 communities or restrict to a specific allowed address",
            "If SNMP is needed, configure SNMPv3 with authentication and privacy",
            "Apply changes",
        ],
        "_default": [
            "Open Winbox and connect to {ip}, or ssh admin@{ip}",
            "Go to IP → Services and disable unused services (telnet, ftp, api if not needed)",
            "Go to IP → Firewall → Filter Rules and restrict management access to trusted IPs",
            "Update RouterOS: System → Packages → Check for Updates",
            "Change default admin password: System → Users",
            "Apply and verify",
        ],
    },
    "Asus": {
        "HTTP without HTTPS": [
            "Open http://{ip} in your browser (or router.asus.com)",
            "Log in with your admin credentials",
            "Go to Administration → System",
            "Enable HTTPS for LAN connection and disable HTTP",
            "Disable WAN access to admin UI under Administration → System → WAN Access",
            "Apply changes and reboot",
        ],
        "Telnet management interface exposed": [
            "Open http://{ip} in your browser (or router.asus.com)",
            "Log in with your admin credentials",
            "Go to Administration → System",
            "Disable Telnet",
            "Enable SSH only if CLI access is required",
            "Apply and reboot",
        ],
        "_default": [
            "Open http://{ip} in your browser (or router.asus.com)",
            "Log in with your admin credentials (default: admin / admin)",
            "Go to Administration → System",
            "Disable any management services not in use",
            "Update firmware under Administration → Firmware Upgrade",
            "Apply and reboot",
        ],
    },
    "Linksys": {
        "_default": [
            "Open http://{ip} in your browser",
            "Log in with your admin credentials (default: blank user / admin)",
            "Go to Administration → Management",
            "Disable remote management and unused services",
            "Update firmware under Administration → Firmware Upgrade",
            "Save and reboot",
        ],
    },
    "Huawei": {
        "HTTP without HTTPS": [
            "Open http://{ip} in your browser",
            "Log in with your admin credentials",
            "Go to Basic → LAN Setup or Security → Firewall",
            "Enable HTTPS for the management interface",
            "Disable HTTP-only access",
            "Save and apply",
        ],
        "_default": [
            "Open http://{ip} in your browser",
            "Log in with your admin credentials (default: admin / admin)",
            "Go to Security settings and restrict management access",
            "Disable unused remote access services",
            "Update firmware under System → Software Upgrade",
            "Save and reboot",
        ],
    },
    "Xiaomi": {
        "_default": [
            "Open http://{ip} in your browser (or miwifi.com)",
            "Log in with your admin credentials",
            "Go to Settings (gear icon) → Advanced",
            "Disable SSH if not actively used",
            "Update firmware under Settings → Upgrade",
            "Save and apply",
        ],
    },
    "Ubiquiti": {
        "_default": [
            "Open https://{ip} in your browser (UniFi Controller or EdgeOS GUI)",
            "Log in with your admin credentials",
            "Go to Settings → System",
            "Disable unused management interfaces",
            "Apply firmware updates from the dashboard",
            "Review firewall policies under Firewall / Security",
        ],
    },
    "AVM": {
        "_default": [
            "Open http://fritz.box or http://{ip} in your browser",
            "Log in with your FRITZ!Box password",
            "Go to System → FRITZ!Box Users → Login to Home Network",
            "Ensure HTTPS is required for the user interface",
            "Disable MyFRITZ! remote access if not needed under Internet → MyFRITZ! Account",
            "Check for firmware updates under System → Update",
        ],
    },
    "Zyxel": {
        "_default": [
            "Open http://{ip} in your browser",
            "Log in with your admin credentials (default: admin / 1234)",
            "Go to Maintenance → Remote Management",
            "Disable unused management services",
            "Update firmware under Maintenance → Firmware Upgrade",
            "Apply and reboot",
        ],
    },
}

# ---------------------------------------------------------------------------
# Scoring weights
# ---------------------------------------------------------------------------

_ROLE_WEIGHT: dict[str, int] = {
    "GATEWAY":    50,
    "COMPUTE":    30,
    "EDGE_DEVICE": 20,
    "OBSERVER":   15,
    "UNKNOWN":    10,
}

_EXPOSURE_WEIGHT: dict[str, int] = {
    "HIGH":   30,
    "MEDIUM": 15,
    "LOW":     0,
}

_EXPLOIT_WEIGHT: dict[str, int] = {
    "HIGH":   25,
    "MEDIUM": 10,
    "LOW":     0,
}

_ISSUE_WEIGHT: dict[str, int] = {
    "HIGH":   40,
    "MEDIUM": 20,
    "LOW":     5,
}


def _device_score(device: dict) -> int:
    """Compute a remediation priority score for a single device."""
    score = _ROLE_WEIGHT.get(device.get("role", "UNKNOWN"), 10)
    score += _EXPOSURE_WEIGHT.get(device.get("exposure", "LOW"), 0)
    score += _EXPLOIT_WEIGHT.get(device.get("exploit_risk_level", "LOW"), 0)
    pi = device.get("primary_issue")
    if pi:
        score += _ISSUE_WEIGHT.get(pi.get("severity", "LOW"), 5)
    return score


# ---------------------------------------------------------------------------
# Critical action templates
# Keyed by (role, primary_issue_title).  Role-only fallbacks follow.
# ---------------------------------------------------------------------------

_ISSUE_ACTIONS: dict[tuple[str, str], dict] = {
    ("GATEWAY", "HTTP without HTTPS"): {
        "title": "Force HTTPS on your router's management interface",
        "steps": [
            "Log in to your router admin panel",
            "Disable HTTP access and enable HTTPS-only",
            "If available, set HTTP to redirect (301) to HTTPS",
            "Restrict management interface to LAN-only or a dedicated admin VLAN",
        ],
        "effort": "LOW",
        "risk_reduction": 65,
        "reasoning": (
            "Your router is the single point that controls all traffic on your network. "
            "Its management interface is currently reachable over unencrypted HTTP, meaning "
            "any device on the same network can intercept your admin credentials in transit. "
            "Securing this one interface significantly reduces your overall network attack surface."
        ),
    },
    ("GATEWAY", "Telnet management interface exposed"): {
        "title": "Disable Telnet on your router immediately",
        "steps": [
            "Log in to your router admin panel",
            "Navigate to remote management or administration settings",
            "Disable Telnet completely",
            "Enable SSH if remote CLI access is required",
        ],
        "effort": "LOW",
        "risk_reduction": 75,
        "reasoning": (
            "Your router's Telnet management port is open. Telnet sends all commands "
            "and passwords in plain text across the network. Anyone on your LAN or with "
            "network access can capture your router admin credentials with trivial tooling. "
            "Disabling Telnet eliminates this critical credential theft vector."
        ),
    },
    ("GATEWAY", "SNMP exposed"): {
        "title": "Restrict or disable SNMP on your router",
        "steps": [
            "Log in to your router admin panel",
            "Disable SNMPv1 and SNMPv2c",
            "If SNMP is required, upgrade to SNMPv3 with AuthPriv mode",
            "Restrict SNMP access to a dedicated management host",
        ],
        "effort": "LOW",
        "risk_reduction": 55,
        "reasoning": (
            "Your router is exposing SNMP, which uses weak community-string authentication. "
            "An attacker can query SNMP to extract your full network topology, routing tables, "
            "and device configuration without any valid credentials."
        ),
    },
    ("COMPUTE", "SMB exposed"): {
        "title": "Block SMB from being reachable on the network",
        "steps": [
            "Open Windows Firewall or your host firewall",
            "Block inbound connections on ports 445 and 139",
            "Disable SMBv1 via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
            "If file sharing is needed, restrict to specific trusted IPs only",
        ],
        "effort": "LOW",
        "risk_reduction": 70,
        "reasoning": (
            "SMB exposure is the primary propagation vector for ransomware attacks including "
            "WannaCry and NotPetya, which exploited EternalBlue (MS17-010). Any unpatched "
            "Windows machine with port 445 reachable on the LAN is a single exploit away from "
            "full compromise. Blocking this port eliminates the largest known Windows attack surface."
        ),
    },
    ("COMPUTE", "RDP exposed"): {
        "title": "Place Remote Desktop behind a VPN",
        "steps": [
            "Disable direct internet-facing RDP (block port 3389 at the perimeter)",
            "Set up a VPN (WireGuard or OpenVPN) for remote access",
            "Enable Network Level Authentication (NLA) on RDP",
            "Enable account lockout after 5 failed attempts",
        ],
        "effort": "MEDIUM",
        "risk_reduction": 70,
        "reasoning": (
            "Remote Desktop on port 3389 is scanned by automated bots within minutes of "
            "being exposed. BlueKeep (CVE-2019-0708) and DejaBlue are wormable RCE exploits "
            "against RDP. Even without those, credential brute-force against RDP is trivial "
            "and extremely common. Moving RDP behind a VPN removes it from the attack surface entirely."
        ),
    },
    ("COMPUTE", "Database port directly exposed"): {
        "title": "Bind your database to localhost only",
        "steps": [
            "Edit your database config (my.cnf / postgresql.conf / mongod.conf)",
            "Set bind-address to 127.0.0.1",
            "Restart the database service",
            "Access the database remotely only through an SSH tunnel or VPN",
        ],
        "effort": "LOW",
        "risk_reduction": 80,
        "reasoning": (
            "A database port reachable from the network is a critical misconfiguration. "
            "Databases are not designed to handle internet-facing traffic directly — they "
            "trust authenticated connections implicitly. Binding to localhost means even a "
            "compromised frontend server cannot pivot directly to your database."
        ),
    },
    ("COMPUTE", "Development server exposed on network"): {
        "title": "Stop your development server from being reachable on the network",
        "steps": [
            "Stop the running development server",
            "Restart it binding to localhost only (e.g. 'python -m http.server --bind 127.0.0.1')",
            "Verify with 'curl http://127.0.0.1:<port>' — it should succeed",
            "Verify with 'curl http://<your-ip>:<port>' — it should be refused",
        ],
        "effort": "LOW",
        "risk_reduction": 90,
        "reasoning": (
            "Development servers are designed for local use and have no authentication, "
            "rate limiting, or access controls. Binding to 127.0.0.1 makes the server "
            "reachable only from the same machine — it disappears completely from the "
            "network and cannot be reached by any other device."
        ),
    },
    ("EDGE_DEVICE", "Media control port exposed"): {
        "title": "Move IoT and media devices to an isolated network segment",
        "steps": [
            "Create a separate guest WiFi or IoT VLAN on your router",
            "Connect all smart/IoT devices exclusively to that segment",
            "Block traffic between the IoT segment and your main network",
            "Allow only necessary outbound internet access from the IoT segment",
        ],
        "effort": "MEDIUM",
        "risk_reduction": 55,
        "reasoning": (
            "IoT and media devices like streaming hardware are frequently targeted because "
            "they run minimal security controls and rarely receive firmware updates. Isolating "
            "them on a separate network segment means that even if one is compromised, the "
            "attacker cannot pivot to your computers or router from it."
        ),
    },
    ("OBSERVER", "RTSP stream exposed"): {
        "title": "Restrict your camera stream to authorised viewers only",
        "steps": [
            "Enable authentication on the camera's RTSP stream",
            "Place the camera on a dedicated VLAN with no internet-facing access",
            "Add a firewall rule to block external access to port 554",
            "Change the default camera credentials if not already done",
        ],
        "effort": "LOW",
        "risk_reduction": 60,
        "reasoning": (
            "Unauthenticated RTSP streams are actively indexed by search engines like Shodan. "
            "Your camera feed may already be publicly visible. Restricting RTSP access takes "
            "minutes and immediately removes it from public internet exposure."
        ),
    },
}

# Role-only fallbacks when no issue-specific action matches
_ROLE_FALLBACKS: dict[str, dict] = {
    "GATEWAY": {
        "title": "Audit and harden your router configuration",
        "steps": [
            "Update router firmware to the latest version",
            "Change default admin credentials",
            "Disable any management interfaces not in active use",
            "Review firewall rules and remove unused port forwards",
        ],
        "effort": "MEDIUM",
        "risk_reduction": 60,
        "reasoning": (
            "Your router is the gateway for all network traffic. Hardening it protects "
            "every device behind it simultaneously. A single configuration change here "
            "can have more impact than fixing ten individual device issues."
        ),
    },
    "COMPUTE": {
        "title": "Patch and reduce the attack surface on this machine",
        "steps": [
            "Apply all pending OS and application security patches",
            "Disable or firewall any services not actively needed",
            "Enable host-based firewall rules",
            "Review running services and close unnecessary ports",
        ],
        "effort": "MEDIUM",
        "risk_reduction": 50,
        "reasoning": (
            "This computer has open ports that are commonly targeted by automated scanners. "
            "Patching and reducing exposed services removes known exploit paths without "
            "any impact on day-to-day functionality."
        ),
    },
    "EDGE_DEVICE": {
        "title": "Isolate this device from your main network",
        "steps": [
            "Move the device to a guest or IoT network segment",
            "Block traffic between this segment and your main LAN",
            "Update the device firmware if an update is available",
            "Disable any features or services not in active use",
        ],
        "effort": "MEDIUM",
        "risk_reduction": 45,
        "reasoning": (
            "IoT and edge devices have limited security controls and often go unpatched "
            "for extended periods. Isolating this device limits the blast radius of any "
            "compromise to the IoT segment only."
        ),
    },
    "OBSERVER": {
        "title": "Secure this monitoring or camera device",
        "steps": [
            "Change default credentials immediately",
            "Update firmware to the latest version",
            "Place on a dedicated camera VLAN with no internet access",
            "Disable any remote access features not actively used",
        ],
        "effort": "LOW",
        "risk_reduction": 50,
        "reasoning": (
            "Camera and monitoring devices are high-value targets because they can expose "
            "sensitive footage and are often deployed with default credentials. Securing "
            "this device prevents both surveillance compromise and use as a network pivot point."
        ),
    },
    "UNKNOWN": {
        "title": "Identify this device and audit its services",
        "steps": [
            "Determine what this device is and whether it should be on the network",
            "If unrecognised, consider isolating it pending investigation",
            "Review what services it is running and whether they are necessary",
            "Apply firmware or software updates if applicable",
        ],
        "effort": "LOW",
        "risk_reduction": 30,
        "reasoning": (
            "An unidentified device with open ports represents an unknown risk. Identifying "
            "it and auditing its services removes a blind spot from your network security posture."
        ),
    },
}


def _brand_steps(device: dict, issue_title: str) -> list[str] | None:
    """Return brand-specific steps for *device* and *issue_title*, or None.

    Substitutes {ip} with the device's actual IP address.
    Falls back to the brand's _default entry if no issue-specific entry exists.
    Returns None when no brand is detected or no entry matches.
    """
    brand = device.get("router_brand")
    if not brand:
        return None
    brand_map = _BRAND_STEPS.get(brand)
    if not brand_map:
        return None
    ip = device.get("ip", "your router")
    steps = brand_map.get(issue_title) or brand_map.get("_default")
    if not steps:
        return None
    return [s.replace("{ip}", ip) for s in steps]


def _select_critical_action(device: dict) -> dict:
    """Select the most impactful action template for the highest-priority device."""
    role = device.get("role", "UNKNOWN")
    pi = device.get("primary_issue")
    issue_title = pi.get("title", "") if pi else ""

    action = _ISSUE_ACTIONS.get((role, issue_title))
    if action is None:
        action = _ROLE_FALLBACKS.get(role, _ROLE_FALLBACKS["UNKNOWN"])

    # Override generic steps with brand-specific ones when available
    steps = _brand_steps(device, issue_title) or action["steps"]

    return {
        "title": action["title"],
        "device": device["ip"],
        "device_type": device.get("device_type", "Unknown Device"),
        "role": role,
        "router_brand": device.get("router_brand"),
        "router_model": device.get("router_model"),
        "steps": steps,
        "effort": action["effort"],
    }


# ---------------------------------------------------------------------------
# Risk reduction estimation
# ---------------------------------------------------------------------------

def _estimate_risk_reduction(top_device: dict, all_devices: list[dict]) -> int:
    """Estimate how much overall risk drops if the top device is remediated.

    Logic:
      - GATEWAY: fixing gateway cuts network-wide risk sharply (60–80%)
      - High-score non-gateway device secured: moderate reduction
      - Adjustment for number of remaining HIGH-risk devices
    """
    role = top_device.get("role", "UNKNOWN")
    top_score = _device_score(top_device)
    total_score = sum(_device_score(d) for d in all_devices) or 1

    base_reduction = round((top_score / total_score) * 100)

    # Gateway bonus: securing the gateway also passively protects everything behind it
    if role == "GATEWAY":
        base_reduction = min(100, round(base_reduction * 1.4))

    return max(10, min(90, base_reduction))


# ---------------------------------------------------------------------------
# Action plan (top 3)
# ---------------------------------------------------------------------------

_EFFORT_MAP: dict[str, str] = {
    "GATEWAY":     "LOW",
    "COMPUTE":     "MEDIUM",
    "EDGE_DEVICE": "MEDIUM",
    "OBSERVER":    "LOW",
    "UNKNOWN":     "LOW",
}

_IMPACT_TEMPLATES: dict[str, str] = {
    "GATEWAY":     "Protects all devices on the network simultaneously",
    "COMPUTE":     "Removes known exploit paths from this machine",
    "EDGE_DEVICE": "Limits blast radius if device is compromised",
    "OBSERVER":    "Prevents camera feed exposure and credential theft",
    "UNKNOWN":     "Eliminates a blind spot in your network security",
}


def _build_action_plan(devices: list[dict]) -> list[dict]:
    """Return the top 3 remediation actions across all devices."""
    sorted_devices = sorted(devices, key=_device_score, reverse=True)[:3]
    plan = []
    seen: set[str] = set()

    for dev in sorted_devices:
        role = dev.get("role", "UNKNOWN")
        pi = dev.get("primary_issue")
        issue_title = pi.get("title", "") if pi else ""

        action = _ISSUE_ACTIONS.get((role, issue_title)) or _ROLE_FALLBACKS.get(role, _ROLE_FALLBACKS["UNKNOWN"])
        title = action["title"]

        if title in seen:
            continue
        seen.add(title)

        steps = _brand_steps(dev, issue_title) or action["steps"]
        plan.append({
            "title": title,
            "device": dev["ip"],
            "device_type": dev.get("device_type", "Unknown Device"),
            "router_brand": dev.get("router_brand"),
            "router_model": dev.get("router_model"),
            "impact": _IMPACT_TEMPLATES.get(role, "Reduces overall network risk"),
            "effort": action["effort"],
            "steps": steps,
        })

    return plan


# ---------------------------------------------------------------------------
# Reasoning narrative
# ---------------------------------------------------------------------------

def _build_reasoning(top_device: dict, risk_reduction: int, all_devices: list[dict]) -> str:
    """Produce a plain-English explanation for why this action is the priority."""
    role = top_device.get("role", "UNKNOWN")
    ip = top_device["ip"]
    device_type = top_device.get("device_type", "Unknown Device")
    pi = top_device.get("primary_issue")
    issue_title = pi.get("title", "") if pi else "open ports"

    action = _ISSUE_ACTIONS.get((role, issue_title)) or _ROLE_FALLBACKS.get(role, _ROLE_FALLBACKS["UNKNOWN"])
    base_reasoning = action["reasoning"]

    high_risk_count = sum(
        1 for d in all_devices
        if d.get("exploit_risk_level") == "HIGH" or d.get("exposure") == "HIGH"
    )

    context = (
        f"Across {len(all_devices)} device(s) on this network, {high_risk_count} "
        f"have HIGH risk indicators. "
    )

    return (
        f"{context}"
        f"The highest-priority target is {ip} ({device_type}, role: {role}). "
        f"{base_reasoning} "
        f"Addressing this issue is estimated to reduce your overall network risk by approximately {risk_reduction}%."
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_remediation_plan(devices: list[dict]) -> dict:
    """Generate a prioritised remediation plan across all scanned devices.

    Args:
        devices: List of enriched device dicts from the service layer.
                 Each must contain: ip, role, exposure, exploit_risk_level,
                 primary_issue (dict or None), device_type.

    Returns:
        Dict with critical_action, action_plan, risk_reduction_score, reasoning.
        Returns a safe empty plan when no devices are provided.
    """
    if not devices:
        return {
            "critical_action": None,
            "action_plan": [],
            "risk_reduction_score": 0,
            "reasoning": "No devices were found in this scan.",
        }

    sorted_devices = sorted(devices, key=_device_score, reverse=True)
    top_device = sorted_devices[0]

    critical_action = _select_critical_action(top_device)
    risk_reduction = _estimate_risk_reduction(top_device, devices)
    action_plan = _build_action_plan(devices)
    reasoning = _build_reasoning(top_device, risk_reduction, devices)

    return {
        "critical_action": critical_action,
        "action_plan": action_plan,
        "risk_reduction_score": risk_reduction,
        "reasoning": reasoning,
    }
