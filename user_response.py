"""User Response Engine.

Transforms internal scan intelligence into plain-English, decision-focused
output for non-technical users (small business owners, home network users).

Design principles:
  - Zero technical jargon in user-facing fields
  - Every statement derived exclusively from real scan data
  - Urgency calibrated to actual risk — never inflated, never understated
  - A single, clear action — never a list of 5 options
  - Every claim grounded in what was actually observed

Public API
----------
build_user_response(scan_data: dict) -> dict
    Returns: answer (status, message, if_you_ignore), why, impact, fix_now, proof, details
"""

from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# Status — 4-tier risk label
# ---------------------------------------------------------------------------

def _build_status(risk_level: str, entry_device: dict | None) -> str:
    """Map risk level + lateral movement data to a 4-tier human status label."""
    if risk_level == "LOW":
        return "SAFE"
    if risk_level == "MEDIUM":
        return "MEDIUM RISK"
    # HIGH — determine whether there is an active, confirmed entry point
    if entry_device:
        lm = entry_device.get("lateral_movement") or {}
        if lm.get("can_be_entry") or lm.get("can_be_pivot"):
            return "HIGH RISK — ACTIVE EXPOSURE"
    return "HIGH RISK"


# ---------------------------------------------------------------------------
# Priority — how urgently this needs action
# ---------------------------------------------------------------------------

def _build_confidence(
    entry_ip: str | None,
    entry_device: dict | None,
    device_probes: dict[str, list[dict]],
) -> str:
    """Rate evidence quality for the entry-point device.

    HIGH   — at least one application-layer probe confirmed reachable.
    MEDIUM — no reachable probe, but open ports and service fingerprint exist.
    LOW    — no ports and no reachable probe (inferred from weak signals only).
    """
    probes = device_probes.get(entry_ip, []) if entry_ip else []
    if any(p.get("reachable") for p in probes):
        return "HIGH"
    if entry_device and (entry_device.get("ports") or []):
        return "MEDIUM"
    return "LOW"


def _build_priority(risk_level: str, entry_device: dict | None) -> str:
    """FIX THIS FIRST when the entry device can also move to other devices.
    IMPORTANT when there is real exploitation risk but the device is contained.
    LOW PRIORITY for informational findings with no active exploitation path.
    """
    if risk_level == "LOW":
        return "LOW PRIORITY"
    lm = (entry_device.get("lateral_movement") or {}) if entry_device else {}
    if lm.get("can_be_entry") and lm.get("can_be_pivot"):
        return "FIX THIS FIRST"
    return "IMPORTANT"


# ---------------------------------------------------------------------------
# message — WHO can attack, WHAT they can do, WHY it matters now
# ---------------------------------------------------------------------------

# Issue-specific messages are strongest — they name the precise threat.
# Role-level messages are fallbacks when no primary issue is known.

_ISSUE_MESSAGES: dict[str, str] = {
    "HTTP without HTTPS": (
        "Anyone connected to your WiFi can silently intercept your router admin password "
        "the next time you log in — no special equipment required, just being on the same network."
    ),
    "HTTP served without HTTPS redirect": (
        "Anyone on your network can read your usernames and passwords in plain text "
        "as you type them into this device's login page — your credentials travel completely unprotected."
    ),
    "Telnet management interface exposed": (
        "Your router broadcasts your admin password in plain text every time you access it — "
        "anyone on your WiFi right now can silently capture it and take full control of your network."
    ),
    "Telnet enabled": (
        "A device on your network is using a completely unprotected remote control channel — "
        "anyone nearby can listen in and capture every command and password you send to it."
    ),
    "SMB exposed": (
        "A computer on your network is open to the same automated attack that spread ransomware "
        "across hundreds of thousands of businesses — tools that scan for this run continuously around the clock."
    ),
    "RDP exposed": (
        "Your computer is accepting remote control requests from anyone on your network — "
        "automated password-guessing tools target open remote access constantly, and only need one weak password to get in."
    ),
    "RTSP stream exposed": (
        "Your security camera is streaming live footage to anyone who asks — "
        "no password, no login, completely open. Public search engines index unprotected cameras like this."
    ),
    "Database port directly exposed": (
        "Your database is accepting connections from any device on your network — "
        "no login screen, no firewall in the way. Anyone who reaches it can read, alter, or delete your records."
    ),
    "MQTT broker exposed without TLS": (
        "Your smart home hub is broadcasting every device action in plain text — "
        "anyone on your WiFi can watch what your devices are doing and send commands to them."
    ),
    "SIP port exposed": (
        "Your phone system's control channel is open to anyone on your network — "
        "this is how attackers eavesdrop on calls or generate fraudulent call charges at your expense."
    ),
    "Development server exposed on network": (
        "A test server running on your network has no access controls — "
        "anyone on your WiFi can browse its files, access private data, and use it as a foothold into your machine."
    ),
    "NFS share exposed": (
        "A file share on your network has no access controls — "
        "anyone connected can read, overwrite, or delete the files stored on it right now."
    ),
    "FTP service detected": (
        "A file transfer service on your network sends your login credentials in plain text — "
        "anyone monitoring your network traffic can read your username and password as they travel."
    ),
    "Camera web interface exposed": (
        "Your camera's control panel is open to anyone on your network — "
        "an attacker can log in, change the password to lock you out, and watch your feed without you knowing."
    ),
    "Web management interface exposed": (
        "Your device's admin panel is reachable from anywhere on your network — "
        "if the password is weak or factory-default, anyone can log in and take control."
    ),
    "SNMP exposed": (
        "Your router is answering network management requests using a default password that is publicly known — "
        "an attacker can silently map your entire network and identify every connected device."
    ),
    "Unrecognized device with open ports": (
        "There is a device on your network we couldn't identify — it's accepting connections "
        "and you have no visibility into what it's doing or who controls it."
    ),
}

_ROLE_MESSAGES: dict[str, dict[str, str]] = {
    "HIGH": {
        "GATEWAY": (
            "Your router has an open security gap — someone already on your WiFi "
            "can intercept every login, message, and transaction happening on your network right now."
        ),
        "COMPUTE": (
            "A computer on your network is accepting remote connections it shouldn't — "
            "an attacker on your WiFi can reach your files, passwords, and everything on that machine."
        ),
        "EDGE_DEVICE": (
            "A connected device on your network has no protection — "
            "it gives an attacker a foothold to silently monitor your traffic and reach your other devices."
        ),
        "OBSERVER": (
            "Your security camera is wide open — someone could already be watching your live feed "
            "without your knowledge, and you have no way to tell."
        ),
        "UNKNOWN": (
            "An unidentified device on your network is accepting connections with no controls — "
            "you cannot protect something you cannot see, and this is a live blind spot."
        ),
        "_default": (
            "Your network has a serious gap — someone nearby can access your data "
            "and move between your devices without triggering any alarm."
        ),
    },
    "MEDIUM": {
        "GATEWAY": (
            "Your router has a configuration weakness — someone with basic knowledge "
            "and access to your WiFi could use it to intercept your traffic or access your network settings."
        ),
        "COMPUTE": (
            "A computer on your network is exposing something it shouldn't — "
            "an attacker on your WiFi could access private data or use it as a stepping stone to other devices."
        ),
        "EDGE_DEVICE": (
            "A smart or connected device on your network has a gap that could be used "
            "to access other devices or monitor your activity without your knowledge."
        ),
        "_default": (
            "Your network has a weakness that someone with basic skills and access to your WiFi "
            "could use to read your data or access devices they shouldn't reach."
        ),
    },
    "LOW": {
        "_default": (
            "Your network is mostly secure — we found minor gaps that don't pose "
            "an immediate threat but are worth fixing before they become one."
        ),
    },
}


def _build_message(
    risk_level: str,
    entry_role: str | None,
    primary_issue_title: str | None,
    entry_ip: str | None = None,
    entry_device: dict | None = None,
) -> str:
    # When we have a real device IP, use device-aware templates so the user
    # sees their actual network identity, not a generic example.
    if entry_ip:
        label = _device_label(entry_ip, entry_device)
        if primary_issue_title and primary_issue_title in _SPECIFIC_MESSAGES:
            return _SPECIFIC_MESSAGES[primary_issue_title].format(label=label, ip=entry_ip)
        level_specific = _SPECIFIC_ROLE_MESSAGES.get(risk_level, _SPECIFIC_ROLE_MESSAGES["LOW"])
        msg = level_specific.get(entry_role or "_default") or level_specific.get("_default")
        if msg:
            return msg.format(label=label, ip=entry_ip)
    # Fallback: issue-specific generic message
    if primary_issue_title and primary_issue_title in _ISSUE_MESSAGES:
        return _ISSUE_MESSAGES[primary_issue_title]
    level_msgs = _ROLE_MESSAGES.get(risk_level, _ROLE_MESSAGES["LOW"])
    return level_msgs.get(entry_role or "_default", level_msgs["_default"])


# ---------------------------------------------------------------------------
# why — plain-English root cause (what is structurally wrong)
# ---------------------------------------------------------------------------

_ISSUE_WHY: dict[str, str] = {
    "HTTP without HTTPS": (
        "Your router's login page uses an unencrypted connection. "
        "When you type your admin password, it travels across your network in plain text — "
        "readable by any device on the same WiFi without any interception tools."
    ),
    "HTTP served without HTTPS redirect": (
        "This device serves its login or control page without encrypting the connection. "
        "Every username and password you enter travels as readable text across your network — "
        "any device on your WiFi can intercept it passively."
    ),
    "Telnet management interface exposed": (
        "Your router is using a remote access method from 1969 that transmits every keystroke — "
        "including your admin password — in plain text across your entire network. "
        "Modern secure alternatives exist and are universally supported."
    ),
    "Telnet enabled": (
        "A device on your network is using a completely unencrypted remote control channel. "
        "Every command and credential sent to it travels in plain text, "
        "readable by anyone listening on the same network."
    ),
    "SMB exposed": (
        "A computer on your network is sharing files using a method that has a long history "
        "of critical security flaws. The same weakness was used by ransomware that infected "
        "over 200,000 computers in a single weekend — and automated tools still scan for it daily."
    ),
    "RDP exposed": (
        "Your computer is advertising remote desktop access to every device on your network. "
        "Automated tools run continuously trying thousands of common passwords against open "
        "remote access services — they only need to succeed once."
    ),
    "RTSP stream exposed": (
        "Your camera's video stream is answering requests from anyone without asking for a password. "
        "Search engines that index publicly accessible cameras may already have found it — "
        "these indexes are publicly browsable."
    ),
    "Database port directly exposed": (
        "Your database is accepting connections directly from the network with no protective layer "
        "in between. Databases are not built to face the network directly — they trust whoever "
        "connects to them, which means anyone who reaches it can attempt to query or modify your data."
    ),
    "MQTT broker exposed without TLS": (
        "Your smart home hub is broadcasting all device communication in plain text "
        "with no authentication required. Anyone on your network can read your device activity "
        "and send commands — such as unlocking a smart lock or turning off an alarm."
    ),
    "SIP port exposed": (
        "Your phone system's signalling channel is open and unprotected on your network. "
        "Attackers use open SIP channels to eavesdrop on calls and to generate fraudulent calls "
        "billed to your account — this is an active form of financial fraud."
    ),
    "Development server exposed on network": (
        "A test or development server is running on your network with no security controls at all. "
        "Dev servers are built for convenience, not protection — they frequently expose private files, "
        "internal project data, and admin tools with no authentication required."
    ),
    "NFS share exposed": (
        "A network file share is mounted and accessible to any device on your network "
        "with no access restriction in place. The files it contains are readable and writable "
        "by anyone who connects."
    ),
    "FTP service detected": (
        "An old file transfer service is running on your network that sends login credentials "
        "in plain text — your username and password are visible to anyone monitoring network traffic. "
        "Secure alternatives have existed for decades."
    ),
    "Camera web interface exposed": (
        "Your camera's web control panel is accessible from your network over an unencrypted connection. "
        "An attacker can attempt to log in using default or guessed passwords — "
        "most camera brands have well-known default credentials that are never changed."
    ),
    "Web management interface exposed": (
        "This device's admin panel is reachable from your network. "
        "Many devices ship with factory-default passwords that are never changed — "
        "these are publicly documented and are the first thing an attacker tries."
    ),
    "SNMP exposed": (
        "Your router is responding to network management requests using 'public' — "
        "a default password known to every network tool and attacker in existence. "
        "This lets anyone silently survey your network layout and connected devices."
    ),
    "Unrecognized device with open ports": (
        "We found a device on your network that we couldn't identify — it has open connections "
        "and is actively accepting requests. Unidentified devices are a blind spot: "
        "you cannot know what data they hold, what they can reach, or whether they belong there."
    ),
}


def _build_why(
    attack_simulation: dict,
    primary_issue_title: str | None,
) -> str:
    if primary_issue_title and primary_issue_title in _ISSUE_WHY:
        return _ISSUE_WHY[primary_issue_title]
    user_msg = (attack_simulation.get("user_message") or "").strip()
    if user_msg:
        return _clean_jargon(user_msg)
    return (
        "One or more devices on your network have open gaps that give "
        "an attacker on your WiFi a direct path to your data or other devices."
    )


# ---------------------------------------------------------------------------
# impact — concrete attacker action + real-world consequence
# ---------------------------------------------------------------------------

_ISSUE_IMPACT: dict[str, str] = {
    "HTTP without HTTPS": (
        "An attacker on your WiFi can capture your router admin password as you type it, "
        "then log in, lock you out, and redirect all your traffic through their machine — "
        "every device on your network becomes visible to them."
    ),
    "HTTP served without HTTPS redirect": (
        "An attacker can read your login credentials in real time as you type them, "
        "then log in as you and take control of this device or the data it manages."
    ),
    "Telnet management interface exposed": (
        "An attacker can silently record your admin credentials the next time you manage your router, "
        "then log in and reconfigure it to intercept all traffic on your network — "
        "including banking, email, and private messages from every connected device."
    ),
    "Telnet enabled": (
        "An attacker can capture your login credentials for this device without you noticing, "
        "then use that access to pivot to other devices on your network."
    ),
    "SMB exposed": (
        "An attacker can spread malware from this computer to every other Windows device on your network "
        "automatically, without needing any login — the same technique used to deploy ransomware that "
        "encrypted hospitals, banks, and businesses and demanded payment to restore access."
    ),
    "RDP exposed": (
        "An attacker who guesses or finds your password can take complete remote control of your computer — "
        "seeing your screen, accessing your files, reading your saved passwords, "
        "and installing software without you knowing."
    ),
    "RTSP stream exposed": (
        "An attacker can watch your live camera feed right now — no login required. "
        "If this camera covers a home, office, or sensitive area, "
        "they can watch your movements and routines indefinitely."
    ),
    "Database port directly exposed": (
        "An attacker can connect directly to your database and attempt to read all records, "
        "export your customer or user data, or delete everything — "
        "all without going through any application or login screen."
    ),
    "MQTT broker exposed without TLS": (
        "An attacker can monitor everything your smart devices do and send them commands — "
        "this includes actions like unlocking smart locks, disabling alarms, "
        "or cutting power to connected devices."
    ),
    "SIP port exposed": (
        "An attacker can eavesdrop on your calls in real time and place calls "
        "through your phone system — running up charges that bill directly to your account."
    ),
    "Development server exposed on network": (
        "An attacker can browse the files on this server — which may include source code, "
        "credentials, internal documents, or private data — and use it as a base "
        "to attack your computer or other devices on the network."
    ),
    "NFS share exposed": (
        "An attacker can read every file on this share and overwrite or delete them — "
        "including documents, backups, and any credentials stored in those files."
    ),
    "FTP service detected": (
        "An attacker monitoring your network can read your FTP username and password in plain text, "
        "then log in and access, modify, or delete the files stored on this service."
    ),
    "Camera web interface exposed": (
        "An attacker can log in to your camera's control panel using default or guessed credentials, "
        "change the password to lock you out, and watch your live feed without your knowledge."
    ),
    "Web management interface exposed": (
        "An attacker can attempt to log in to your device's admin panel — "
        "if they succeed, they can reconfigure it, access its data, or use it to reach other devices."
    ),
    "SNMP exposed": (
        "An attacker can silently query your router to map every device on your network, "
        "then use that map to plan targeted attacks against your most vulnerable devices."
    ),
    "Unrecognized device with open ports": (
        "An unidentified device with open connections is a potential attacker-controlled device "
        "or a forgotten piece of equipment with unknown access — "
        "either way, it represents a gap you currently have no visibility into."
    ),
}

_DATA_TRANSLATIONS: dict[str, str] = {
    "All network traffic":                      "everything traveling across your network — logins, banking, messages",
    "Admin credentials":                        "your router and admin passwords",
    "DNS queries":                              "every website visit from every device on your network",
    "VPN keys":                                 "your secure remote work connections",
    "Local files and documents":                "your private files and documents",
    "Saved passwords":                          "all your saved passwords",
    "Browser sessions":                         "your active accounts — email, banking, shopping",
    "Email":                                    "your emails",
    "Device control access":                    "control over your smart home devices",
    "Usage patterns":                           "your daily routines and activity patterns",
    "Local network topology":                   "the full layout of your private network",
    "Live camera feed":                         "your live security camera footage",
    "Recorded footage":                         "your recorded camera footage",
    "Motion detection events":                  "your security alerts and camera triggers",
    "Network file shares and credentials":      "shared files and login credentials stored on your network",
    "Full desktop session and all local data":  "full remote access to your computer and everything on it",
    "SSH keys and shell access":                "complete technical control of this device",
    "Files accessible via FTP":                 "files stored on this device's file service",
    "Email messages in transit":                "emails as they are being sent or received",
    "Database records and user data":           "all your stored records and customer data",
    "Unknown data — device purpose not identified": "data from an unidentified device on your network",
}


# Device-specific impact templates — use {label} and {ip} placeholders.
_SPECIFIC_IMPACT: dict[str, str] = {
    "HTTP without HTTPS": (
        "An attacker on your WiFi can capture the admin password for {label} as you type it, "
        "then log in, lock you out, and redirect your traffic — "
        "every device on your network becomes visible to them."
    ),
    "HTTP served without HTTPS redirect": (
        "An attacker can read login credentials sent to {label} in real time, "
        "then log in and take control of the device or the data it manages."
    ),
    "Telnet management interface exposed": (
        "An attacker can capture the admin credentials for {label}, "
        "then log in and reconfigure it to intercept all traffic on your network — "
        "banking, email, and private messages from every connected device."
    ),
    "Telnet enabled": (
        "An attacker can capture login credentials for {label} without you noticing, "
        "then use that access to reach other devices on your network."
    ),
    "SMB exposed": (
        "Malware can spread automatically from {label} to every other Windows device on your network "
        "without any login — the same technique used by ransomware that has encrypted hospitals and businesses."
    ),
    "RDP exposed": (
        "Anyone who finds the password for {label} gets full remote control — "
        "they can see the screen, access files, read saved passwords, and install software without you knowing."
    ),
    "RTSP stream exposed": (
        "Anyone can watch the live feed from {label} right now — no login required. "
        "If this camera covers a home, office, or sensitive area, they can watch your movements indefinitely."
    ),
    "Camera web interface exposed": (
        "An attacker can log in to {label} using default or guessed credentials, "
        "change the password to lock you out, and watch the live feed without your knowledge."
    ),
    "Web management interface exposed": (
        "Anyone who logs in to {label}'s admin panel can reconfigure it, "
        "access stored data, and use it as a base to reach other devices on your network."
    ),
    "SNMP exposed": (
        "An attacker can silently query {label} to map every device on your network, "
        "then use that map to plan targeted attacks against the most exposed ones."
    ),
    "Database port directly exposed": (
        "Anyone on your network can connect directly to the database at {ip} "
        "and read all records, export data, or delete everything — "
        "with no login screen and no application layer in the way."
    ),
    "FTP service detected": (
        "Anyone monitoring your network can read the credentials for {label} in plain text, "
        "then log in and access, modify, or delete the files stored on it."
    ),
    "NFS share exposed": (
        "Any device on your network can read and modify files on {label} — "
        "including documents, backups, and any credentials stored in those files."
    ),
    "Unrecognized device with open ports": (
        "The device at {ip} is accepting connections and you have no visibility into what it does — "
        "it could be attacker-controlled or a forgotten device with unknown access."
    ),
    "MQTT broker exposed without TLS": (
        "An attacker can monitor everything your smart devices do via {label} and send them commands — "
        "including unlocking smart locks, disabling alarms, or cutting power to connected devices."
    ),
    "SIP port exposed": (
        "An attacker can eavesdrop on calls through {label} and place fraudulent calls "
        "that bill directly to your account."
    ),
    "Development server exposed on network": (
        "An attacker can browse files on {label} — which may include source code, credentials, "
        "and private data — and use it as a base to attack your main devices."
    ),
}

_SPECIFIC_ROLE_IMPACT: dict[str, str] = {
    "GATEWAY": (
        "An attacker who reaches {label} controls your entire network — "
        "every device, transaction, and communication passes through it."
    ),
    "COMPUTE": (
        "An attacker who reaches {label} has access to every file, account, "
        "and saved credential on that machine — and a base to reach others."
    ),
    "EDGE_DEVICE": (
        "An attacker who reaches {label} has a persistent foothold — "
        "they can monitor traffic and move to other devices without detection."
    ),
    "OBSERVER": (
        "An attacker who reaches {label} has live visibility into your premises — "
        "useful for planning physical or digital intrusions."
    ),
    "_default": (
        "An attacker who reaches {label} has a foothold into your network — "
        "they can monitor traffic and reach other devices from there."
    ),
}


def _build_impact(
    attack_simulation: dict,
    primary_issue_title: str | None,
    entry_ip: str | None = None,
    entry_device: dict | None = None,
) -> str:
    # Device-specific impact when we have a real IP — names the actual device.
    if entry_ip:
        label = _device_label(entry_ip, entry_device)
        if primary_issue_title and primary_issue_title in _SPECIFIC_IMPACT:
            return _SPECIFIC_IMPACT[primary_issue_title].format(label=label, ip=entry_ip)
        entry_role = (entry_device or {}).get("role")
        role_tmpl = _SPECIFIC_ROLE_IMPACT.get(entry_role or "_default") or _SPECIFIC_ROLE_IMPACT["_default"]
        return role_tmpl.format(label=label, ip=entry_ip)

    # Issue-specific impact is the most concrete — always prefer it
    if primary_issue_title and primary_issue_title in _ISSUE_IMPACT:
        return _ISSUE_IMPACT[primary_issue_title]

    data_at_risk = attack_simulation.get("data_at_risk", [])
    compromised  = attack_simulation.get("compromised_devices", [])
    risk_level   = attack_simulation.get("impact_level", "LOW")

    if not data_at_risk and not compromised:
        return "No significant impact was identified from the issues detected."

    translated: list[str] = []
    for item in data_at_risk[:3]:
        translated.append(_DATA_TRANSLATIONS.get(item, item.lower()))

    prefix_map = {
        "HIGH":   "An attacker on your network can reach and steal ",
        "MEDIUM": "An attacker on your network could access ",
        "LOW":    "In the worst case, someone on your network could access ",
    }
    prefix = prefix_map.get(risk_level, "Someone could access ")

    if translated:
        if len(translated) == 1:
            impact = f"{prefix}{translated[0]}."
        elif len(translated) == 2:
            impact = f"{prefix}{translated[0]} and {translated[1]}."
        else:
            impact = f"{prefix}{translated[0]}, {translated[1]}, and {translated[2]}."
    else:
        impact = f"{prefix}sensitive data on your network."

    device_count = len(compromised)
    if device_count > 1:
        impact += (
            f" Once inside through this gap, an attacker can reach "
            f"up to {device_count} device{'s' if device_count != 1 else ''} on your network."
        )

    return impact


# ---------------------------------------------------------------------------
# business_impact — what this means in operational and financial terms
# ---------------------------------------------------------------------------

_ISSUE_BUSINESS_IMPACT: dict[str, str] = {
    "HTTP without HTTPS": (
        "If your router admin password is stolen, an attacker controls your entire network — "
        "every transaction, login, and communication your business sends becomes visible to them. "
        "Recovering control requires a factory reset and reconfiguring everything from scratch."
    ),
    "HTTP served without HTTPS redirect": (
        "Staff or customers logging into this device have their credentials exposed on the network. "
        "A stolen login can be used to access other systems that share the same password."
    ),
    "Telnet management interface exposed": (
        "Anyone on your network can silently capture your admin password and take over your router — "
        "putting every device, transaction, and communication on your network under their control."
    ),
    "Telnet enabled": (
        "A stolen credential from this device can be reused to access other systems in your network. "
        "Unencrypted access is a known starting point for broader network breaches."
    ),
    "SMB exposed": (
        "Ransomware entering through this gap can spread automatically to every Windows machine on your network, "
        "encrypting your files and demanding payment before you can access them again. "
        "Recovery without a backup can take days and cost thousands."
    ),
    "RDP exposed": (
        "An attacker who gets in through remote desktop has full access to everything on that computer — "
        "customer records, financial data, passwords, and any cloud accounts open in the browser. "
        "This is one of the most common entry points for ransomware attacks on businesses."
    ),
    "RTSP stream exposed": (
        "If this camera covers your business premises, an attacker can study your physical layout, "
        "staff schedules, and security practices — useful intelligence before a physical or digital intrusion."
    ),
    "Database port directly exposed": (
        "Your customer or business records are reachable with no login screen in the way. "
        "A breach could mean regulatory consequences, customer notification obligations, "
        "and reputational damage if data is stolen or published."
    ),
    "MQTT broker exposed without TLS": (
        "An attacker can monitor and control your smart devices — "
        "this includes anything connected to your smart home hub, such as locks, alarms, or environmental controls."
    ),
    "SIP port exposed": (
        "Fraudulent calls placed through your phone system bill directly to your account. "
        "International toll fraud can generate charges of hundreds or thousands of dollars "
        "before you notice — and carriers rarely reverse them."
    ),
    "Development server exposed on network": (
        "Test servers often contain real data, credentials, and internal project details. "
        "An attacker who accesses it gains a detailed picture of your systems "
        "and a base from which to attack your main infrastructure."
    ),
    "NFS share exposed": (
        "Any device on your network — including guest devices — can read and modify these files. "
        "If the share contains business documents, credentials, or backups, "
        "the contents can be copied or destroyed without leaving a trace."
    ),
    "FTP service detected": (
        "Login credentials captured from this service are often reused across other systems. "
        "An attacker who gets your FTP password may also be able to access your email, cloud storage, or admin tools."
    ),
    "Camera web interface exposed": (
        "An attacker who takes control of your camera can watch your premises live, "
        "disable recording, and use the device as a foothold to reach other systems on your network."
    ),
    "Web management interface exposed": (
        "If an attacker logs into this device's admin panel, they can reconfigure it, "
        "access stored data, and use it as a base to reach other devices on your network."
    ),
    "SNMP exposed": (
        "An attacker who maps your network knows exactly which devices you run and where to target next. "
        "This reconnaissance step is often the first stage of a larger, planned attack."
    ),
    "Unrecognized device with open ports": (
        "Unknown devices represent a blind spot in your security posture — "
        "you cannot audit, monitor, or protect a device you haven't accounted for. "
        "If it was placed by someone else, it may already be used for unauthorized access."
    ),
}

_ROLE_BUSINESS_IMPACT: dict[str, dict[str, str]] = {
    "HIGH": {
        "GATEWAY": (
            "An attacker who controls your router controls your entire network — "
            "every device, transaction, and communication passes through it."
        ),
        "COMPUTE": (
            "A compromised computer gives an attacker access to every file, account, "
            "and credential on that machine — and a base to reach others on your network."
        ),
        "EDGE_DEVICE": (
            "A compromised device on your network gives an attacker a persistent, hidden foothold — "
            "they can use it to monitor traffic and reach other devices without detection."
        ),
        "OBSERVER": (
            "A compromised camera gives an attacker live visibility into your premises — "
            "useful for planning physical or digital intrusions."
        ),
        "_default": (
            "This gap puts your business data and connected systems at direct risk of unauthorized access."
        ),
    },
    "MEDIUM": {
        "_default": (
            "This weakness could be used by someone on your network to access data or systems "
            "they shouldn't reach — the risk is real but requires the attacker to be on your network."
        ),
    },
    "LOW": {
        "_default": (
            "No significant business impact is expected from this finding in isolation, "
            "but it should be closed to prevent it becoming part of a larger exposure."
        ),
    },
}


def _build_business_impact(
    risk_level: str,
    entry_role: str | None,
    primary_issue_title: str | None,
) -> str:
    if primary_issue_title and primary_issue_title in _ISSUE_BUSINESS_IMPACT:
        return _ISSUE_BUSINESS_IMPACT[primary_issue_title]
    level = _ROLE_BUSINESS_IMPACT.get(risk_level, _ROLE_BUSINESS_IMPACT["LOW"])
    return level.get(entry_role or "_default", level["_default"])


# ---------------------------------------------------------------------------
# attack_path — plain-English chain: attacker → entry → reach
# ---------------------------------------------------------------------------

# How an attacker enters through each specific issue
_ISSUE_ENTRY_VIA: dict[str, str] = {
    "HTTP without HTTPS":                    "your router's unprotected login page",
    "HTTP served without HTTPS redirect":    "an unencrypted login page on a network device",
    "Telnet management interface exposed":   "an unencrypted remote control channel on your router",
    "Telnet enabled":                        "an unencrypted remote control channel on a network device",
    "SMB exposed":                           "an unprotected file sharing service",
    "RDP exposed":                           "an open remote desktop connection",
    "RTSP stream exposed":                   "an open, unauthenticated camera stream",
    "Database port directly exposed":        "a database with no network protection",
    "MQTT broker exposed without TLS":       "an open smart home messaging channel",
    "SIP port exposed":                      "an open phone system control channel",
    "Development server exposed on network": "an unprotected test server with no access controls",
    "NFS share exposed":                     "an open network file share",
    "FTP service detected":                  "an unencrypted file transfer service",
    "Camera web interface exposed":          "a camera control panel using default credentials",
    "Web management interface exposed":      "a device admin panel open on the network",
    "SNMP exposed":                          "a network management channel using a known default password",
    "Unrecognized device with open ports":   "an unidentified device with open connections",
    "Media control port exposed":            "an open media device control interface",
}

# Device-type labels for the attack path fallback — ensures correct articles and capitalization
_DEVICE_ENTRY_LABEL: dict[str, str] = {
    "Router/Firewall":        "your router",
    "IP Camera":              "your security camera",
    "Computer / Workstation": "a computer on your network",
    "IoT Device":             "an IoT device on your network",
    "Development Server":     "an unprotected development server",
    "Database Server":        "a database server on your network",
    "NAS/Storage Device":     "a network storage device",
    "Smart Home Hub":         "your smart home hub",
    "VoIP Device":            "your phone system",
    "Media Device":           "a media device on your network",
    "Network Printer":        "a network printer",
    "Unidentified Device":    "an unidentified device on your network",
}

# How to describe what an attacker reaches, translated from data_at_risk items
_REACH_TRANSLATIONS: dict[str, str] = {
    "All network traffic":                      "everything traveling across your network",
    "Admin credentials":                        "your admin passwords",
    "DNS queries":                              "every website every device visits",
    "VPN keys":                                 "your secure work connections",
    "Local files and documents":                "your private files",
    "Saved passwords":                          "your saved passwords",
    "Browser sessions":                         "your active email and banking sessions",
    "Email":                                    "your emails",
    "Device control access":                    "control over your smart devices",
    "Live camera feed":                         "your live camera footage",
    "Network file shares and credentials":      "your shared files and stored credentials",
    "Full desktop session and all local data":  "full control of that computer",
    "Database records and user data":           "your stored records and customer data",
}


def _build_attack_path(
    attack_simulation: dict,
    device_dicts: list[dict],
    entry_device: dict | None,
    primary_issue_title: str | None,
) -> str:
    entry_ip     = attack_simulation.get("entry_point")
    compromised  = attack_simulation.get("compromised_devices", [])
    data_at_risk = attack_simulation.get("data_at_risk", [])

    if not entry_ip or not entry_device:
        return ""

    # How the attacker enters — issue-specific first, device-type fallback with correct article
    device_type = entry_device.get("device_type") or "network device"
    entry_via = _ISSUE_ENTRY_VIA.get(
        primary_issue_title or "",
        _DEVICE_ENTRY_LABEL.get(device_type, f"a network device"),
    )

    # What the attacker reaches after entry
    other_ips = [ip for ip in compromised if ip != entry_ip]
    if other_ips and data_at_risk:
        first_data = _REACH_TRANSLATIONS.get(data_at_risk[0], data_at_risk[0].lower())
        reach = (
            f"reaches {len(other_ips)} other device{'s' if len(other_ips) != 1 else ''} "
            f"on your network and can access {first_data}"
        )
    elif other_ips:
        reach = (
            f"reaches {len(other_ips)} other device{'s' if len(other_ips) != 1 else ''} "
            f"on your network"
        )
    elif data_at_risk:
        first_data = _REACH_TRANSLATIONS.get(data_at_risk[0], data_at_risk[0].lower())
        reach = f"can access {first_data}"
    else:
        reach = "has full access to this device and its data"

    # Include the real IP so the path names an actual node the user can look up.
    if entry_ip:
        port = _first_port(entry_device)
        port_part = f" (port {port})" if port else ""
        return f"An attacker on your WiFi → connects to {entry_ip}{port_part} via {entry_via} → {reach}"
    return f"An attacker on your WiFi → enters through {entry_via} → {reach}"


# ---------------------------------------------------------------------------
# if_you_ignore — one line: the cost of doing nothing
# ---------------------------------------------------------------------------

_ISSUE_IGNORE: dict[str, str] = {
    "HTTP without HTTPS": (
        "Every login to your router is an opportunity for someone on your WiFi to steal your admin password."
    ),
    "HTTP served without HTTPS redirect": (
        "Every time you log into this device, your credentials are visible to anyone monitoring your network."
    ),
    "Telnet management interface exposed": (
        "Your admin password continues to travel in plain text — anyone on your network can capture it silently."
    ),
    "Telnet enabled": (
        "This device stays accessible via an unprotected channel that broadcasts credentials in plain text."
    ),
    "SMB exposed": (
        "This machine remains a single point of failure — one automated scan away from spreading malware across your entire network."
    ),
    "RDP exposed": (
        "Automated tools will keep trying passwords against your remote access indefinitely — they only need to succeed once."
    ),
    "RTSP stream exposed": (
        "Your camera feed stays publicly accessible — anyone who finds it can watch it without limit."
    ),
    "Database port directly exposed": (
        "Your records stay directly reachable from your network — any device on your WiFi can attempt to access them."
    ),
    "MQTT broker exposed without TLS": (
        "Anyone on your WiFi can continue to watch and control your smart devices without restriction."
    ),
    "SIP port exposed": (
        "Your phone system stays open to eavesdropping and fraudulent calls billed to your account."
    ),
    "Development server exposed on network": (
        "This server stays visible and browsable to every device on your network — including guests and any attacker who reaches your WiFi."
    ),
    "NFS share exposed": (
        "Your files stay accessible and writable by any device on your network — including ones you don't control."
    ),
    "FTP service detected": (
        "Your file transfer credentials continue to travel in plain text — readable by anyone monitoring your network."
    ),
    "Camera web interface exposed": (
        "Your camera's admin panel stays open — an attacker can take control of it at any time."
    ),
    "Web management interface exposed": (
        "Your device's admin panel stays reachable — any device on your network can attempt to log in."
    ),
    "SNMP exposed": (
        "An attacker on your network can silently continue mapping your devices using the known default password."
    ),
    "Unrecognized device with open ports": (
        "This unknown device stays active on your network — you have no visibility into what it can access or do."
    ),
}

_ROLE_IGNORE: dict[str, dict[str, str]] = {
    "HIGH": {
        "GATEWAY": (
            "Your entire network stays open to interception — every device behind this router is at risk until this is fixed."
        ),
        "COMPUTE": (
            "This computer stays remotely accessible to anyone on your network — its files and passwords remain exposed."
        ),
        "EDGE_DEVICE": (
            "This device stays exposed and can be used as a foothold to reach your other devices."
        ),
        "OBSERVER": (
            "Your camera feed stays open — anyone can watch it without your knowledge, indefinitely."
        ),
        "_default": (
            "The gap stays open — an attacker on your network can use it at any time."
        ),
    },
    "MEDIUM": {
        "_default": (
            "The weakness remains — the window for someone to use it stays open until you close it."
        ),
    },
    "LOW": {
        "_default": (
            "Minor gaps remain but pose limited immediate risk — fix them before they become a larger problem."
        ),
    },
}


def _build_if_you_ignore(
    risk_level: str,
    entry_role: str | None,
    primary_issue_title: str | None,
) -> str:
    if primary_issue_title and primary_issue_title in _ISSUE_IGNORE:
        return _ISSUE_IGNORE[primary_issue_title]
    level = _ROLE_IGNORE.get(risk_level, _ROLE_IGNORE["LOW"])
    return level.get(entry_role or "_default", level["_default"])


# ---------------------------------------------------------------------------
# fix_now — action + time + result (what disappears when you do this)
# ---------------------------------------------------------------------------

_EFFORT_TIME: dict[str, str] = {
    "LOW":    "About 5 minutes",
    "MEDIUM": "About 15–20 minutes",
    "HIGH":   "About 30–60 minutes (consider asking your IT provider)",
}

_ACTION_TRANSLATIONS: dict[str, str] = {
    "Force HTTPS on your router's management interface": (
        "Switch your router's login page to an encrypted connection"
    ),
    "Disable Telnet on your router immediately": (
        "Turn off the old, unprotected remote access channel on your router"
    ),
    "Restrict or disable SNMP on your router": (
        "Turn off your router's network management feature — it uses a publicly known default password"
    ),
    "Block SMB from being reachable on the network": (
        "Stop this computer from sharing files over the network in an unprotected way"
    ),
    "Place Remote Desktop behind a VPN": (
        "Put your remote access behind a secure tunnel — make it invisible to anyone who isn't you"
    ),
    "Bind your database to localhost only": (
        "Make your database reachable only from the same computer it runs on — not from the network"
    ),
    "Move IoT and media devices to an isolated network segment": (
        "Create a separate WiFi network for smart devices, cut off from your main computers"
    ),
    "Restrict your camera stream to authorised viewers only": (
        "Add a password to your camera so only you can see the feed"
    ),
    "Audit and harden your router configuration": (
        "Review and lock down your router settings to close the gaps we found"
    ),
    "Stop your development server from being reachable on the network": (
        "Shut down the test server or restrict it so only this computer can reach it — not your network"
    ),
    "Patch and reduce the attack surface on this machine": (
        "Update this computer's software and turn off features that aren't actively in use"
    ),
    "Isolate this device from your main network": (
        "Move this device to a separate network where it cannot reach your main computers"
    ),
    "Secure this monitoring or camera device": (
        "Change the default password on your camera and apply any available updates"
    ),
    "Identify this device and audit its services": (
        "Find out what this unknown device is and remove it from your network if it shouldn't be there"
    ),
}

_ISSUE_RESULT: dict[str, str] = {
    "HTTP without HTTPS": (
        "Your admin password stops traveling in plain text — "
        "anyone listening on your network sees only scrambled data, not your credentials."
    ),
    "HTTP served without HTTPS redirect": (
        "Login credentials stop traveling in plain text — "
        "your password becomes unreadable to anyone intercepting the connection."
    ),
    "Telnet management interface exposed": (
        "The open broadcast channel closes — there is nothing left for an attacker to listen to, "
        "and your admin password stays private every time you use it."
    ),
    "Telnet enabled": (
        "The unprotected remote access channel disappears from your network — "
        "credentials sent to this device are no longer visible to anyone else."
    ),
    "SMB exposed": (
        "The main path used to spread ransomware across your network closes — "
        "this machine can no longer be used as a launch point for malware spreading to your other devices."
    ),
    "RDP exposed": (
        "Remote access becomes invisible to everyone but you — "
        "automated password attacks stop immediately because there is nothing left to target."
    ),
    "RTSP stream exposed": (
        "Your camera stream becomes inaccessible without a password — "
        "public search engines can no longer index it, and unauthorized viewers are blocked immediately."
    ),
    "Database port directly exposed": (
        "Your database disappears from the network entirely — "
        "no device other than the one it runs on can reach it, so no remote attack is possible."
    ),
    "MQTT broker exposed without TLS": (
        "Outsiders can no longer read your device activity or send commands to your smart home — "
        "the open broadcast channel is replaced by an authenticated, encrypted one."
    ),
    "SIP port exposed": (
        "The open phone system channel closes — eavesdropping and fraudulent call generation "
        "become impossible from your network."
    ),
    "Development server exposed on network": (
        "The server becomes completely invisible to your network — "
        "no device other than this computer can find or reach it."
    ),
    "NFS share exposed": (
        "Your files become accessible only to the devices you authorize — "
        "everything else on your network is blocked from reading or modifying them."
    ),
    "FTP service detected": (
        "Credentials and files stop traveling in plain text — "
        "the interception risk disappears along with the unencrypted service."
    ),
    "Camera web interface exposed": (
        "Your camera's control panel becomes inaccessible to anyone without the new password — "
        "the default-credential login path closes permanently."
    ),
    "Web management interface exposed": (
        "The admin panel becomes protected — automated login attempts fail and "
        "your device configuration is no longer reachable without your credentials."
    ),
    "SNMP exposed": (
        "Your router stops answering network mapping requests — "
        "an attacker can no longer use the known default password to survey your network."
    ),
    "Unrecognized device with open ports": (
        "The unknown device is removed from your network — "
        "the blind spot closes and everything on your network is accounted for."
    ),
}


def _translate_action(title: str) -> str:
    return _ACTION_TRANSLATIONS.get(title, title)


def _build_result(primary_issue_title: str | None, action_steps: list[str]) -> str:
    if primary_issue_title and primary_issue_title in _ISSUE_RESULT:
        return _ISSUE_RESULT[primary_issue_title]
    if action_steps:
        return (
            "The specific gap we found closes — "
            "the path an attacker would use to get in is no longer available."
        )
    return (
        "The most exposed path into your network closes when you complete this action."
    )


def _risk_reduction_label(raw: int | None) -> str:
    """Convert a numeric risk_reduction score (0–100) to a human tier."""
    if raw is None:
        return "MEDIUM"
    if raw >= 70:
        return "HIGH"
    if raw >= 40:
        return "MEDIUM"
    return "LOW"


def _build_fix_now(
    remediation_plan: dict,
    primary_issue_title: str | None,
) -> dict:
    critical = remediation_plan.get("critical_action")
    if not critical:
        return {
            "action":         "Log in to your router and disable remote management, UPnP, and any services you don't actively use — these are the most common paths used to reach a network from outside.",
            "time":           "About 15 minutes",
            "result":         (
                "Fewer open access points means fewer paths an attacker can use — "
                "your network's exposure shrinks immediately."
            ),
            "risk_reduction": "MEDIUM",
        }

    title  = critical.get("title", "")
    effort = critical.get("effort", "MEDIUM")
    steps  = critical.get("steps", [])

    return {
        "action":         _translate_action(title),
        "time":           _EFFORT_TIME.get(effort, "About 15 minutes"),
        "result":         _build_result(primary_issue_title, steps),
        "risk_reduction": _risk_reduction_label(critical.get("risk_reduction")),
    }


# ---------------------------------------------------------------------------
# proof — observed evidence, not log entries
# ---------------------------------------------------------------------------

_PORT_PROOF: dict[int, str] = {
    80:    "We found your device's management page accessible without encryption — any login you make travels openly across your network",
    23:    "We found an old unprotected remote control channel open on your device — anyone on your network can potentially intercept commands sent to it",
    554:   "We found a camera stream port open and responding to connection attempts on your network",
    445:   "We found file sharing open and reachable from any device on your network",
    3389:  "We found remote desktop access open and reachable from any device on your network",
    8008:  "We found a smart device control interface open and responding to connection attempts on your network",
    1883:  "We found a smart home messaging channel open and accepting connections on your network",
    5060:  "We found a phone system control channel open and answering requests on your network",
    21:    "We found an old file transfer service open — it transfers data without any encryption",
    3306:  "We found a database open and directly reachable from your network with no protective layer in between",
    5432:  "We found a database open and directly reachable from your network with no protective layer in between",
    27017: "We found a database open and directly reachable from your network with no protective layer in between",
    8080:  "We found a web application open and reachable on your network — we could not verify whether access controls are in place",
    631:   "We found a network printer's control panel open and responding to connection attempts",
}

# Device-specific port proof — use when the entry device IP is known.
# {ip} is substituted with the actual device IP address.
_PORT_PROOF_SPECIFIC: dict[int, str] = {
    80:    "We detected an open management page at {ip} on port 80 — any admin login to this address travels without encryption",
    23:    "We detected an unprotected remote control channel at {ip} on port 23 — anyone on your network can intercept commands sent to it",
    554:   "We detected a camera stream port open at {ip} on port 554 — it is responding to connection attempts",
    445:   "We detected file-sharing at {ip} on port 445 — it is reachable from every device on your network",
    3389:  "We detected remote desktop access at {ip} on port 3389 — it is reachable from every device on your network",
    8008:  "We detected a smart device control interface at {ip} on port 8008 — it is responding to connection attempts on your network",
    1883:  "We detected a smart home messaging channel at {ip} on port 1883 — it is open and accepting connections",
    5060:  "We detected a phone system control channel at {ip} on port 5060 — it is answering requests openly on your network",
    21:    "We detected a file transfer service at {ip} on port 21 — it transfers data without encryption",
    3306:  "We detected a database at {ip} on port 3306 directly reachable from your network — no login screen in the way",
    5432:  "We detected a database at {ip} on port 5432 directly reachable from your network — no login screen in the way",
    27017: "We detected a database at {ip} on port 27017 directly reachable from your network — no login screen in the way",
    8080:  "We detected a web application at {ip} on port 8080 — it is responding to connection attempts on your network",
    631:   "We detected a printer control panel at {ip} on port 631 — it is responding to connection attempts",
}


def _build_proof(
    attack_simulation: dict,
    device_dicts: list[dict],
    device_probes: dict[str, list[dict]],
) -> list[str]:
    """Build proof statements exclusively from the entry-point device's confirmed data.

    All probe-derived statements are gated on reachable=True — port-open (nmap)
    is never conflated with service-reachable (application-layer probe).
    Probes from non-entry devices are never attributed to the entry device.
    """
    proof: list[str] = []
    seen: set[str] = set()

    def add(stmt: str) -> None:
        if stmt not in seen:
            seen.add(stmt)
            proof.append(stmt)

    entry_ip = attack_simulation.get("entry_point")
    entry_dev = next(
        (d for d in device_dicts if d.get("ip") == entry_ip), None
    ) if entry_ip else None

    # 1. Probe-derived evidence — only from the entry-point device, only when reachable
    entry_probes: list[dict] = device_probes.get(entry_ip, []) if entry_ip else []

    for probe in entry_probes:
        pt = probe.get("probe_type", "")
        probe_port = probe.get("port", "")
        ip_port_ref = f" at {entry_ip} (port {probe_port})" if entry_ip and probe_port else (
            f" at {entry_ip}" if entry_ip else ""
        )

        if pt == "http" and probe.get("reachable"):
            if not probe.get("redirect_to_https"):
                add(
                    f"We connected directly{ip_port_ref} and confirmed "
                    "it was serving credentials over an unprotected connection"
                )
            server = (probe.get("server") or "").strip()
            if server and re.search(r"\d", server):
                ip_ref = f"{entry_ip} " if entry_ip else "Your device "
                add(
                    f"{ip_ref}openly advertised it is running '{server}' — "
                    "this lets anyone look up exactly which known weaknesses apply to that version"
                )
            title_text = (probe.get("title") or "").lower()
            if "index of" in title_text or "directory listing" in title_text:
                add(
                    f"We opened the web interface{' at ' + entry_ip if entry_ip else ''} "
                    "and found it displaying a full list of files — "
                    "no login was required and no access control was in place"
                )

        if pt == "https" and probe.get("reachable") and not probe.get("tls_ok"):
            add(
                f"We found an encrypted connection{ip_port_ref} "
                "but its security certificate had a problem — "
                "the encryption may not be fully protecting your traffic"
            )

        if pt == "banner" and probe.get("banner"):
            snippet = (probe.get("banner") or "")[:50].replace("\n", " ").strip()
            if snippet:
                ip_ref = entry_ip if entry_ip else "Your device"
                add(
                    f"{ip_ref} responded and identified itself as '{snippet}' — "
                    "confirming it is actively accepting connections from your network"
                )

    # 2. Port-based evidence for the entry point device
    # Skip ports where a reachable probe already produced evidence (avoids semantic duplicates)
    probe_confirmed_ports: set[int] = {
        p.get("port") for p in entry_probes if p.get("reachable") and p.get("port")
    }
    if entry_dev:
        for port in (entry_dev.get("ports") or [])[:3]:
            if port in probe_confirmed_ports:
                continue  # probe evidence is stronger and already added
            # Use the device-specific template (with real IP) when available.
            if entry_ip and port in _PORT_PROOF_SPECIFIC:
                add(_PORT_PROOF_SPECIFIC[port].format(ip=entry_ip))
            elif port in _PORT_PROOF:
                add(_PORT_PROOF[port])

    # 3. Scan-level fact — names the entry device so the user sees a real address.
    device_count = len(device_dicts)
    if device_count:
        if entry_ip and entry_dev:
            label = _device_label(entry_ip, entry_dev)
            others = device_count - 1
            tail = (
                f" along with {others} other device{'s' if others != 1 else ''}"
                if others else ""
            )
            add(
                f"We confirmed {label} is active on your network{tail} — "
                "all connected devices are at risk if the most exposed one is reached"
            )
        else:
            add(
                f"We scanned your network and found "
                f"{device_count} active device{'s' if device_count != 1 else ''} — "
                f"all of them are affected if the weakest one is taken over"
            )

    # 4. Blast radius fact
    compromised = attack_simulation.get("compromised_devices", [])
    if len(compromised) > 1:
        add(
            f"Our analysis indicates that from the most exposed device, "
            f"an attacker could potentially reach {len(compromised)} devices on your network"
        )

    # 5. Fallback for a complete scan that found no devices — SAFE state needs evidence too.
    if not proof:
        add(
            "We completed a scan of your network and found no active devices with open security issues at this time"
        )

    return proof[:4]


# ---------------------------------------------------------------------------
# Jargon cleaner — used only on fallback text from other engines
# ---------------------------------------------------------------------------

_JARGON_RE: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"CVE-\d{4}-\d+",            re.I), "a known security flaw"),
    (re.compile(r"\bport\s+\d+\b",           re.I), "a network channel"),
    (re.compile(r"\bTLS\b|\bSSL\b",          re.I), "encryption"),
    (re.compile(r"\bHTTPS?\b",               re.I), "a secure web connection"),
    (re.compile(r"\bSMB\b",                  re.I), "file sharing"),
    (re.compile(r"\bRDP\b",                  re.I), "remote desktop access"),
    (re.compile(r"\bSSH\b",                  re.I), "secure remote access"),
    (re.compile(r"\bSNMP\b",                 re.I), "a network management feature"),
    (re.compile(r"\bRTSP\b",                 re.I), "a camera video stream"),
    (re.compile(r"\bFTP\b",                  re.I), "file transfer"),
    (re.compile(r"\btelnet\b",               re.I), "an unencrypted remote access tool"),
    (re.compile(r"\bbrute[- ]force\b",       re.I), "password guessing attacks"),
    (re.compile(r"\bexploit(?:ed|ing)?\b",   re.I), "attack"),
    (re.compile(r"\bvulnerabilit(?:y|ies)\b",re.I), "security gap"),
    (re.compile(r"\bmisconfiguration\b",     re.I), "incorrect setting"),
    (re.compile(r"\blateral movement\b",     re.I), "spreading to other devices"),
    (re.compile(r"\bpivot(?:ing)?\b",        re.I), "moving to other devices"),
    (re.compile(r"\bcompromised?\b",         re.I), "taken over"),
    (re.compile(r"\battack surface\b",       re.I), "the number of ways in"),
    (re.compile(r"\bfirewall\b",             re.I), "network protection"),
    (re.compile(r"\bVLAN\b",                 re.I), "a separate network segment"),
]


def _clean_jargon(text: str) -> str:
    for pattern, replacement in _JARGON_RE:
        text = pattern.sub(replacement, text)
    return text


# ---------------------------------------------------------------------------
# Device-aware helpers — inject real IP and device identity into messages
# ---------------------------------------------------------------------------


def _device_label(ip: str | None, device: dict | None) -> str:
    """Human-readable device name that always includes the actual IP address.

    Examples: "your router (192.168.1.1)", "a camera (192.168.1.4)", "a device at 10.0.0.5"
    """
    if not ip:
        return "a device on your network"
    dt = ((device or {}).get("device_type") or "").lower()
    brand = ((device or {}).get("router_brand") or "").strip()
    if "router" in dt or "firewall" in dt:
        return f"your {brand} router ({ip})" if brand else f"your router ({ip})"
    if "camera" in dt:
        return f"your camera ({ip})"
    if "computer" in dt or "workstation" in dt:
        return f"a computer ({ip})"
    if "printer" in dt:
        return f"a printer ({ip})"
    if "storage" in dt or "nas" in dt:
        return f"a storage device ({ip})"
    if "smart" in dt or "iot" in dt:
        return f"a smart device ({ip})"
    if "voip" in dt or "phone" in dt:
        return f"a phone device ({ip})"
    if "media" in dt:
        return f"a media device ({ip})"
    return f"a device at {ip}"


def _first_port(device: dict | None) -> str:
    """Return the first open port as a string, or empty string."""
    ports = (device or {}).get("ports") or []
    return str(ports[0]) if ports else ""


# Issue-specific messages with {label} and {ip} placeholders — every entry
# names the real device so users see *their* network, not a generic example.
_SPECIFIC_MESSAGES: dict[str, str] = {
    "HTTP without HTTPS": (
        "Anyone on your WiFi can see unencrypted traffic from {label} — "
        "including any admin password typed into its login page."
    ),
    "HTTP served without HTTPS redirect": (
        "Anyone on your network can read credentials sent to {label} in plain text — "
        "the login page at {ip} has no encryption protecting it."
    ),
    "Telnet management interface exposed": (
        "Your router at {ip} has an unprotected remote control channel open — "
        "anyone on your WiFi can silently capture every command and password sent to it."
    ),
    "Telnet enabled": (
        "{label} has an unencrypted remote control channel open — "
        "anyone on the network can intercept every command and credential sent to it."
    ),
    "SMB exposed": (
        "A computer at {ip} is sharing files in a way that lets automated tools "
        "spread malware across your network — no login required."
    ),
    "RDP exposed": (
        "The computer at {ip} is accepting remote control requests from anyone on your network — "
        "automated tools continuously guess passwords against open remote access."
    ),
    "RTSP stream exposed": (
        "Your camera at {ip} is streaming live footage to anyone who asks — "
        "no password, no login, completely open."
    ),
    "Camera web interface exposed": (
        "{label} has its admin panel open on your network — "
        "anyone can attempt to log in using default or common passwords."
    ),
    "Web management interface exposed": (
        "{label} has its admin panel reachable from your network — "
        "if the password is weak or factory-default, anyone nearby can log in and take control."
    ),
    "FTP service detected": (
        "{label} is running a file transfer service that sends login credentials in plain text — "
        "anyone monitoring traffic on your network can read them."
    ),
    "SNMP exposed": (
        "Your router at {ip} is answering network mapping requests using a publicly known default password — "
        "anyone on your network can silently survey every device connected to it."
    ),
    "Database port directly exposed": (
        "A database at {ip} is accepting connections directly from your network — "
        "no login screen, no protection between it and anyone who finds it."
    ),
    "MQTT broker exposed without TLS": (
        "{label} is broadcasting smart home commands in plain text — "
        "anyone on your WiFi can watch what your devices do and send them commands."
    ),
    "SIP port exposed": (
        "{label} has its phone system control channel open — "
        "anyone on your network can eavesdrop on calls or generate charges at your expense."
    ),
    "Development server exposed on network": (
        "A test server at {ip} has no access controls and is reachable from your network — "
        "anyone on your WiFi can browse its files and data."
    ),
    "NFS share exposed": (
        "{label} has a file share open to every device on your network — "
        "anyone connected can read, overwrite, or delete files stored on it."
    ),
    "Unrecognized device with open ports": (
        "There is an unidentified device at {ip} accepting connections on your network — "
        "you have no visibility into what it does or who controls it."
    ),
}

# Role-based fallbacks when no named issue is identified — still include the IP.
_SPECIFIC_ROLE_MESSAGES: dict[str, dict[str, str]] = {
    "HIGH": {
        "GATEWAY": (
            "Your router at {ip} has a security gap that lets anyone on your WiFi "
            "intercept traffic and access settings across your entire network."
        ),
        "COMPUTE": (
            "The computer at {ip} is accepting connections it shouldn't — "
            "someone on your WiFi can reach its files and everything stored on it."
        ),
        "EDGE_DEVICE": (
            "A device at {ip} has no protection — it gives anyone on your WiFi "
            "a foothold to monitor traffic and reach your other devices."
        ),
        "OBSERVER": (
            "Your camera at {ip} is wide open — someone could already be watching "
            "your live feed without your knowledge."
        ),
        "_default": (
            "A device at {ip} has a serious gap — someone on your WiFi can use it "
            "to access data and move between your devices without detection."
        ),
    },
    "MEDIUM": {
        "GATEWAY": (
            "Your router at {ip} has a configuration weakness — "
            "someone with basic skills on your WiFi could access your network settings."
        ),
        "COMPUTE": (
            "The computer at {ip} is exposing something it shouldn't — "
            "someone on your WiFi could access private data or use it to reach other devices."
        ),
        "_default": (
            "A device at {ip} has a weakness — "
            "someone on your WiFi with basic skills could use it to reach data they shouldn't."
        ),
    },
    "LOW": {
        "_default": (
            "We found {label} with minor gaps that don't pose an immediate threat "
            "but are worth fixing before they become one."
        ),
    },
}


# ---------------------------------------------------------------------------
# upgrade_prompt — soft conversion message (relief, not sales)
# ---------------------------------------------------------------------------

# Keyed by (priority, entry_role). Falls back to priority-only, then empty.
_UPGRADE_PROMPTS: dict[tuple[str, str], str] = {
    ("FIX THIS FIRST", "GATEWAY"): (
        "If you'd rather not touch your router settings yourself, "
        "a network professional can close this remotely — no disruption to your network, "
        "usually done in under 30 minutes."
    ),
    ("FIX THIS FIRST", "COMPUTE"): (
        "If you'd prefer someone else handles this, "
        "a technician can secure this machine in a short remote session "
        "without interrupting your work."
    ),
    ("FIX THIS FIRST", "EDGE_DEVICE"): (
        "If you'd like this sorted without the hassle, "
        "a professional can isolate and secure this device remotely — "
        "typically a 15-minute job."
    ),
    ("FIX THIS FIRST", "OBSERVER"): (
        "If you'd rather not configure your camera yourself, "
        "a technician can lock it down remotely in minutes — "
        "no camera access needed on your end."
    ),
    ("FIX THIS FIRST", "UNKNOWN"): (
        "If you're not sure what this device is or whether it belongs there, "
        "a professional can identify it and remove it safely — "
        "usually resolved in a single remote session."
    ),
    ("IMPORTANT", "GATEWAY"): (
        "If you'd like help reviewing your router settings, "
        "a professional can walk you through it or handle it for you in a quick remote call."
    ),
    ("IMPORTANT", "COMPUTE"): (
        "If you'd like someone to handle this for you, "
        "a technician can secure this in a short remote session at a time that suits you."
    ),
}

_UPGRADE_PROMPT_FALLBACK: dict[str, str] = {
    "FIX THIS FIRST": (
        "If you'd rather not handle this yourself, "
        "a network professional can fix this remotely — "
        "no disruption, no technical knowledge required on your end."
    ),
    "IMPORTANT": (
        "If you'd like help with this, "
        "a security professional can walk you through the fix or handle it for you in a short remote session."
    ),
    "LOW PRIORITY": "",
}


def _build_upgrade_prompt(priority: str, entry_role: str | None) -> str:
    specific = _UPGRADE_PROMPTS.get((priority, entry_role or ""))
    if specific:
        return specific
    return _UPGRADE_PROMPT_FALLBACK.get(priority, "")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_user_response(scan_data: dict) -> dict:
    """Transform internal scan intelligence into a plain-English user response.

    All output is derived exclusively from real scan data — no hallucination,
    no generic templates applied without grounding in the actual results.

    Args:
        scan_data: Dict with keys:
            attack_simulation  — from simulate_attack_impact()
            remediation_plan   — from generate_remediation_plan()
            device_dicts       — list of enriched device dicts
            device_probes      — dict mapping IP → list of probe results for that device
                                 (empty dict when probes are unavailable, e.g. GET /scans/{id})
            details            — the full existing details dict (passed through unchanged)

    Returns:
        Dict with keys:
            answer          — {status, message, if_you_ignore}
            priority        — FIX THIS FIRST | IMPORTANT | LOW PRIORITY
            why             — plain-English root cause
            impact          — concrete attacker action + real-world consequence
            business_impact — operational and financial consequence for the owner
            attack_path     — plain-English chain: attacker → entry → reach
            fix_now         — {action, time, result, risk_reduction}
            proof           — list of observation statements (max 4)
            if_you_ignore   — kept inside answer.if_you_ignore (also top-level for direct access)
            upgrade_prompt  — soft offer of professional help
            details         — full technical detail dict (unchanged)
    """
    attack_simulation = scan_data.get("attack_simulation", {})
    remediation_plan  = scan_data.get("remediation_plan",  {})
    device_dicts      = scan_data.get("device_dicts",      [])
    device_probes     = scan_data.get("device_probes",     {})
    details           = scan_data.get("details",           {})

    risk_level = attack_simulation.get("impact_level", "LOW")
    entry_ip   = attack_simulation.get("entry_point")

    entry_device = next(
        (d for d in device_dicts if d.get("ip") == entry_ip), None
    ) if entry_ip else None

    entry_role          = entry_device.get("role")           if entry_device else None
    primary_issue_title = (
        (entry_device.get("primary_issue") or {}).get("title")
        if entry_device else None
    )

    priority   = _build_priority(risk_level, entry_device)
    confidence = _build_confidence(entry_ip, entry_device, device_probes)

    return {
        "answer": {
            "status":        _build_status(risk_level, entry_device),
            "message":       _build_message(
                                 risk_level, entry_role, primary_issue_title,
                                 entry_ip, entry_device,
                             ),
            "if_you_ignore": _build_if_you_ignore(risk_level, entry_role, primary_issue_title),
        },
        "priority":        priority,
        "confidence":      confidence,
        "why":             _build_why(attack_simulation, primary_issue_title),
        "impact":          _build_impact(
                               attack_simulation, primary_issue_title,
                               entry_ip, entry_device,
                           ),
        "business_impact": _build_business_impact(risk_level, entry_role, primary_issue_title),
        "attack_path":     _build_attack_path(
                               attack_simulation, device_dicts, entry_device, primary_issue_title
                           ),
        "fix_now":         _build_fix_now(remediation_plan, primary_issue_title),
        "proof":           _build_proof(attack_simulation, device_dicts, device_probes),
        "upgrade_prompt":  _build_upgrade_prompt(priority, entry_role),
        "details":         details,
    }
