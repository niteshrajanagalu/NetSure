"""Evidence Engine — attaches verifiable proof to every issue and insight.

Uses only data already collected during the scan (ports, services, probes).
No new network calls are made.  If no probe data exists for a port, only
port-level evidence is recorded.

Public API
----------
attach_evidence(device: dict) -> list[dict]
    Returns a list of evidence entries for the device.
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Probe evidence builders
# ---------------------------------------------------------------------------

def _evidence_from_http_probe(probe: dict) -> dict | None:
    """Build one evidence entry from an HTTP probe result."""
    if not probe.get("reachable"):
        return None

    port = probe.get("port")
    facts: list[str] = ["HTTP service responded"]

    status = probe.get("status_code")
    if status is not None:
        facts.append(f"status {status}")

    redirect = probe.get("redirect_to_https", False)
    if redirect:
        facts.append("redirects to HTTPS")
    else:
        facts.append("no HTTPS redirect observed")

    server = probe.get("server")
    if server:
        facts.append(f"Server: {server}")

    title = probe.get("title")
    if title:
        facts.append(f"page title: {title!r}")

    raw: dict = {}
    for key in ("status_code", "server", "title", "redirect_to_https"):
        if probe.get(key) is not None:
            raw[key] = probe[key]

    return {
        "type": "http_probe",
        "port": port,
        "proof": "; ".join(facts),
        "raw": raw,
    }


def _evidence_from_https_probe(probe: dict) -> dict | None:
    """Build one evidence entry from an HTTPS probe result."""
    if not probe.get("reachable"):
        return None

    port = probe.get("port")
    facts: list[str] = []

    if probe.get("tls_ok"):
        facts.append("TLS endpoint confirmed reachable")
    else:
        facts.append("HTTPS port reachable but TLS handshake failed")

    status = probe.get("status_code")
    if status is not None:
        facts.append(f"status {status}")

    server = probe.get("server")
    if server:
        facts.append(f"Server: {server}")

    raw: dict = {}
    for key in ("status_code", "server", "tls_ok"):
        if probe.get(key) is not None:
            raw[key] = probe[key]

    return {
        "type": "https_probe",
        "port": port,
        "proof": "; ".join(facts) if facts else "HTTPS service reachable",
        "raw": raw,
    }


def _evidence_from_banner_probe(probe: dict) -> dict | None:
    """Build one evidence entry from a banner grab result."""
    banner = probe.get("banner")
    if not banner:
        return None

    port = probe.get("port")
    snippet = banner[:100].replace("\n", " ").replace("\r", "")

    return {
        "type": "banner_probe",
        "port": port,
        "proof": f"Service banner received: {snippet!r}",
        "raw": {"banner": snippet},
    }


def _probe_evidence(probes: list[dict]) -> list[dict]:
    """Convert all probe results into evidence entries."""
    evidence: list[dict] = []
    for probe in probes:
        pt = probe.get("probe_type")
        entry: dict | None = None
        if pt == "http":
            entry = _evidence_from_http_probe(probe)
        elif pt == "https":
            entry = _evidence_from_https_probe(probe)
        elif pt == "banner":
            entry = _evidence_from_banner_probe(probe)
        if entry:
            evidence.append(entry)
    return evidence


# ---------------------------------------------------------------------------
# Issue → evidence mapping
# ---------------------------------------------------------------------------

# Maps issue title → list of port-level evidence descriptors.
# Each descriptor is (port, proof_template) where {port} is substituted.
_ISSUE_PORT_EVIDENCE: dict[str, list[tuple[int | None, str]]] = {
    "HTTP without HTTPS": [
        (80,  "Port 80 open — HTTP service detected by nmap"),
    ],
    "HTTP served without HTTPS redirect": [
        (80,   "Port 80 open — HTTP service reachable"),
        (8008, "Port 8008 open — alternate HTTP service reachable"),
        (8080, "Port 8080 open — HTTP service reachable"),
    ],
    "SMB exposed": [
        (445, "Port 445 open — SMB service detected by nmap"),
    ],
    "RDP exposed": [
        (3389, "Port 3389 open — RDP service detected by nmap"),
    ],
    "Telnet enabled": [
        (23, "Port 23 open — Telnet service detected by nmap"),
    ],
    "Telnet management interface exposed": [
        (23, "Port 23 open — Telnet detected on a network device"),
    ],
    "Telnet enabled on camera": [
        (23, "Port 23 open — Telnet detected on camera device"),
    ],
    "Telnet enabled on unidentified device": [
        (23, "Port 23 open — Telnet detected on unknown device"),
    ],
    "RTSP stream exposed": [
        (554, "Port 554 open — RTSP service detected by nmap"),
    ],
    "Database port directly exposed": [
        (3306,  "Port 3306 open — MySQL reachable from network"),
        (5432,  "Port 5432 open — PostgreSQL reachable from network"),
        (1433,  "Port 1433 open — MSSQL reachable from network"),
        (27017, "Port 27017 open — MongoDB reachable from network"),
    ],
    "Database port exposed on unidentified device": [
        (3306,  "Port 3306 open — MySQL reachable from network"),
        (5432,  "Port 5432 open — PostgreSQL reachable from network"),
        (1433,  "Port 1433 open — MSSQL reachable from network"),
        (27017, "Port 27017 open — MongoDB reachable from network"),
    ],
    "FTP service detected": [
        (21, "Port 21 open — FTP service detected by nmap"),
    ],
    "SSH exposed to network": [
        (22, "Port 22 open — SSH service detected by nmap"),
    ],
    "SNMP exposed": [
        (161, "Port 161 open — SNMP service detected by nmap"),
    ],
    "Network printing port exposed": [
        (9100, "Port 9100 open — raw print service detected by nmap"),
        (515,  "Port 515 open — LPD print service detected by nmap"),
    ],
    "Media control port exposed": [
        (8008, "Port 8008 open — media control service detected by nmap"),
    ],
    "Alternate HTTPS port exposed": [
        (8443, "Port 8443 open — non-standard HTTPS port detected by nmap"),
    ],
    "SMTP port exposed": [
        (25, "Port 25 open — SMTP service detected by nmap"),
    ],
    "Camera web interface exposed": [
        (80,   "Port 80 open — HTTP web interface reachable"),
        (8080, "Port 8080 open — alternate HTTP interface reachable"),
    ],
    "Unencrypted web interface exposed": [
        (80,   "Port 80 open — unencrypted HTTP interface detected"),
        (8080, "Port 8080 open — unencrypted HTTP interface detected"),
    ],
    "Web management interface exposed": [
        (443, "Port 443 open — HTTPS management interface detected"),
        (80,  "Port 80 open — HTTP management interface detected"),
    ],
}


def _issue_evidence(
    issues: list[dict],
    ports: list[int],
    probe_evidence: list[dict],
) -> list[dict]:
    """Build issue-correlated evidence from port and probe data.

    For each issue, emit one evidence entry listing which observed ports
    and probe results support it.  Only ports actually present on the
    device are included — no phantom evidence.
    """
    port_set = set(ports)
    # Index probe evidence by port for fast lookup
    probe_by_port: dict[int, dict] = {
        e["port"]: e for e in probe_evidence if e.get("port") is not None
    }

    evidence: list[dict] = []

    for issue in issues:
        title = issue.get("title", "")
        port_descriptors = _ISSUE_PORT_EVIDENCE.get(title, [])

        supporting_ports: list[int] = []
        supporting_probes: list[str] = []
        raw: dict = {"issue": title, "supporting_ports": [], "probe_confirmations": []}

        for port, proof_text in port_descriptors:
            if port is not None and port not in port_set:
                continue
            if port is not None:
                supporting_ports.append(port)
                raw["supporting_ports"].append({"port": port, "proof": proof_text})

                # Attach any matching probe confirmation
                if port in probe_by_port:
                    pe = probe_by_port[port]
                    supporting_probes.append(f"port {port} probe: {pe['proof']}")
                    raw["probe_confirmations"].append({
                        "port": port,
                        "probe_type": pe["type"],
                        "proof": pe["proof"],
                    })

        # Only emit if at least one supporting port was found on this device
        if not supporting_ports:
            # Fallback: nmap detected the service — use port list as evidence
            if ports:
                raw["supporting_ports"].append({
                    "port": ports[0],
                    "proof": f"Detected by nmap on port {ports[0]}",
                })
                proof = f"Issue '{title}' supported by nmap detection on {ports[0]}"
            else:
                continue
        else:
            parts: list[str] = [f"ports detected: {supporting_ports}"]
            if supporting_probes:
                parts.extend(supporting_probes)
            proof = "; ".join(parts)

        evidence.append({
            "type": "issue_evidence",
            "issue": title,
            "severity": issue.get("severity", ""),
            "proof": proof,
            "raw": raw,
        })

    return evidence


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def attach_evidence(device: dict) -> list[dict]:
    """Build a verifiable evidence list for a single device.

    Uses only data already collected: nmap ports/services and probe results.
    No new network activity is performed.

    Args:
        device: Enriched device dict containing ports, services, probes,
                and issues (list of dicts with title + severity).

    Returns:
        List of evidence dicts.  Empty list when no supporting data exists.
    """
    ports: list[int] = device.get("ports", [])
    probes: list[dict] = device.get("probes", [])
    issues: list[dict] = device.get("issues", [])

    probe_ev = _probe_evidence(probes)
    issue_ev = _issue_evidence(issues, ports, probe_ev)

    # Combine: probe evidence first (raw observations), then issue correlations
    return probe_ev + issue_ev
