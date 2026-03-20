"""Risk scoring rules for detected open ports."""

from __future__ import annotations

# Maps a port number to its risk level.
# To add a new rule: insert a port → level entry here; no logic changes needed.
PORT_RISK_RULES: dict[int, str] = {
    23: "HIGH",    # Telnet – plaintext credentials
    445: "HIGH",   # SMB – frequent ransomware vector
    3389: "HIGH",  # RDP – remote desktop, brute-force target
    21: "MEDIUM",  # FTP – plaintext, credential exposure
    22: "MEDIUM",  # SSH – encrypted but brute-force target
    554: "MEDIUM", # RTSP – streaming/camera exposure
}

_RISK_ORDER: dict[str, int] = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
_DEFAULT_RISK = "LOW"


def calculate_risk(ports: list[int]) -> str:
    """Return the highest risk level for the given list of open ports.

    Unknown ports not present in PORT_RISK_RULES default to LOW.

    Args:
        ports: List of open port numbers.

    Returns:
        One of "HIGH", "MEDIUM", or "LOW".
    """
    if not ports:
        return _DEFAULT_RISK

    highest = _DEFAULT_RISK
    for port in ports:
        level = PORT_RISK_RULES.get(port, _DEFAULT_RISK)
        if _RISK_ORDER.get(level, 0) > _RISK_ORDER.get(highest, 0):
            highest = level

    return highest
