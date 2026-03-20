"""Router Fingerprinting Engine.

Identifies router brand and model from probe data using multi-signal scoring.
No external APIs, no ML — deterministic rule-based matching only.

Public API
----------
fingerprint_router(ip, ports, services, probes) -> dict
    Returns {"brand": str | None, "model": str | None, "confidence": float}
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Signal weights
# ---------------------------------------------------------------------------

_W_TITLE  = 0.5   # HTML page title — strongest signal
_W_SERVER = 0.3   # HTTP Server header
_W_PORT   = 0.3   # Port presence
_W_IP     = 0.1   # IP address pattern — weakest signal

_MIN_CONFIDENCE = 0.4  # below this → return None brand


# ---------------------------------------------------------------------------
# Title matching rules
# (pattern, brand, model_pattern_or_None)
# Evaluated in order; first match wins per brand accumulation.
# ---------------------------------------------------------------------------

_TITLE_RULES: list[tuple[str, str, str | None]] = [
    # TP-Link
    (r"(?i)tp-?link",                      "TP-Link",  None),
    (r"(?i)tl-\w+",                        "TP-Link",  r"(?i)(TL-[\w]+)"),
    (r"(?i)archer\s*[\w]+",                "TP-Link",  r"(?i)(Archer\s*[\w]+)"),
    (r"(?i)deco\s*[\w]+",                  "TP-Link",  r"(?i)(Deco\s*[\w]+)"),
    # Netgear
    (r"(?i)netgear",                        "Netgear",  None),
    (r"(?i)nighthawk",                      "Netgear",  r"(?i)(Nighthawk\s*[\w-]+)"),
    (r"(?i)orbi",                           "Netgear",  r"(?i)(Orbi\s*[\w-]*)"),
    (r"(?i)r[67]\d{3}",                     "Netgear",  r"(?i)(R[67]\d{3})"),
    # D-Link
    (r"(?i)d-?link",                        "D-Link",   None),
    (r"(?i)dir-\d+",                        "D-Link",   r"(?i)(DIR-\d+)"),
    # MikroTik
    (r"(?i)mikrotik",                       "MikroTik", None),
    (r"(?i)routeros",                       "MikroTik", None),
    (r"(?i)rb\d+",                          "MikroTik", r"(?i)(RB[\w]+)"),
    (r"(?i)hap\s*[\w-]+",                   "MikroTik", r"(?i)(hAP\s*[\w-]*)"),
    # Asus
    (r"(?i)asus",                           "Asus",     None),
    (r"(?i)rt-\w+",                         "Asus",     r"(?i)(RT-[\w]+)"),
    (r"(?i)aimesh",                         "Asus",     None),
    # Linksys
    (r"(?i)linksys",                        "Linksys",  None),
    (r"(?i)wrt\d+",                         "Linksys",  r"(?i)(WRT[\w]+)"),
    (r"(?i)velop",                          "Linksys",  r"(?i)(Velop\s*[\w-]*)"),
    # Huawei
    (r"(?i)huawei",                         "Huawei",   None),
    (r"(?i)hg\d+",                          "Huawei",   r"(?i)(HG\d+[\w]*)"),
    (r"(?i)b\d{3}",                         "Huawei",   r"(?i)(B\d{3}[\w]*)"),
    # Xiaomi / Mi
    (r"(?i)xiaomi|mi\s*router|miwifi",      "Xiaomi",   None),
    (r"(?i)ax\d{4}",                        "Xiaomi",   r"(?i)(AX\d{4}[\w]*)"),
    # Ubiquiti
    (r"(?i)ubiquiti|ubnt|unifi|edgeos",     "Ubiquiti", None),
    (r"(?i)edgerouter",                     "Ubiquiti", r"(?i)(EdgeRouter\s*[\w-]*)"),
    (r"(?i)usg",                            "Ubiquiti", r"(?i)(USG[\w-]*)"),
    # Cisco
    (r"(?i)cisco",                          "Cisco",    None),
    (r"(?i)rv\d{3}",                        "Cisco",    r"(?i)(RV\d{3}[\w]*)"),
    # Fritz!Box
    (r"(?i)fritz.?box|avm",                 "AVM",      r"(?i)(FRITZ!Box\s*[\w]+)"),
    # OpenWrt / DD-WRT / Tomato (firmware, not brand — brand stays None)
    (r"(?i)openwrt",                        "OpenWrt",  None),
    (r"(?i)dd-?wrt",                        "DD-WRT",   None),
    # Zyxel
    (r"(?i)zyxel",                          "Zyxel",    None),
    (r"(?i)nbg\d+|vmg\d+",                 "Zyxel",    r"(?i)((?:NBG|VMG)\d+[\w]*)"),
    # Tenda
    (r"(?i)tenda",                          "Tenda",    None),
    # GL.iNet
    (r"(?i)gl[.-]?inet|gl[.-]?\w+\s*router", "GL.iNet", None),
]


# ---------------------------------------------------------------------------
# Server header matching rules
# (pattern, brand)
# ---------------------------------------------------------------------------

_SERVER_RULES: list[tuple[str, str]] = [
    (r"(?i)mikrotik",          "MikroTik"),
    (r"(?i)routeros",          "MikroTik"),
    (r"(?i)uhttpd",            "OpenWrt"),   # OpenWrt default HTTP server
    (r"(?i)mini_httpd",        "D-Link"),    # common on D-Link
    (r"(?i)GoAhead",           "D-Link"),    # common on D-Link / Tenda
    (r"(?i)lighttpd",          "TP-Link"),   # TP-Link and many embedded routers
    (r"(?i)Boa",               "Asus"),      # Asus and other embedded
    (r"(?i)RomPager",          "Huawei"),    # Huawei/ZTE CPE firmware
    (r"(?i)ZyXEL",             "Zyxel"),
    (r"(?i)FRITZ",             "AVM"),
    (r"(?i)cisco",             "Cisco"),
    (r"(?i)linksys",           "Linksys"),
    (r"(?i)netgear",           "Netgear"),
    (r"(?i)asus",              "Asus"),
    (r"(?i)tenda",             "Tenda"),
    (r"(?i)GL[-.]iNet",        "GL.iNet"),
]


# ---------------------------------------------------------------------------
# Port → brand mapping
# ---------------------------------------------------------------------------

_PORT_RULES: list[tuple[int, str]] = [
    (8291,  "MikroTik"),   # Winbox management port
    (8728,  "MikroTik"),   # API port
    (8729,  "MikroTik"),   # API-SSL port
    (37215, "Huawei"),     # TR-069 / HGW management
    (7547,  None),         # TR-069 ISP management — generic, no brand
    (4567,  "Zyxel"),      # Zyxel management
    (4664,  "Linksys"),    # Linksys admin
]


# ---------------------------------------------------------------------------
# IP pattern → brand
# ---------------------------------------------------------------------------

_IP_RULES: list[tuple[str, str]] = [
    (r"^192\.168\.31\.",   "Xiaomi"),
    (r"^192\.168\.10\.",   "Huawei"),
    (r"^192\.168\.8\.",    "Huawei"),
    (r"^10\.0\.0\.",       "Apple"),     # AirPort default
    (r"^192\.168\.15\.",   "Netgear"),
    (r"^192\.168\.16\.",   "Tenda"),
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_title(probes: list[dict]) -> str:
    """Return the first non-empty page title found across HTTP probes."""
    for p in probes:
        if p.get("probe_type") in ("http", "https"):
            t = (p.get("title") or "").strip()
            if t:
                return t
    return ""


def _extract_server(probes: list[dict]) -> str:
    """Return the first non-empty Server header value across probes."""
    for p in probes:
        if p.get("probe_type") in ("http", "https"):
            s = (p.get("server") or "").strip()
            if s:
                return s
    return ""


def _extract_banners(probes: list[dict]) -> list[str]:
    """Return all non-empty banner strings."""
    return [
        (p.get("banner") or "").strip()
        for p in probes
        if p.get("probe_type") == "banner" and p.get("banner")
    ]


def _match_model(text: str, pattern: str | None) -> str | None:
    """Extract model substring from *text* using *pattern*, or return None."""
    if not pattern or not text:
        return None
    m = re.search(pattern, text)
    return m.group(1).strip() if m else None


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _score_title(title: str) -> dict[str, tuple[float, str | None]]:
    """Return {brand: (score, model)} from title matching."""
    results: dict[str, tuple[float, str | None]] = {}
    for pattern, brand, model_pattern in _TITLE_RULES:
        if re.search(pattern, title):
            model = _match_model(title, model_pattern)
            current = results.get(brand, (0.0, None))
            # Keep best model (non-None preferred), accumulate score once per brand
            if brand not in results:
                results[brand] = (_W_TITLE, model)
            else:
                # refine model if better one found
                existing_model = current[1]
                results[brand] = (current[0], model if model else existing_model)
    return results


def _score_server(server: str, banners: list[str]) -> dict[str, float]:
    """Return {brand: score} from server header and banner matching."""
    results: dict[str, float] = {}
    texts = [server] + banners
    for text in texts:
        if not text:
            continue
        for pattern, brand in _SERVER_RULES:
            if re.search(pattern, text):
                results[brand] = results.get(brand, 0.0) + _W_SERVER
    return results


def _score_ports(ports: list[int]) -> dict[str, float]:
    """Return {brand: score} from port presence."""
    results: dict[str, float] = {}
    for port, brand in _PORT_RULES:
        if brand and port in ports:
            results[brand] = results.get(brand, 0.0) + _W_PORT
    return results


def _score_ip(ip: str) -> dict[str, float]:
    """Return {brand: score} from IP pattern matching."""
    results: dict[str, float] = {}
    for pattern, brand in _IP_RULES:
        if re.match(pattern, ip):
            results[brand] = results.get(brand, 0.0) + _W_IP
    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def fingerprint_router(
    ip: str,
    ports: list[int],
    services: list[str],
    probes: list[dict],
) -> dict:
    """Identify router brand and model from multi-signal probe data.

    Combines title, server header, port, and IP pattern signals into a
    weighted score per brand.  Returns the highest-scoring brand if its
    confidence meets the minimum threshold.

    Args:
        ip:       Device IP address.
        ports:    Open port numbers from nmap.
        services: Service name strings parallel to ports.
        probes:   Probe result dicts from probe_engine.

    Returns:
        Dict with keys:
            brand      (str | None)  — detected brand or None if unknown
            model      (str | None)  — detected model string or None
            confidence (float)       — 0.0–1.0 detection confidence
    """
    title   = _extract_title(probes)
    server  = _extract_server(probes)
    banners = _extract_banners(probes)

    # Accumulate scores per brand
    combined: dict[str, float] = {}
    models:   dict[str, str | None] = {}

    # Title signals (also carries model extraction)
    title_scores = _score_title(title)
    for brand, (score, model) in title_scores.items():
        combined[brand] = combined.get(brand, 0.0) + score
        if model:
            models[brand] = model

    # Server + banner signals
    for brand, score in _score_server(server, banners).items():
        combined[brand] = combined.get(brand, 0.0) + score

    # Port signals
    for brand, score in _score_ports(ports).items():
        combined[brand] = combined.get(brand, 0.0) + score

    # IP pattern signals
    for brand, score in _score_ip(ip).items():
        combined[brand] = combined.get(brand, 0.0) + score

    if not combined:
        return {"brand": None, "model": None, "confidence": 0.0}

    # Pick highest-scoring brand
    best_brand = max(combined, key=lambda b: combined[b])
    raw_score  = combined[best_brand]
    confidence = min(1.0, round(raw_score, 3))

    if confidence < _MIN_CONFIDENCE:
        return {"brand": None, "model": None, "confidence": confidence}

    return {
        "brand":      best_brand,
        "model":      models.get(best_brand),
        "confidence": confidence,
    }
