"""Service layer: orchestrates scanning, risk scoring, and persistence.

This is the single boundary between the HTTP layer and the core modules
(scanner, risk_engine, intelligence_engine, database). Routers must import
only from here.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import subprocess
import time

from fastapi.concurrency import run_in_threadpool
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from exceptions import NotFoundError
from exposure_engine import _empty_report as _empty_exposure_report
from exposure_engine import rebuild_finding_message, run_exposure_check
from intelligence_engine import analyze_device, infer_device_role
from models import Device, Scan
from network_engine import (
    build_network_graph,
    generate_attack_paths,
    generate_impact_statements,
    generate_top_actions,
    rank_network_risks,
)
from evidence_engine import attach_evidence
from impact_engine import simulate_attack_impact
from remediation_engine import generate_remediation_plan
from probe_engine import probe_device
from router_fingerprint import fingerprint_router
from user_response import build_user_response
from risk_engine import calculate_risk
from scanner import scan_network
from schemas import ScanMode, ScanResponse, ScanResult, ScanSummary, SecurityIssue

logger = logging.getLogger(__name__)

# Hard ceiling on scan wall-clock time. When exceeded, return partial results
# rather than raising an error to the UI.
_HARD_SCAN_TIMEOUT = 10

# nmap's own timeout is capped 2 seconds below the asyncio hard limit so that
# nmap always finishes (and can return partial data) before asyncio kills the thread.
_NMAP_TIMEOUT_HEADROOM = 2

# Common ports probed on a gateway fallback device when no ports were discovered.
_GATEWAY_FALLBACK_PORTS: list[int] = [80, 443]
_GATEWAY_FALLBACK_SERVICES: list[str] = ["http", "https"]

# ---------------------------------------------------------------------------
# Unified risk engine — ordering, floors, and flip-flop prevention
# ---------------------------------------------------------------------------

# Canonical ordering for risk level comparison (higher value = higher risk).
# "HIGH RISK — ACTIVE EXPOSURE" is the highest-specificity label produced by
# _build_status when lateral movement is confirmed; it must rank above plain
# "HIGH RISK" so _apply_risk_floor never silently downgrades it.
_RISK_ORDER: dict[str, int] = {
    "HIGH RISK — ACTIVE EXPOSURE": 4,
    "HIGH RISK":                   3,
    "MEDIUM RISK":                 2,
    "LOW RISK":                    1,
    "SAFE":                        0,
}

# Maps exposure tiers to the minimum risk level they mandate.
_EXPOSURE_RISK_FLOOR: dict[str, str] = {
    "CONFIRMED": "HIGH RISK",
    "LIKELY":    "HIGH RISK",
    "POSSIBLE":  "MEDIUM RISK",
    "NONE":      "SAFE",      # no forced floor
}

# Module-level cache: cidr → last emitted risk status.
# Prevents a single scan from flipping HIGH → SAFE.
_risk_cache: dict[str, str] = {}


def _risk_rank(status: str) -> int:
    """Return the numeric rank of a risk status string (case-insensitive)."""
    return _RISK_ORDER.get(status.upper() if status else "", 0)


def _elevate_risk(current: str, minimum: str) -> str:
    """Return *current* or *minimum*, whichever is higher."""
    return current if _risk_rank(current) >= _risk_rank(minimum) else minimum


def _apply_risk_floor(user: dict, floor: str, reason: str) -> None:
    """Raise user['answer']['status'] to *floor* if it is currently below it.

    Mutates *user* in place.  *reason* is logged for observability.
    """
    current = user.get("answer", {}).get("status", "SAFE")
    elevated = _elevate_risk(current, floor)
    if elevated != current:
        logger.info("Risk elevated %s → %s (%s)", current, elevated, reason)
        user["answer"]["status"] = elevated
        # Update message to match the new status so the wording never contradicts it.
        if elevated == "MEDIUM RISK" and current == "SAFE":
            user["answer"]["message"] = (
                "We confirmed your network is active and found signals that need attention. "
                "A full review may reveal additional risks."
            )
        elif elevated == "HIGH RISK" and _risk_rank(current) < _risk_rank("HIGH RISK"):
            user["answer"]["message"] = (
                "We detected that a device on your network may be reachable from the internet — "
                "someone outside your home or office could potentially access your network."
            )


def _stabilize_risk(cidr: str, new_status: str) -> str:
    """Prevent a sudden HIGH → SAFE flip for the same network.

    If the previous scan of *cidr* was HIGH RISK and this scan would produce
    SAFE or LOW RISK, return MEDIUM RISK instead.  Any other transition is
    returned unchanged.
    """
    last = _risk_cache.get(cidr, "")
    if _risk_rank(last) >= _risk_rank("HIGH RISK") and _risk_rank(new_status) < _risk_rank("MEDIUM RISK"):
        logger.info(
            "Stabilizing %s risk: %s → MEDIUM RISK (last scan was %s)",
            cidr, new_status, last,
        )
        return "MEDIUM RISK"
    return new_status


# Injected when a partial-mode device has no issues at all — ensures every
# response has at least one actionable finding.
_MINIMUM_PARTIAL_ISSUE = SecurityIssue(
    title="Network Device Detected",
    severity="LOW",
    description="A network device was confirmed active on your network.",
    recommendation=(
        "Review this device's configuration, change any default passwords, "
        "and ensure its firmware is up to date."
    ),
)


async def run_scan(
    cidr: str,
    timeout: int,
    mode: ScanMode,
    db: AsyncSession,
) -> ScanResponse:
    """Scan *cidr*, persist the results, and return a structured response.

    scan_network() is CPU/IO-bound (nmap subprocess), so it runs in a
    thread-pool to avoid blocking the event loop.

    Device results are built from the in-memory device_rows list — no
    extra DB round-trip is needed after the commit.  Security intelligence
    is computed after the scan and included in the response, but is not
    persisted to the database.

    Args:
        cidr: Target network in CIDR notation.
        timeout: Maximum seconds to allow nmap to run.
        mode: "fast" (port discovery) or "full" (includes service detection).
        db: Async database session (injected by FastAPI).

    Returns:
        ScanResponse containing the new scan_id and all discovered devices
        with full security intelligence annotations.

    Raises:
        ValueError: Propagated from the scanner for an invalid CIDR.

    Never raises TimeoutError or RuntimeError — those are caught internally
    and converted to a partial result so the UI always receives a valid response.
    """
    logger.info("Scan requested — cidr=%s timeout=%ds mode=%s", cidr, timeout, mode)

    _t0 = time.perf_counter()
    scan_status = "complete"

    # Cap nmap's own timeout below the asyncio hard limit so nmap finishes
    # cleanly and can hand back partial results rather than being killed mid-run.
    nmap_timeout = min(timeout, _HARD_SCAN_TIMEOUT - _NMAP_TIMEOUT_HEADROOM)

    try:
        raw_devices, scan_partial = await asyncio.wait_for(
            run_in_threadpool(scan_network, cidr, nmap_timeout, mode),
            timeout=_HARD_SCAN_TIMEOUT,
        )
        if scan_partial:
            scan_status = "partial"
    except asyncio.TimeoutError:
        # asyncio hard limit fired before nmap could return anything.
        logger.warning(
            "Scan hit asyncio hard limit (%ds) for %s — no partial data available",
            _HARD_SCAN_TIMEOUT,
            cidr,
        )
        raw_devices = []
        scan_status = "partial"
    except RuntimeError as exc:
        logger.warning("Scanner error for %s (%s) — returning partial results", cidr, exc)
        raw_devices = []
        scan_status = "partial"

    # ── Gateway fallback — guarantee at least one real device ─────────────
    # When a partial scan yields nothing, discover the default gateway and use
    # it as the seed device so every response has real, provable network data.
    if not raw_devices and scan_status == "partial":
        gateway_ip = await run_in_threadpool(_get_default_gateway)
        if not gateway_ip:
            gateway_ip = _infer_gateway_from_cidr(cidr)
        logger.info("Using gateway fallback device: %s", gateway_ip)
        raw_devices = [{
            "ip": gateway_ip,
            "open_ports": _GATEWAY_FALLBACK_PORTS,
            "services": _GATEWAY_FALLBACK_SERVICES,
        }]

    duration_ms = round((time.perf_counter() - _t0) * 1000)

    # ── Exposure check — started NOW so it runs concurrently with enrichment ──
    # run_in_executor submits to the thread pool immediately; the thread runs
    # in parallel while the synchronous enrichment code below occupies the
    # event loop.  We use raw_devices (ip + open_ports) for port correlation;
    # device_type labels are patched in once enrichment has completed.
    _loop = asyncio.get_running_loop()
    _exposure_future = _loop.run_in_executor(None, run_exposure_check, raw_devices)

    # ── Persist ────────────────────────────────────────────────────────────
    scan = Scan(cidr=cidr, mode=mode)
    db.add(scan)

    device_rows = [
        Device(
            scan_id=scan.id,
            ip=d["ip"],
            ports=d["open_ports"],
            services=d["services"],
            risk=calculate_risk(d["open_ports"]),
        )
        for d in raw_devices
    ]
    db.add_all(device_rows)
    await db.commit()

    # ── Probe services + build response with intelligence annotations ──────
    # In partial mode probe only the first device (gateway or first discovered)
    # to get real, evidence-backed data without burning more time.
    results = []
    for i, dev in enumerate(device_rows):
        should_probe = scan_status == "complete" or i == 0
        probes = probe_device(dev.ip, dev.ports, dev.services) if should_probe else []
        results.append(_enrich(dev.ip, dev.ports, dev.services, dev.risk, probes))

    # ── Minimum output guarantee ───────────────────────────────────────────
    # Partial scans must always have at least one issue so the response has
    # a concrete, actionable finding rather than generic empty output.
    if scan_status == "partial":
        for result in results:
            if not result.issues:
                result.issues = [_MINIMUM_PARTIAL_ISSUE]
            if result.primary_issue is None:
                result.primary_issue = result.issues[0]

    # ── Network intelligence ───────────────────────────────────────────────
    device_dicts = [_result_to_dict(r) for r in results]
    attack_paths      = generate_attack_paths(device_dicts)
    impact_summary    = generate_impact_statements(device_dicts)
    top_risks         = rank_network_risks(device_dicts)
    top_actions       = generate_top_actions(device_dicts)
    remediation_plan  = generate_remediation_plan(device_dicts)
    attack_simulation = simulate_attack_impact(device_dicts)

    details = {
        "devices":           [r.model_dump() for r in results],
        "attack_paths":      attack_paths,
        "impact_summary":    impact_summary,
        "top_risks":         top_risks,
        "top_actions":       top_actions,
        "remediation_plan":  remediation_plan,
        "attack_simulation": attack_simulation,
    }
    device_probes = {r.ip: r.probes for r in results}
    user = build_user_response({
        "attack_simulation": attack_simulation,
        "remediation_plan":  remediation_plan,
        "device_dicts":      device_dicts,
        "device_probes":     device_probes,
        "details":           details,
    })

    # ── Collect exposure result ────────────────────────────────────────────
    # The thread has been running since before enrichment started.  Await the
    # future with an 8 s cap so a slow external probe never stalls the response.
    try:
        internet_exposure = await asyncio.wait_for(_exposure_future, timeout=8.0)
        # Patch enriched device_type into findings so labels name the real device.
        type_by_ip = {r.ip: r.device_type for r in results}
        for finding in internet_exposure.get("exposed_devices", []):
            device_ip = finding.get("device_ip")
            if device_ip and device_ip in type_by_ip:
                finding["device_type"] = type_by_ip[device_ip]
                finding["message"] = rebuild_finding_message(finding)
    except (asyncio.TimeoutError, Exception) as exc:
        logger.warning("Exposure check did not complete in time: %s", exc)
        internet_exposure = _empty_exposure_report("Exposure check timed out.")

    # ── Confidence cap for partial scans ──────────────────────────────────
    # A partial scan cannot produce HIGH-confidence findings — cap to MEDIUM.
    if scan_status == "partial" and user.get("confidence") == "HIGH":
        user["confidence"] = "MEDIUM"

    # ── Unified risk decision ──────────────────────────────────────────────
    # Apply risk floors in ascending priority order so the highest-priority
    # rule always wins.

    # 1. Partial scan — we cannot assert SAFE if we didn't finish.
    if scan_status == "partial":
        _apply_risk_floor(user, "MEDIUM RISK", "partial scan")

    # 2. Issues present — any detected issue means the network is not SAFE.
    has_issues = any(r.issues for r in results)
    if has_issues:
        _apply_risk_floor(user, "MEDIUM RISK", "issues detected")

    # 3. Exposure tier — CONFIRMED/LIKELY → HIGH; POSSIBLE → MEDIUM floor.
    exposure_level = internet_exposure.get("level", "NONE")
    exposure_floor = _EXPOSURE_RISK_FLOOR.get(exposure_level, "SAFE")
    if exposure_floor != "SAFE":
        _apply_risk_floor(user, exposure_floor, f"exposure level={exposure_level}")

    # 4. Stabilization — prevent a single-scan HIGH → SAFE flip.
    final_status = user["answer"].get("status", "SAFE")
    final_status = _stabilize_risk(cidr, final_status)
    user["answer"]["status"] = final_status

    # 5. Store in cache for next scan of this CIDR.
    _risk_cache[cidr] = final_status

    logger.info(
        "Scan persisted — scan_id=%s cidr=%s devices=%d duration=%dms scan_status=%s",
        scan.id,
        cidr,
        len(results),
        duration_ms,
        scan_status,
    )
    return ScanResponse(
        scan_id=scan.id,
        cidr=scan.cidr,
        mode=scan.mode,
        timestamp=scan.timestamp,
        device_count=len(results),
        duration_ms=duration_ms,
        scan_status=scan_status,
        internet_exposure=internet_exposure,
        answer=user["answer"],
        priority=user["priority"],
        confidence=user["confidence"],
        why=user["why"],
        impact=user["impact"],
        business_impact=user["business_impact"],
        attack_path=user["attack_path"],
        fix_now=user["fix_now"],
        proof=user["proof"],
        upgrade_prompt=user["upgrade_prompt"],
        details=details,
    )


async def list_scans(
    db: AsyncSession,
    limit: int = 20,
    offset: int = 0,
) -> list[ScanSummary]:
    """Return a paginated summary of past scans, newest first.

    Device count is computed at the database level via a single aggregation
    query (outerjoin + GROUP BY) — no Python-side len() or per-scan queries.

    Args:
        db: Async database session.
        limit: Maximum number of records to return (applied in SQL).
        offset: Number of records to skip (applied in SQL).

    Returns:
        List of ScanSummary objects ordered by descending timestamp.
    """
    stmt = (
        select(
            Scan.id,
            Scan.cidr,
            Scan.mode,
            Scan.timestamp,
            func.count(Device.id).label("device_count"),
        )
        .outerjoin(Device, Device.scan_id == Scan.id)
        .group_by(Scan.id, Scan.cidr, Scan.mode, Scan.timestamp)
        .order_by(Scan.timestamp.desc())
        .limit(limit)
        .offset(offset)
    )

    rows = (await db.execute(stmt)).all()

    return [
        ScanSummary(
            scan_id=row.id,
            cidr=row.cidr,
            mode=row.mode,
            timestamp=row.timestamp,
            device_count=row.device_count,
        )
        for row in rows
    ]


async def get_scan_by_id(scan_id: str, db: AsyncSession) -> ScanResponse:
    """Fetch a single scan with all its device records.

    Uses selectinload to eagerly load devices in a second query, avoiding
    the N+1 pattern while staying compatible with async sessions.
    Security intelligence is recomputed from persisted port/service data.

    Args:
        scan_id: UUID string of the scan to retrieve.
        db: Async database session.

    Returns:
        ScanResponse with full device list and security intelligence.

    Raises:
        NotFoundError: When no scan with the given ID exists.
    """
    stmt = select(Scan).options(selectinload(Scan.devices)).where(Scan.id == scan_id)
    scan = (await db.execute(stmt)).scalar_one_or_none()

    if scan is None:
        raise NotFoundError(f"Scan '{scan_id}' not found")

    devices = [
        _enrich(dev.ip, dev.ports, dev.services, dev.risk, [])
        for dev in scan.devices
    ]

    device_dicts = [_result_to_dict(d) for d in devices]
    attack_paths = generate_attack_paths(device_dicts)
    impact_summary = generate_impact_statements(device_dicts)
    top_risks = rank_network_risks(device_dicts)
    top_actions = generate_top_actions(device_dicts)
    remediation_plan  = generate_remediation_plan(device_dicts)
    attack_simulation = simulate_attack_impact(device_dicts)

    details = {
        "devices":           [d.model_dump() for d in devices],
        "attack_paths":      attack_paths,
        "impact_summary":    impact_summary,
        "top_risks":         top_risks,
        "top_actions":       top_actions,
        "remediation_plan":  remediation_plan,
        "attack_simulation": attack_simulation,
    }
    user = build_user_response({
        "attack_simulation": attack_simulation,
        "remediation_plan":  remediation_plan,
        "device_dicts":      device_dicts,
        "device_probes":     {},   # probes not stored in DB
        "details":           details,
    })

    return ScanResponse(
        scan_id=scan.id,
        cidr=scan.cidr,
        mode=scan.mode,
        timestamp=scan.timestamp,
        device_count=len(devices),
        answer=user["answer"],
        priority=user["priority"],
        confidence=user["confidence"],
        why=user["why"],
        impact=user["impact"],
        business_impact=user["business_impact"],
        attack_path=user["attack_path"],
        fix_now=user["fix_now"],
        proof=user["proof"],
        upgrade_prompt=user["upgrade_prompt"],
        details=details,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_default_gateway() -> str | None:
    """Return the default gateway IP from the OS routing table, or None.

    Parses `ip route` output looking for the `default via <ip>` entry.
    Returns None on any error so callers can fall back gracefully.
    """
    try:
        output = subprocess.check_output(
            ["ip", "route"],
            timeout=2,
            text=True,
            stderr=subprocess.DEVNULL,
        )
        for line in output.splitlines():
            if line.startswith("default"):
                parts = line.split()
                if "via" in parts:
                    return parts[parts.index("via") + 1]
    except Exception:
        pass
    return None


def _infer_gateway_from_cidr(cidr: str) -> str:
    """Return the first usable host in *cidr* as a best-guess gateway IP."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = list(network.hosts())
        if hosts:
            return str(hosts[0])
    except Exception:
        pass
    return "192.168.1.1"


def _enrich(
    ip: str,
    ports: list[int],
    services: list[str],
    risk: str,
    probes: list[dict],
) -> ScanResult:
    """Attach security intelligence to a raw device record.

    Args:
        ip: Host IP address string.
        ports: Open port numbers.
        services: Service name strings (parallel to ports).
        risk: Pre-computed risk level from risk_engine.
        probes: Probe results from probe_engine.probe_device().

    Returns:
        ScanResult with device_type, configuration, issues, and probes populated.
    """
    intel = analyze_device(ports, services, probes)
    device_type = intel["inferred_device_type"]
    role = infer_device_role(device_type)
    rf = fingerprint_router(ip, ports, services, probes)
    issues_objs = [SecurityIssue(**issue) for issue in intel["issues"]]
    return ScanResult(
        ip=ip,
        ports=ports,
        services=services,
        risk=risk,
        device_type=device_type,
        role=role,
        confidence=intel["confidence"],
        exposure=intel["exposure"],
        configuration=intel["configuration_summary"],
        issues=issues_objs,
        primary_issue=SecurityIssue(**intel["primary_issue"]) if intel["primary_issue"] else None,
        known_exploits=list(intel["known_exploits"]),
        exploit_risk_level=intel["exploit_risk_level"],
        primary_exploit=dict(intel["primary_exploit"]) if intel["primary_exploit"] else None,
        probes=probes,
        evidence=attach_evidence({
            "ports": ports,
            "services": services,
            "probes": probes,
            "issues": [i.model_dump() for i in issues_objs],
        }),
        router_brand=rf["brand"],
        router_model=rf["model"],
        router_confidence=rf["confidence"],
        reasoning=intel["reasoning"],
        lateral_movement=intel["lateral_movement"],
    )


def _result_to_dict(r: ScanResult) -> dict:
    """Flatten a ScanResult into a plain dict for network_engine consumption."""
    return {
        "ip": r.ip,
        "ports": r.ports,
        "role": r.role,
        "device_type": r.device_type,
        "exposure": r.exposure,
        "exploit_risk_level": r.exploit_risk_level,
        "primary_issue": r.primary_issue.model_dump() if r.primary_issue else None,
        "router_brand": r.router_brand,
        "router_model": r.router_model,
        "lateral_movement": r.lateral_movement,
    }


