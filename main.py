"""CLI entry point for the NetSure network scanner."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any

from risk_engine import calculate_risk
from scanner import DEFAULT_SCAN_TIMEOUT, ScanMode, scan_network

# Logs/errors → stderr; final report → stdout.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)


def build_report(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach a risk level to each scanned device.

    Args:
        devices: Raw scan output from scan_network().

    Returns:
        List of dicts with ip, open_ports, services, and risk fields.
    """
    return [
        {
            "ip": d["ip"],
            "open_ports": d["open_ports"],
            "services": d["services"],
            "risk": calculate_risk(d["open_ports"]),
        }
        for d in devices
    ]


def print_report(report: list[dict[str, Any]]) -> None:
    """Write the final report to stdout as newline-delimited JSON records.

    One JSON object per host ensures strict, parseable output for API consumers.

    Args:
        report: Output of build_report().
    """
    for entry in report:
        sys.stdout.write(json.dumps(entry, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments.

    Args:
        argv: Argument list (defaults to sys.argv[1:]).

    Returns:
        Parsed namespace with cidr, timeout, and mode attributes.
    """
    parser = argparse.ArgumentParser(
        prog="netsure",
        description="Scan a network CIDR and report open ports with risk levels.",
    )
    parser.add_argument(
        "--cidr",
        required=True,
        metavar="NETWORK",
        help="Target network in CIDR notation, e.g. 192.168.1.0/24",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_SCAN_TIMEOUT,
        metavar="SECONDS",
        help=f"Scan timeout in seconds (default: {DEFAULT_SCAN_TIMEOUT}, env: SCAN_TIMEOUT)",
    )
    parser.add_argument(
        "--mode",
        choices=["fast", "full"],
        default="full",
        help="fast: port discovery only; full: includes service detection (default: full)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Orchestrate scan and reporting.

    Args:
        argv: Optional argument list for testing; defaults to sys.argv[1:].

    Returns:
        Exit code (0 = success, 1 = error).
    """
    args = parse_args(argv)
    mode: ScanMode = args.mode  # type: ignore[assignment]

    logger.info("NetSure starting — cidr=%s timeout=%ds mode=%s", args.cidr, args.timeout, mode)

    try:
        devices = scan_network(args.cidr, timeout=args.timeout, mode=mode)
    except ValueError as exc:
        logger.error("Invalid input: %s", exc)
        return 1
    except TimeoutError as exc:
        logger.error("Scan timed out: %s", exc)
        return 1
    except RuntimeError as exc:
        logger.error("Scan failed: %s", exc)
        return 1

    if not devices:
        logger.info("No hosts with open ports found in %s", args.cidr)
        return 0

    report = build_report(devices)
    print_report(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
