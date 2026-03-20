"""Network scanning utilities."""

from __future__ import annotations

import ipaddress
import logging
import os
from typing import Any, Literal

import nmap

logger = logging.getLogger(__name__)

DEFAULT_SCAN_TIMEOUT: int = int(os.environ.get("SCAN_TIMEOUT", 20))

ScanMode = Literal["fast", "full"]

_FAST_PORTS = "21,22,23,80,443,445,554,3389,8080,8443"
_FAST_MAX_HOSTS = 20

_NMAP_ARGS: dict[ScanMode, str] = {
    "fast": f"-T4 --open -p {_FAST_PORTS} --host-timeout 1s",
    "full": "-sV -T4 --open",
}


def scan_network(
    cidr: str,
    timeout: int = DEFAULT_SCAN_TIMEOUT,
    mode: ScanMode = "full",
) -> tuple[list[dict[str, Any]], bool]:
    """Scan a CIDR range and return open ports and detected services per host.

    Args:
        cidr: Target network in CIDR notation (e.g. "192.168.1.0/24").
        timeout: Maximum seconds to allow the scan to run.
        mode: "fast" skips service detection; "full" enables it.

    Returns:
        Tuple of (devices, is_partial) where devices is a list of dicts with
        keys: ip, open_ports, services, and is_partial is True when nmap hit
        its timeout and results may be incomplete.

    Raises:
        ValueError: If the CIDR is not valid.
        RuntimeError: If nmap fails for any other reason.
    """
    _validate_cidr(cidr)

    nmap_args = _NMAP_ARGS.get(mode, _NMAP_ARGS["full"])

    # Fast mode: cap to first _FAST_MAX_HOSTS to bound scan time.
    scan_target = cidr
    if mode == "fast":
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = list(network.hosts())
        if len(hosts) > _FAST_MAX_HOSTS:
            scan_target = " ".join(str(h) for h in hosts[:_FAST_MAX_HOSTS])
            logger.info("Fast mode: capped target to %d hosts", _FAST_MAX_HOSTS)

    logger.info("Starting %s scan of %s (timeout=%ds, args='%s')", mode, scan_target, timeout, nmap_args)

    scanner = nmap.PortScanner()

    try:
        scanner.scan(hosts=scan_target, arguments=nmap_args, timeout=timeout)
    except nmap.PortScannerTimeout:
        # nmap hit its timeout — parse whatever it collected before stopping.
        partial = _parse_scan_results(scanner)
        logger.warning(
            "nmap timed out after %ds for %s — returning %d partial result(s)",
            timeout, cidr, len(partial),
        )
        return partial, True
    except nmap.PortScannerError as exc:
        raise RuntimeError(f"nmap error while scanning {cidr}: {exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"Unexpected scanner failure for {cidr}: {exc}") from exc

    devices = _parse_scan_results(scanner)
    logger.info("Scan complete. %d host(s) with open ports found.", len(devices))
    return devices, False


def _parse_scan_results(scanner: nmap.PortScanner) -> list[dict[str, Any]]:
    """Extract open-port data from a completed nmap scan.

    Args:
        scanner: A PortScanner instance that has already run scan().

    Returns:
        Sorted list of host dicts with ip, open_ports, and services.
    """
    devices: list[dict[str, Any]] = []

    for host in sorted(scanner.all_hosts(), key=ipaddress.ip_address):
        open_ports: list[int] = []
        services: list[str] = []

        for protocol in sorted(scanner[host].all_protocols()):
            for port in sorted(scanner[host][protocol].keys()):
                port_data = scanner[host][protocol][port]
                if port_data.get("state") != "open":
                    continue
                open_ports.append(port)
                services.append(port_data.get("name") or "unknown")

        if open_ports:
            devices.append({"ip": host, "open_ports": open_ports, "services": services})

    return devices


def _validate_cidr(cidr: str) -> None:
    """Raise ValueError if cidr is not a valid network address.

    Args:
        cidr: String to validate as a CIDR network.

    Raises:
        ValueError: If the string is not a valid CIDR network.
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR network: {cidr!r}") from exc
