"""Device fingerprinting: OS detection, hostname resolution, port scanning, mDNS."""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
import subprocess
import sys
from typing import Any

from netsentinel.config import Settings
from netsentinel.core.models import Device, DeviceType
from netsentinel.core.vendor import lookup_vendor

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Hostname resolution
# ---------------------------------------------------------------------------

def _resolve_hostname_dns(ip: str) -> str | None:
    """Reverse DNS lookup."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def _resolve_hostname_mdns(ip: str) -> str | None:
    """Attempt mDNS/Bonjour hostname resolution."""
    try:
        # Try .local resolution via system resolver
        hostname, _, _ = socket.gethostbyaddr(ip)
        if hostname and ".local" in hostname:
            return hostname
    except Exception:
        pass
    return None


def _resolve_hostname_netbios(ip: str) -> str | None:
    """Attempt NetBIOS name resolution (Windows devices)."""
    try:
        result = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True,
            text=True,
            timeout=3,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if "<00>" in line and "GROUP" not in line:
                return line.split()[0]
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass
    return None


async def resolve_hostname(ip: str) -> str | None:
    """Try multiple hostname resolution methods in order."""
    for resolver in (_resolve_hostname_dns, _resolve_hostname_mdns, _resolve_hostname_netbios):
        try:
            result = await asyncio.to_thread(resolver, ip)
            if result:
                return result
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# OS fingerprinting via TTL
# ---------------------------------------------------------------------------

def _ping_ttl(ip: str) -> int | None:
    """Send a single ping and extract TTL from the response."""
    try:
        if sys.platform == "win32":
            cmd = ["ping", "-n", "1", "-w", "1000", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        for line in result.stdout.splitlines():
            lower = line.lower()
            if "ttl=" in lower:
                idx = lower.index("ttl=")
                rest = lower[idx + 4:]
                ttl_str = ""
                for ch in rest:
                    if ch.isdigit():
                        ttl_str += ch
                    else:
                        break
                if ttl_str:
                    return int(ttl_str)
    except (subprocess.TimeoutExpired, Exception):
        pass
    return None


def _guess_os_from_ttl(ttl: int | None) -> str | None:
    """Guess the OS based on the initial TTL value."""
    if ttl is None:
        return None
    if ttl <= 64:
        return "Linux/macOS/iOS/Android"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Network Equipment"
    return None


async def guess_os(ip: str) -> str | None:
    """Guess the operating system by analyzing ping TTL."""
    ttl = await asyncio.to_thread(_ping_ttl, ip)
    return _guess_os_from_ttl(ttl)


async def guess_os_nmap(ip: str) -> str | None:
    """Use python-nmap for OS detection if available (requires root)."""
    try:
        import nmap
        nm = nmap.PortScanner()
        result = await asyncio.to_thread(
            nm.scan, ip, arguments="-O --osscan-limit", sudo=True
        )
        if ip in nm.all_hosts():
            os_matches = nm[ip].get("osmatch", [])
            if os_matches:
                return os_matches[0].get("name")
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("nmap OS detection failed for %s: %s", ip, exc)
    return None


# ---------------------------------------------------------------------------
# Port scanning
# ---------------------------------------------------------------------------

async def _check_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a TCP port is open."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
        return False


async def scan_ports(ip: str, ports: list[int]) -> list[int]:
    """Quick TCP connect scan on a list of ports."""
    tasks = [_check_port(ip, port) for port in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    open_ports: list[int] = []
    for port, result in zip(ports, results):
        if result is True:
            open_ports.append(port)
    return open_ports


# ---------------------------------------------------------------------------
# mDNS service discovery
# ---------------------------------------------------------------------------

async def discover_mdns_services(ip: str) -> list[str]:
    """Discover mDNS/Bonjour services advertised by the device."""
    services: list[str] = []
    try:
        result = await asyncio.to_thread(
            subprocess.run,
            ["dns-sd", "-B", "_services._dns-sd._udp", "local"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        # Parse service types (this is best-effort)
        for line in result.stdout.splitlines():
            if "_tcp" in line or "_udp" in line:
                parts = line.split()
                for part in parts:
                    if part.startswith("_") and ("._tcp" in part or "._udp" in part):
                        services.append(part)
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass
    return list(set(services))


# ---------------------------------------------------------------------------
# IPv6 neighbor discovery
# ---------------------------------------------------------------------------

async def discover_ipv6(ip: str) -> str | None:
    """Attempt to discover IPv6 address for a device."""
    try:
        # Use the system neighbor table
        if sys.platform == "win32":
            cmd = ["netsh", "interface", "ipv6", "show", "neighbors"]
        else:
            cmd = ["ip", "-6", "neigh", "show"]
        result = await asyncio.to_thread(
            subprocess.run, cmd, capture_output=True, text=True, timeout=3
        )
        # Look for entries that might correspond to this IPv4 host
        # This is heuristic — matching by proximity in the neighbor table
        for line in result.stdout.splitlines():
            if "fe80::" in line.lower():
                parts = line.split()
                if parts:
                    return parts[0]
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass
    return None


# ---------------------------------------------------------------------------
# Device type inference
# ---------------------------------------------------------------------------

_PHONE_VENDORS = {"apple", "samsung", "huawei", "xiaomi", "oneplus", "google", "oppo", "vivo", "motorola", "lg"}
_PRINTER_VENDORS = {"hp", "hewlett", "canon", "epson", "brother", "xerox", "lexmark", "ricoh"}
_TV_VENDORS = {"samsung", "lg", "sony", "vizio", "tcl", "hisense", "roku"}
_IOT_VENDORS = {"espressif", "tuya", "shelly", "sonoff", "tp-link", "ring", "nest", "amazon"}
_CONSOLE_VENDORS = {"sony", "microsoft", "nintendo"}
_ROUTER_VENDORS = {"cisco", "netgear", "tp-link", "asus", "linksys", "ubiquiti", "mikrotik", "arris"}


def infer_device_type(
    vendor: str | None,
    open_ports: list[int],
    os_guess: str | None,
    is_gateway: bool,
    mdns_services: list[str],
) -> DeviceType:
    """Infer the device type from available signals."""
    if is_gateway:
        return DeviceType.ROUTER

    vendor_lower = (vendor or "").lower()

    # Check mDNS service signatures
    service_str = " ".join(mdns_services).lower()
    if "_airplay._tcp" in service_str or "_googlecast._tcp" in service_str:
        return DeviceType.SMART_TV
    if "_printer._tcp" in service_str or "_ipp._tcp" in service_str:
        return DeviceType.PRINTER

    # Port-based hints
    if 62078 in open_ports:  # iPhone lockdownd
        return DeviceType.PHONE
    if 9100 in open_ports or 631 in open_ports:
        return DeviceType.PRINTER

    # Vendor-based hints
    if any(v in vendor_lower for v in _ROUTER_VENDORS):
        if is_gateway:
            return DeviceType.ROUTER
    if any(v in vendor_lower for v in _PRINTER_VENDORS):
        return DeviceType.PRINTER
    if any(v in vendor_lower for v in _TV_VENDORS) and "smart" in vendor_lower.lower():
        return DeviceType.SMART_TV
    if any(v in vendor_lower for v in _IOT_VENDORS):
        return DeviceType.IOT_DEVICE
    if any(v in vendor_lower for v in _CONSOLE_VENDORS) and os_guess == "Network Equipment":
        return DeviceType.GAME_CONSOLE

    # OS-based inference
    if os_guess:
        if "Windows" in os_guess:
            return DeviceType.COMPUTER
        if "Linux" in os_guess or "macOS" in os_guess:
            # Could be phone or computer — check ports
            if 22 in open_ports or 80 in open_ports or 445 in open_ports:
                return DeviceType.COMPUTER
            if any(v in vendor_lower for v in _PHONE_VENDORS):
                return DeviceType.PHONE
            return DeviceType.COMPUTER
        if "Network Equipment" in os_guess:
            return DeviceType.ROUTER

    return DeviceType.UNKNOWN


# ---------------------------------------------------------------------------
# Full fingerprinting pipeline
# ---------------------------------------------------------------------------

async def fingerprint_device(
    raw: dict[str, Any],
    settings: Settings,
    *,
    existing: Device | None = None,
) -> Device:
    """Enrich a raw scan result into a fully fingerprinted Device.

    `raw` should have keys: mac, ipv4, latency_ms, is_gateway.
    `existing` is a previously known Device (for merging history).
    """
    mac: str = raw["mac"]
    ipv4: str = raw["ipv4"]

    # Run independent enrichment tasks concurrently
    vendor_task = asyncio.to_thread(lookup_vendor, mac)
    hostname_task = resolve_hostname(ipv4)
    os_task = guess_os(ipv4)
    ports_task = scan_ports(ipv4, settings.quick_scan_ports)
    ipv6_task = discover_ipv6(ipv4)

    vendor, hostname, os_guess, open_ports, ipv6 = await asyncio.gather(
        vendor_task, hostname_task, os_task, ports_task, ipv6_task,
        return_exceptions=False,
    )

    # Handle exceptions from gather (shouldn't happen with return_exceptions=False,
    # but be defensive)
    if isinstance(vendor, BaseException):
        vendor = None
    if isinstance(hostname, BaseException):
        hostname = None
    if isinstance(os_guess, BaseException):
        os_guess = None
    if isinstance(open_ports, BaseException):
        open_ports = []
    if isinstance(ipv6, BaseException):
        ipv6 = None

    # Try nmap OS detection as enrichment
    if os_guess is None:
        try:
            os_guess = await guess_os_nmap(ipv4)
        except Exception:
            pass

    # Discover mDNS services (quick, best-effort)
    try:
        mdns_services = await discover_mdns_services(ipv4)
    except Exception:
        mdns_services = []

    is_gateway = raw.get("is_gateway", False)

    device_type = infer_device_type(
        vendor=vendor,
        open_ports=open_ports,
        os_guess=os_guess,
        is_gateway=is_gateway,
        mdns_services=mdns_services,
    )

    from netsentinel.core.models import _utcnow

    now = _utcnow()

    if existing:
        return Device(
            mac=mac,
            vendor=vendor or existing.vendor,
            ipv4=ipv4,
            ipv6=ipv6 or existing.ipv6,
            hostname=hostname or existing.hostname,
            custom_name=existing.custom_name,
            device_type=device_type if device_type != DeviceType.UNKNOWN else existing.device_type,
            os_guess=os_guess or existing.os_guess,
            open_ports=open_ports or existing.open_ports,
            mdns_services=mdns_services or existing.mdns_services,
            latency_ms=raw.get("latency_ms"),
            is_gateway=is_gateway or existing.is_gateway,
            is_online=True,
            first_seen=existing.first_seen,
            last_seen=now,
            last_changed=now if ipv4 != existing.ipv4 else existing.last_changed,
            scan_count=existing.scan_count + 1,
            notes=existing.notes,
        )
    else:
        return Device(
            mac=mac,
            vendor=vendor,
            ipv4=ipv4,
            ipv6=ipv6,
            hostname=hostname,
            device_type=device_type,
            os_guess=os_guess,
            open_ports=open_ports,
            mdns_services=mdns_services,
            latency_ms=raw.get("latency_ms"),
            is_gateway=is_gateway,
            is_online=True,
            first_seen=now,
            last_seen=now,
            last_changed=now,
            scan_count=1,
        )
