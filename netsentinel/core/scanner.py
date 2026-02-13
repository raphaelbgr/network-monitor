"""ARP scan engine with interface auto-detection.

On Linux/macOS with root privileges, uses scapy's Layer 2 ARP scan (srp).
On Windows (or when Npcap is unavailable), falls back to a ping sweep + arp table approach.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import subprocess
import sys
import time
from typing import Any

from netsentinel.config import Settings

logger = logging.getLogger(__name__)


def _normalize_mac(mac: str) -> str:
    """Normalize a MAC address to uppercase colon-separated format."""
    mac = mac.replace("-", ":").upper()
    parts = mac.split(":")
    return ":".join(p.zfill(2) for p in parts)


# ---------------------------------------------------------------------------
# Gateway / subnet detection
# ---------------------------------------------------------------------------

def _detect_gateway() -> tuple[str | None, str | None]:
    """Detect the default gateway IP and associated interface."""
    # Try scapy first (works cross-platform when available)
    try:
        from scapy.all import conf as scapy_conf

        gw_ip = scapy_conf.route.route("0.0.0.0")[2]
        iface = scapy_conf.route.route("0.0.0.0")[0]
        if gw_ip and gw_ip != "0.0.0.0":
            iface_name = iface if isinstance(iface, str) else getattr(iface, "name", str(iface))
            return gw_ip, iface_name
    except Exception:
        pass

    # Fallback: parse system commands
    if sys.platform == "win32":
        return _detect_gateway_windows()
    else:
        return _detect_gateway_unix()


def _detect_gateway_windows() -> tuple[str | None, str | None]:
    """Parse 'route print' on Windows to find default gateway."""
    try:
        result = subprocess.run(
            ["route", "print", "0.0.0.0"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                return parts[2], None  # gateway IP, interface unknown
    except Exception:
        pass
    return None, None


def _detect_gateway_unix() -> tuple[str | None, str | None]:
    """Parse 'ip route' or 'netstat -rn' on Unix to find default gateway."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        # "default via 192.168.1.1 dev eth0 ..."
        parts = result.stdout.split()
        if "via" in parts:
            idx = parts.index("via")
            gw = parts[idx + 1]
            iface = parts[idx + 3] if "dev" in parts else None
            return gw, iface
    except Exception:
        pass
    return None, None


def _detect_subnet(interface: str | None) -> str | None:
    """Detect the subnet for a given interface."""
    try:
        from scapy.all import conf as scapy_conf, get_if_addr

        if interface is None:
            interface = str(scapy_conf.iface)

        ip_addr = get_if_addr(interface)
        if not ip_addr or ip_addr == "0.0.0.0":
            ip_addr = None

        # Try to determine the netmask from the routing table
        if ip_addr:
            for route in scapy_conf.route.routes:
                net, mask, gw, iface, addr, metric = route
                if addr == ip_addr and mask != 0 and mask != 0xFFFFFFFF:
                    net_addr = ipaddress.IPv4Address(net & mask)
                    prefix = bin(mask).count("1")
                    return f"{net_addr}/{prefix}"

            # Fallback: assume /24
            parts = ip_addr.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        pass

    # Fallback: detect from system IP config
    return _detect_subnet_system()


def _detect_subnet_system() -> str | None:
    """Detect subnet using system commands (no scapy needed)."""
    if sys.platform == "win32":
        return _detect_subnet_windows()
    return _detect_subnet_unix()


def _detect_subnet_windows() -> str | None:
    """Parse ipconfig to find IP and subnet mask."""
    try:
        result = subprocess.run(
            ["ipconfig"], capture_output=True, text=True, timeout=5,
        )
        ip_addr = None
        for line in result.stdout.splitlines():
            line = line.strip()
            if "IPv4 Address" in line or "IPv4-Adresse" in line:
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    ip_addr = match.group(1)
            elif "Subnet Mask" in line or "Subnetzmaske" in line:
                if ip_addr:
                    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        mask = match.group(1)
                        prefix = bin(int(ipaddress.IPv4Address(mask))).count("1")
                        net = ipaddress.IPv4Network(f"{ip_addr}/{prefix}", strict=False)
                        return str(net)
    except Exception:
        pass
    return None


def _detect_subnet_unix() -> str | None:
    """Parse 'ip addr' to find subnet."""
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet ") and "127.0.0.1" not in line:
                # e.g. "inet 192.168.1.100/24 brd ..."
                match = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", line)
                if match:
                    net = ipaddress.IPv4Network(match.group(1), strict=False)
                    return str(net)
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Layer 2 ARP scan (scapy — needs Npcap on Windows)
# ---------------------------------------------------------------------------

def _has_l2_support() -> bool:
    """Check if scapy Layer 2 sockets are available."""
    try:
        from scapy.all import conf as scapy_conf
        # On Windows without Npcap, L2socket is _NotAvailableSocket
        sock_class = scapy_conf.L2socket
        if hasattr(sock_class, "__name__") and "NotAvailable" in sock_class.__name__:
            return False
        # Also check the class name string representation
        if "NotAvailable" in str(sock_class):
            return False
        return True
    except Exception:
        return False


def _arp_scan_scapy(
    subnet: str,
    interface: str | None,
    timeout: int,
    gateway_ip: str | None,
) -> list[dict[str, Any]]:
    """Perform ARP scan using scapy's srp (Layer 2). Requires Npcap on Windows."""
    from scapy.all import ARP, Ether, conf as scapy_conf, srp

    logger.info("Starting scapy ARP scan on %s (interface=%s)", subnet, interface)

    iface = interface if interface else scapy_conf.iface
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)

    start = time.monotonic()
    answered, _ = srp(pkt, iface=iface, timeout=timeout, verbose=False)
    elapsed = time.monotonic() - start

    devices: list[dict[str, Any]] = []
    for sent, received in answered:
        ip = received.psrc
        mac = _normalize_mac(received.hwsrc)
        latency = (received.time - sent.sent_time) * 1000 if hasattr(received, "time") else None
        devices.append({
            "mac": mac,
            "ipv4": ip,
            "latency_ms": round(latency, 2) if latency else None,
            "is_gateway": ip == gateway_ip,
        })

    logger.info("Scapy ARP scan: %d devices in %.2fs", len(devices), elapsed)
    return devices


# ---------------------------------------------------------------------------
# Fallback: ping sweep + ARP table parsing (no Npcap needed)
# ---------------------------------------------------------------------------

def _ping_sweep(subnet: str, timeout: int) -> None:
    """Ping all hosts in the subnet to populate the OS ARP table."""
    network = ipaddress.IPv4Network(subnet, strict=False)
    hosts = list(network.hosts())

    logger.info("Ping sweep: %d hosts in %s", len(hosts), subnet)

    if sys.platform == "win32":
        # Use a fast parallel ping on Windows
        # ping -n 1 -w <ms> each host
        procs: list[subprocess.Popen[str]] = []
        for host in hosts:
            try:
                proc = subprocess.Popen(
                    ["ping", "-n", "1", "-w", str(timeout * 300), str(host)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                procs.append(proc)
                # Limit concurrent pings to avoid overwhelming the system
                if len(procs) >= 64:
                    for p in procs:
                        p.wait()
                    procs.clear()
            except Exception:
                pass
        for p in procs:
            try:
                p.wait(timeout=timeout)
            except Exception:
                p.kill()
    else:
        # On Linux/macOS, use fping if available, else sequential ping
        try:
            subprocess.run(
                ["fping", "-a", "-q", "-g", subnet, "-t", str(timeout * 1000)],
                capture_output=True, timeout=timeout * 2 + 10,
            )
        except FileNotFoundError:
            procs = []
            for host in hosts:
                try:
                    proc = subprocess.Popen(
                        ["ping", "-c", "1", "-W", str(timeout), str(host)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    procs.append(proc)
                    if len(procs) >= 64:
                        for p in procs:
                            p.wait()
                        procs.clear()
                except Exception:
                    pass
            for p in procs:
                try:
                    p.wait(timeout=timeout)
                except Exception:
                    p.kill()
        except Exception:
            pass


def _parse_arp_table(gateway_ip: str | None) -> list[dict[str, Any]]:
    """Read the OS ARP table and return discovered devices."""
    devices: list[dict[str, Any]] = []

    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception as exc:
        logger.warning("Failed to read ARP table: %s", exc)
        return devices

    # Parse arp -a output
    # Windows: "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic"
    # Linux:   "? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
    # macOS:   "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
    mac_pattern = re.compile(r"([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})")
    ip_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    seen_macs: set[str] = set()

    for line in result.stdout.splitlines():
        # Skip broadcast and incomplete entries
        if "ff-ff-ff-ff-ff-ff" in line.lower() or "ff:ff:ff:ff:ff:ff" in line.lower():
            continue
        if "incomplete" in line.lower() or "static" in line.lower():
            continue

        ip_match = ip_pattern.search(line)
        mac_match = mac_pattern.search(line)

        if ip_match and mac_match:
            ip = ip_match.group(1)
            mac = _normalize_mac(mac_match.group(1))

            # Skip multicast and broadcast MACs
            if mac.startswith("01:") or mac.startswith("FF:") or mac == "00:00:00:00:00:00":
                continue

            if mac in seen_macs:
                continue
            seen_macs.add(mac)

            devices.append({
                "mac": mac,
                "ipv4": ip,
                "latency_ms": None,
                "is_gateway": ip == gateway_ip,
            })

    logger.info("ARP table: %d devices found", len(devices))
    return devices


def _fallback_scan_sync(
    subnet: str,
    timeout: int,
    gateway_ip: str | None,
) -> list[dict[str, Any]]:
    """Ping sweep + ARP table scan (no Npcap/libpcap needed)."""
    logger.info("Using fallback scanner (ping sweep + arp table) for %s", subnet)
    _ping_sweep(subnet, timeout)
    # Small delay to let the ARP table populate
    time.sleep(0.5)
    return _parse_arp_table(gateway_ip)


# ---------------------------------------------------------------------------
# Latency measurement (best-effort, for fallback scanner)
# ---------------------------------------------------------------------------

def _measure_latency(ip: str) -> float | None:
    """Measure ping RTT to a single host."""
    try:
        if sys.platform == "win32":
            cmd = ["ping", "-n", "1", "-w", "1000", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        # Look for time=Xms or time<1ms
        for line in result.stdout.splitlines():
            match = re.search(r"time[=<](\d+\.?\d*)", line, re.IGNORECASE)
            if match:
                return float(match.group(1))
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# NetworkScanner class
# ---------------------------------------------------------------------------

class NetworkScanner:
    """Async network scanner with automatic fallback.

    Uses scapy Layer 2 ARP scan when available, otherwise falls back
    to ping sweep + ARP table parsing.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._interface: str | None = settings.interface
        self._subnet: str | None = settings.subnet
        self._gateway_ip: str | None = None
        self._gateway_mac: str | None = None
        self._use_scapy: bool = False

    async def initialize(self) -> None:
        """Auto-detect interface, subnet, gateway, and scan method."""
        gw_ip, gw_iface = await asyncio.to_thread(_detect_gateway)
        self._gateway_ip = gw_ip

        if self._interface is None and gw_iface:
            self._interface = gw_iface
            logger.info("Auto-detected interface: %s", self._interface)

        if self._subnet is None:
            self._subnet = await asyncio.to_thread(_detect_subnet, self._interface)
            logger.info("Auto-detected subnet: %s", self._subnet)

        if self._gateway_ip:
            logger.info("Gateway: %s", self._gateway_ip)

        # Determine scan method
        self._use_scapy = await asyncio.to_thread(_has_l2_support)
        if self._use_scapy:
            logger.info("Scanner: using scapy Layer 2 ARP")
        else:
            logger.info("Scanner: using ping sweep + ARP table (Npcap not available)")

    @property
    def interface(self) -> str | None:
        return self._interface

    @property
    def subnet(self) -> str | None:
        return self._subnet

    @property
    def gateway_ip(self) -> str | None:
        return self._gateway_ip

    async def scan(self) -> list[dict[str, Any]]:
        """Run a network scan and return raw device dicts.

        Automatically chooses between scapy ARP and ping+arp fallback.
        """
        if not self._subnet:
            raise RuntimeError(
                "No subnet configured or detected. "
                "Set NETSENTINEL_SUBNET or configure 'subnet' in config.yaml."
            )

        if self._use_scapy:
            try:
                devices = await asyncio.to_thread(
                    _arp_scan_scapy,
                    self._subnet,
                    self._interface,
                    self.settings.scan_timeout,
                    self._gateway_ip,
                )
            except Exception as exc:
                logger.warning("Scapy scan failed (%s), falling back to ping sweep", exc)
                devices = await asyncio.to_thread(
                    _fallback_scan_sync,
                    self._subnet,
                    self.settings.scan_timeout,
                    self._gateway_ip,
                )
        else:
            devices = await asyncio.to_thread(
                _fallback_scan_sync,
                self._subnet,
                self.settings.scan_timeout,
                self._gateway_ip,
            )

        # Measure latency for devices that don't have it
        async def _add_latency(d: dict[str, Any]) -> dict[str, Any]:
            if d.get("latency_ms") is None and d.get("ipv4"):
                d["latency_ms"] = await asyncio.to_thread(_measure_latency, d["ipv4"])
            return d

        # Measure latency concurrently (max 20 at a time)
        sem = asyncio.Semaphore(20)

        async def _measure(d: dict[str, Any]) -> dict[str, Any]:
            async with sem:
                return await _add_latency(d)

        devices = await asyncio.gather(*[_measure(d) for d in devices])

        # Track gateway MAC
        for d in devices:
            if d.get("is_gateway"):
                self._gateway_mac = d["mac"]
                break

        return devices


def check_privileges() -> bool:
    """Check if we have sufficient privileges for raw socket operations.

    On Windows with the fallback scanner, admin is not strictly required.
    """
    if sys.platform == "win32":
        # Fallback scanner works without admin on Windows
        return True
    else:
        import os
        return os.geteuid() == 0
