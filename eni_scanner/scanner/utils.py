import asyncio
import socket
import time
import sys
import logging
from typing import Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger('eni_scanner')

# ----- Imports with availability checks -----
try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from pysnmp.hlapi import *
    PYSNMP_AVAILABLE = True
except ImportError:
    PYSNMP_AVAILABLE = False

try:
    from aiosnmp import Snmp
    AIOSNMP_AVAILABLE = True
except ImportError:
    AIOSNMP_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# ----- OUI Registry -----
class OUIRegistry:
    _instance = None
    _cache = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_default()
        return cls._instance

    def _load_default(self):
        self._cache = {
            "00:0C:29": "VMware", "00:50:56": "VMware", "00:1C:42": "Parallels",
            "08:00:27": "VirtualBox", "00:15:5D": "Hyper-V", "00:1A:A0": "TP-Link",
            "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "00:23:AB": "Hikvision",
            "00:24:8C": "Dahua", "00:25:9C": "D-Link", "00:26:5B": "Netgear",
            "00:30:4F": "Huawei", "00:37:6D": "Xiaomi", "10:BF:48": "Xiaomi",
            "18:68:CB": "Cisco", "1C:B2:7A": "MikroTik", "2C:30:33": "Dahua",
            "3C:52:A1": "MikroTik", "40:4A:03": "ZTE", "4C:CC:6A": "ZTE",
            "54:4A:16": "Huawei", "70:3A:CB": "D-Link", "7C:DD:90": "Asus",
            "80:89:17": "TP-Link", "84:0D:8E": "Xiaomi", "94:0C:6D": "TP-Link",
            "B0:BE:76": "MikroTik", "C4:6E:1F": "D-Link", "CC:34:29": "Dahua",
            "D4:6E:0E": "Hikvision", "E4:5F:01": "TP-Link", "F4:F2:6D": "Hikvision",
            "FC:EC:DA": "Xiaomi"
        }

    def update_from_ieee(self):
        try:
            import requests
            from .config import CONFIG
        except ImportError:
            logger.warning("requests not installed, cannot update OUI")
            return False
        try:
            response = requests.get(CONFIG['oui']['url'], timeout=10)
            if response.status_code == 200:
                new_cache = {}
                for line in response.text.splitlines():
                    if "(base 16)" in line:
                        parts = line.split()
                        oui = parts[0].upper()
                        vendor = ' '.join(parts[2:]).strip()
                        new_cache[oui] = vendor
                if new_cache:
                    self._cache = new_cache
                    logger.info("OUI database updated from IEEE (%d entries)", len(self._cache))
                    return True
        except Exception as e:
            logger.warning("Failed to update OUI from IEEE: %s", e)
        return False

    def get_vendor(self, mac: str) -> str:
        if not mac:
            return "Unknown"
        oui = mac.upper()[:8]
        return self._cache.get(oui, "Unknown")

oui_registry = OUIRegistry()

# ----- MAC cache -----
class MacCache:
    def __init__(self):
        self._cache = {}
        self._lock = asyncio.Lock()

    async def get(self, ip: str) -> Tuple[Optional[str], Optional[str]]:
        async with self._lock:
            return self._cache.get(ip, (None, None))

    async def set(self, ip: str, mac: str, vendor: str):
        async with self._lock:
            self._cache[ip] = (mac, vendor)

mac_cache = MacCache()

async def get_mac_by_ip(ip: str, timeout: float = 2.0) -> Tuple[Optional[str], Optional[str]]:
    cached = await mac_cache.get(ip)
    if cached[0]:
        return cached
    if ':' in ip:  # IPv6
        if sys.platform.startswith('linux'):
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ip", "neigh", "show", ip,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL
                )
                stdout, _ = await proc.communicate()
                for line in stdout.decode().splitlines():
                    if "lladdr" in line:
                        parts = line.split()
                        mac = parts[4]
                        vendor = oui_registry.get_vendor(mac)
                        await mac_cache.set(ip, mac, vendor)
                        return mac, vendor
            except Exception:
                pass
        return None, None
    else:
        if not SCAPY_AVAILABLE:
            return None, None
        loop = asyncio.get_running_loop()
        def _arp():
            arp = ARP(pdst=ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=timeout, verbose=0)[0]
            if result:
                return result[0][1].hwsrc
            return None
        mac = await loop.run_in_executor(None, _arp)
        if mac:
            vendor = oui_registry.get_vendor(mac)
            await mac_cache.set(ip, mac, vendor)
            return mac, vendor
    return None, None

# ----- Token bucket rate limiter -----
class TokenBucket:
    def __init__(self, rate: Optional[float], capacity: Optional[int] = None):
        self.rate = rate if rate is not None else float('inf')
        self.capacity = capacity if capacity is not None else (self.rate if self.rate != float('inf') else 100)
        self.tokens = self.capacity
        self.last = time.time()
        self.lock = asyncio.Lock()

    async def consume(self, tokens=1) -> bool:
        if self.rate == float('inf'):
            return True
        async with self.lock:
            now = time.time()
            self.tokens += (now - self.last) * self.rate
            self.tokens = min(self.tokens, self.capacity)
            self.last = now
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    async def wait(self, tokens=1):
        while not await self.consume(tokens):
            await asyncio.sleep(0.01)

# ----- Dependency check -----
def check_dependencies():
    missing = []
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        missing.append("beautifulsoup4")
    if not SCAPY_AVAILABLE:
        missing.append("scapy")
    try:
        import paramiko
    except ImportError:
        missing.append("paramiko")
    try:
        import socks
    except ImportError:
        missing.append("PySocks")
    if not PYSNMP_AVAILABLE and not AIOSNMP_AVAILABLE:
        missing.append("pysnmp or aiosnmp")
    try:
        from zeroconf import ServiceBrowser
    except ImportError:
        missing.append("zeroconf")
    if not CRYPTO_AVAILABLE:
        missing.append("cryptography")
    try:
        import requests
    except ImportError:
        missing.append("requests")
    if missing:
        logger.warning("Missing optional libraries: %s. Some features may be limited.", ", ".join(missing))

# ----- Global proxy setup -----
def set_global_proxy(proxy_url: str):
    try:
        import socks
    except ImportError:
        logger.error("PySocks not installed, proxy unavailable")
        return
    parsed = urlparse(proxy_url)
    if parsed.scheme == 'socks5':
        socks.set_default_proxy(socks.SOCKS5, parsed.hostname, parsed.port)
        socket.socket = socks.socksocket
        logger.info("Proxy set: %s", proxy_url)
    else:
        logger.error("Unsupported proxy scheme: %s (only socks5 is supported)", parsed.scheme)
