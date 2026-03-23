import asyncio
import socket
import json
import hashlib
import time
import logging
from typing import Tuple, Optional
from urllib.parse import urlparse

from .config import CONFIG

logger = logging.getLogger('eni_scanner')

# --- Импорты с проверкой наличия ---
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

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
    from zeroconf import ServiceBrowser, Zeroconf, ServiceListener
    ZEROCONF_AVAILABLE = True
except ImportError:
    ZEROCONF_AVAILABLE = False

# --- Базовый класс ---
class AsyncProbe:
    def __init__(self, timeout: float, use_proxy: bool = False, grab_banner: bool = True, proxy_url: str = None):
        self.timeout = timeout
        self.use_proxy = use_proxy
        self.grab_banner = grab_banner
        self.proxy_url = proxy_url
        if proxy_url:
            self._setup_proxy()

    def _setup_proxy(self):
        try:
            import socks
        except ImportError:
            raise RuntimeError("PySocks required for proxy")
        parsed = urlparse(self.proxy_url)
        if parsed.scheme == 'socks5':
            socks.set_default_proxy(socks.SOCKS5, parsed.hostname, parsed.port)
            socket.socket = socks.socksocket

    async def _get_conn(self, ip, port):
        return await asyncio.open_connection(ip, port, ssl=False)

    async def probe_with_retries(self, ip, port, retries=2):
        for attempt in range(retries + 1):
            try:
                return await self.probe(ip, port)
            except (asyncio.TimeoutError, ConnectionRefusedError):
                if attempt == retries:
                    logger.debug("Probe %s:%d failed after %d retries", ip, port, retries)
                    return "closed", "", ""
                wait = 0.5 * (2 ** attempt)
                await asyncio.sleep(wait)
            except Exception as e:
                logger.debug("Unexpected error: %s", e)
                return "error", "", ""
        return "closed", "", ""

    async def probe(self, ip: str, port: int) -> Tuple[str, str, str]:
        raise NotImplementedError

# --- Конкретные пробы ---
class AsyncSshProbe(AsyncProbe):
    name = "ssh"
    async def probe(self, ip, port):
        reader, writer = await self._get_conn(ip, port)
        try:
            if not self.grab_banner:
                writer.close()
                await writer.wait_closed()
                return "open", "", ""
            banner = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            banner_str = banner.decode(errors="replace").strip()
            version = banner_str.replace("SSH-2.0-", "") if "SSH-" in banner_str else "Unknown"
            return "open", banner_str, version
        finally:
            writer.close()
            await writer.wait_closed()

class AsyncFtpProbe(AsyncProbe):
    name = "ftp"
    async def probe(self, ip, port):
        reader, writer = await self._get_conn(ip, port)
        try:
            if not self.grab_banner:
                writer.close()
                await writer.wait_closed()
                return "open", "", ""
            banner = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            banner_str = banner.decode(errors="replace").strip()
            version = banner_str.split(" ", 1)[1] if "220" in banner_str else "Unknown"
            return "open", banner_str, version
        finally:
            writer.close()
            await writer.wait_closed()

class AsyncHttpProbe(AsyncProbe):
    name = "http"
    def __init__(self, session, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = session
        self.iot_paths = [
            "/cgi-bin/config.exp", "/admin/login.php", "/web/system.html",
            "/cgi-bin/luci", "/cgi-bin/status", "/config/getuser",
            "/system.ini", "/status.cgi", "/cgi-bin/guest/Login.cgi",
            "/cgi-bin/admin/config.cgi", "/cgi-bin/snmp.cgi", "/cgi-bin/upgrade.cgi"
        ]

    async def probe(self, ip, port, use_ssl=False):
        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{ip}:{port}/"
        try:
            async with self.session.get(url, timeout=self.timeout, allow_redirects=True) as resp:
                server = resp.headers.get('Server', 'Unknown')
                text = await resp.text()
                title = None
                if BS4_AVAILABLE:
                    soup = BeautifulSoup(text, 'html.parser')
                    title_tag = soup.find('title')
                    if title_tag:
                        title = title_tag.text.strip()
                favicon_hash = None
                try:
                    async with self.session.get(f"{url}favicon.ico", timeout=self.timeout) as fav_resp:
                        if fav_resp.status == 200:
                            fav_data = await fav_resp.read()
                            favicon_hash = hashlib.md5(fav_data).hexdigest()
                except:
                    pass
                detected_paths = []
                for path in self.iot_paths:
                    try:
                        async with self.session.get(f"{url}{path.lstrip('/')}", timeout=self.timeout) as r:
                            if r.status in (200, 401):
                                detected_paths.append(path)
                    except:
                        pass
                banner_info = {
                    "server": server,
                    "title": title,
                    "favicon_hash": favicon_hash,
                    "detected_paths": detected_paths
                }
                banner = json.dumps(banner_info, ensure_ascii=False)
                return "open", banner, server
        except Exception as e:
            logger.debug("HTTP probe error %s:%d: %s", ip, port, e)
            return "closed", "", ""

class AsyncHttpsProbe(AsyncHttpProbe):
    name = "https"
    async def probe(self, ip, port):
        return await super().probe(ip, port, use_ssl=True)

class AsyncGenericProbe(AsyncProbe):
    name = "port"
    async def probe(self, ip, port):
        reader, writer = await self._get_conn(ip, port)
        writer.close()
        await writer.wait_closed()
        return "open", "", ""

class AsyncSnmpProbe(AsyncProbe):
    name = "snmp"
    def __init__(self, *args, communities=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.communities = communities or CONFIG['snmp']['default_communities']

    async def probe(self, ip, port=161):
        if AIOSNMP_AVAILABLE:
            for community in self.communities:
                try:
                    snmp = Snmp(host=ip, port=port, community=community, timeout=self.timeout)
                    result = await snmp.get('1.3.6.1.2.1.1.1.0')
                    if result and result[0]:
                        sysDescr = result[0].value
                        return "open", sysDescr, f"community={community}"
                except Exception:
                    continue
        elif PYSNMP_AVAILABLE:
            loop = asyncio.get_running_loop()
            for community in self.communities:
                def _snmp_get():
                    try:
                        errorIndication, errorStatus, errorIndex, varBinds = next(
                            getCmd(SnmpEngine(),
                                   CommunityData(community, mpModel=1),
                                   UdpTransportTarget((ip, port), timeout=self.timeout, retries=0),
                                   ContextData(),
                                   ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))
                        )
                        if errorIndication or errorStatus:
                            return None
                        for varBind in varBinds:
                            return varBind[1].prettyPrint()
                    except Exception:
                        return None
                sysDescr = await loop.run_in_executor(None, _snmp_get)
                if sysDescr:
                    return "open", sysDescr, f"community={community}"
        return "closed", "", ""

class AsyncMdnsProbe(AsyncProbe):
    name = "mdns"
    async def probe(self, ip, port=5353):
        if not ZEROCONF_AVAILABLE:
            return "error", "zeroconf missing", ""
        loop = asyncio.get_running_loop()
        def _mdns_discover():
            class Listener(ServiceListener):
                def __init__(self):
                    self.services = []
                def add_service(self, zc, type_, name):
                    self.services.append(name)
                def remove_service(self, zc, type_, name): pass
                def update_service(self, zc, type_, name): pass
            listener = Listener()
            zc = Zeroconf()
            browser = ServiceBrowser(zc, "_services._dns-sd._udp.local.", listener)
            time.sleep(2)
            zc.close()
            return listener.services
        services = await loop.run_in_executor(None, _mdns_discover)
        if services:
            banner = f"mDNS services: {', '.join(services[:5])}"
            return "open", banner, "mDNS"
        else:
            return "closed", "", ""

class AsyncSsdpProbe(AsyncProbe):
    name = "ssdp"
    async def probe(self, ip, port=1900):
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        def _send_recv():
            try:
                search_request = (
                    "M-SEARCH * HTTP/1.1\r\n"
                    "HOST: 239.255.255.250:1900\r\n"
                    "MAN: \"ssdp:discover\"\r\n"
                    "MX: 2\r\n"
                    "ST: ssdp:all\r\n"
                    "\r\n"
                ).encode()
                sock.sendto(search_request, (ip, port))
                data, addr = sock.recvfrom(4096)
                return data.decode(errors="replace")
            except Exception:
                return None
            finally:
                sock.close()
        response = await loop.run_in_executor(None, _send_recv)
        if response:
            return "open", response, "SSDP"
        else:
            return "closed", "", ""

# --- Map of probe classes (without HTTP, they need session) ---
ASYNC_PROBE_MAP = {
    "ssh": AsyncSshProbe,
    "ftp": AsyncFtpProbe,
    "https": AsyncHttpsProbe,
    "snmp": AsyncSnmpProbe,
    "ssdp": AsyncSsdpProbe,
    "mdns": AsyncMdnsProbe,
    "port": AsyncGenericProbe
}

