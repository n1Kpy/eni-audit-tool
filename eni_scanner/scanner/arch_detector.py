from typing import List

class ArchDetector:
    @staticmethod
    def detect_from_banner(banner: str, service: str) -> str:
        b = banner.lower()
        if "arm" in b:
            return "arm"
        if "mips" in b:
            return "mips"
        if "x86_64" in b or "amd64" in b:
            return "x86_64"
        if "i386" in b or "i686" in b:
            return "x86"
        if "powerpc" in b or "ppc" in b:
            return "powerpc"
        return "unknown"

    @staticmethod
    async def detect_from_http(ip: str, port: int, session, use_ssl=False) -> str:
        scheme = "https" if use_ssl else "http"
        try:
            async with session.get(f"{scheme}://{ip}:{port}/cgi-bin/status", timeout=2, ssl=False) as resp:
                text = await resp.text()
                if "arm" in text:
                    return "arm"
                if "mips" in text:
                    return "mips"
        except:
            pass
        return "unknown"

    @staticmethod
    async def detect_from_http_ua(ip: str, port: int, session, use_ssl=False) -> str:
        scheme = "https" if use_ssl else "http"
        try:
            async with session.get(f"{scheme}://{ip}:{port}/", timeout=2, ssl=False) as resp:
                ua = resp.headers.get('User-Agent', '')
                if "arm" in ua:
                    return "arm"
                if "mips" in ua:
                    return "mips"
        except:
            pass
        return "unknown"

    @staticmethod
    async def detect_from_snmp(ip: str, port: int, communities: List[str]) -> str:
        try:
            from aiosnmp import Snmp
        except ImportError:
            return "unknown"
        for community in communities:
            try:
                snmp = Snmp(host=ip, port=port, community=community, timeout=2)
                result = await snmp.get('1.3.6.1.2.1.1.1.0')
                if result and result[0]:
                    sysDescr = result[0].value.lower()
                    if "arm" in sysDescr:
                        return "arm"
                    if "mips" in sysDescr:
                        return "mips"
            except:
                continue
        return "unknown"
