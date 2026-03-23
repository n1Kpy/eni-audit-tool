import asyncio
import logging
import time
from typing import Set, List, Tuple, Optional
import aiohttp
from tqdm import tqdm

from .utils import TokenBucket, get_mac_by_ip
from .database import Database
from .probes import AsyncHttpProbe, AsyncHttpsProbe, ASYNC_PROBE_MAP
from .arch_detector import ArchDetector
from .models import ScanResult

logger = logging.getLogger('eni_scanner')

class AsyncScanner:
    def __init__(self, args, db: Optional[Database] = None, exclude_ips: Set[str] = None, exclude_ports: Set[int] = None):
        self.args = args
        self.db = db
        self.exclude_ips = exclude_ips or set()
        self.exclude_ports = exclude_ports or set()
        self.rate = TokenBucket(args.rate, capacity=100)  # capacity from config?
        self.results = []
        self.lock = asyncio.Lock()
        self.session = None
        self.open_count = 0
        self.stop = False
        self.queue = asyncio.Queue()
        self.workers = []

    async def worker(self, pbar):
        while not self.stop:
            try:
                item = await asyncio.wait_for(self.queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            ip, port, probe = item
            try:
                await self.scan_one(ip, port, probe)
            except Exception as e:
                logger.debug("Worker error: %s", e)
            self.queue.task_done()
            pbar.update(1)
            pbar.set_postfix(open=self.open_count)

    async def scan_one(self, ip, port, probe):
        if self.stop:
            return
        if ip in self.exclude_ips or port in self.exclude_ports:
            return
        if self.args.resume and self.db and await self.db.is_scanned(ip, port, probe.name):
            return
        await self.rate.wait()
        try:
            if hasattr(probe, 'probe_with_retries'):
                status, banner, version = await probe.probe_with_retries(ip, port)
            else:
                status, banner, version = await probe.probe(ip, port)
        except Exception as e:
            logger.debug("Probe error: %s", e)
            status, banner, version = "error", "", ""
        arch = ""
        if status == "open" and banner:
            arch = ArchDetector.detect_from_banner(banner, probe.name)
            if arch == "unknown" and probe.name in ("http", "https"):
                arch = await ArchDetector.detect_from_http(ip, port, self.session, use_ssl=(probe.name == "https"))
            if arch == "unknown" and probe.name in ("http", "https"):
                arch = await ArchDetector.detect_from_http_ua(ip, port, self.session, use_ssl=(probe.name == "https"))
            if arch == "unknown" and probe.name == "snmp" and hasattr(probe, 'communities'):
                arch = await ArchDetector.detect_from_snmp(ip, port, probe.communities)
        fp = ""
        res = ScanResult(
            ip, port, probe.name, status, banner, version, fp, time.time(), arch=arch
        )
        if self.args.local:
            mac, vendor = await get_mac_by_ip(ip, self.args.timeout)
            if mac:
                res.mac = mac
                res.vendor = vendor
        async with self.lock:
            self.results.append(res)
            if self.db:
                await self.db.insert_or_update(res)
            if status == "open":
                self.open_count += 1

    async def run(self, targets: List[str], probes: List[Tuple[int, type]]):
        connector = aiohttp.TCPConnector(ssl=False, limit=100)
        self.session = aiohttp.ClientSession(connector=connector)
        try:
            total = len(targets) * len(probes)
            pbar = tqdm(total=total, desc="Scanning", unit="probe")
            # Fill queue
            for ip in targets:
                for port, probe_class in probes:
                    if probe_class in (AsyncHttpProbe, AsyncHttpsProbe):
                        probe = probe_class(self.session, self.args.timeout, bool(self.args.proxy),
                                            self.args.banner, proxy_url=self.args.proxy)
                    else:
                        probe = probe_class(self.args.timeout, bool(self.args.proxy),
                                            self.args.banner, proxy_url=self.args.proxy)
                    await self.queue.put((ip, port, probe))
            # Start workers
            num_workers = min(self.args.threads, total)
            self.workers = [asyncio.create_task(self.worker(pbar)) for _ in range(num_workers)]
            await self.queue.join()
            # Stop workers
            self.stop = True
            for w in self.workers:
                w.cancel()
            await asyncio.gather(*self.workers, return_exceptions=True)
            pbar.close()
        finally:
            if self.session:
                await self.session.close()
        return self.results
