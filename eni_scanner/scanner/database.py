import sqlite3
import asyncio
import time
import hashlib
from typing import Optional, List
from .models import ScanResult

def hash_cred(user: str, pwd: str) -> str:
    return hashlib.sha256(f"{user}:{pwd}".encode()).hexdigest()

class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.lock = asyncio.Lock()
        self._create_tables()

    def _create_tables(self):
        cur = self.conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                service TEXT,
                status TEXT,
                banner TEXT,
                version TEXT,
                fingerprint TEXT,
                ts REAL,
                mac TEXT,
                vendor TEXT,
                arch TEXT,
                notes TEXT,
                payload_status TEXT DEFAULT 'none',
                UNIQUE(ip, port, service)
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ip ON scan_results(ip)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_status ON scan_results(status)")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS hacked_creds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                service TEXT,
                cred_hash TEXT,
                timestamp REAL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scanned (
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                service TEXT,
                PRIMARY KEY (ip, port, service)
            )
        """)
        self.conn.commit()

    async def insert_or_update(self, result: ScanResult):
        async with self.lock:
            cur = self.conn.cursor()
            cur.execute("""
                INSERT OR REPLACE INTO scan_results
                (ip, port, service, status, banner, version, fingerprint, ts, mac, vendor, arch, notes, payload_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result.ip, result.port, result.service, result.status,
                result.banner, result.version, result.fingerprint, result.ts,
                result.mac, result.vendor, result.arch, result.notes, result.payload_status
            ))
            cur.execute("""
                INSERT OR IGNORE INTO scanned (ip, port, service) VALUES (?, ?, ?)
            """, (result.ip, result.port, result.service))
            self.conn.commit()

    async def mark_pwned(self, ip, port, service, arch="", cred_hash=""):
        async with self.lock:
            cur = self.conn.cursor()
            cur.execute("""
                UPDATE scan_results
                SET notes = 'pwned', arch = ?
                WHERE ip = ? AND port = ? AND service = ?
            """, (arch, ip, port, service))
            if cred_hash:
                cur.execute("""
                    INSERT INTO hacked_creds (ip, port, service, cred_hash, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (ip, port, service, cred_hash, time.time()))
            self.conn.commit()

    async def update_payload_status(self, ip, port, service, status):
        async with self.lock:
            cur = self.conn.cursor()
            cur.execute("""
                UPDATE scan_results
                SET payload_status = ?
                WHERE ip = ? AND port = ? AND service = ?
            """, (status, ip, port, service))
            self.conn.commit()

    async def is_scanned(self, ip, port, service) -> bool:
        async with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT 1 FROM scanned WHERE ip=? AND port=? AND service=?", (ip, port, service))
            return cur.fetchone() is not None

    async def get_open_targets(self, service=None):
        async with self.lock:
            cur = self.conn.cursor()
            if service:
                cur.execute("SELECT * FROM scan_results WHERE status='open' AND service=?", (service,))
            else:
                cur.execute("SELECT * FROM scan_results WHERE status='open'")
            rows = cur.fetchall()
            results = []
            for row in rows:
                res = ScanResult(
                    ip=row[1], port=row[2], service=row[3], status=row[4],
                    banner=row[5], version=row[6], fingerprint=row[7], ts=row[8],
                    mac=row[9], vendor=row[10], arch=row[11], notes=row[12],
                    payload_status=row[13] if len(row) > 13 else "none"
                )
                results.append(res)
            return results
