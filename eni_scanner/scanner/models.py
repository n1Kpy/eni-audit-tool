from dataclasses import dataclass

@dataclass
class ScanResult:
    ip: str
    port: int
    service: str
    status: str
    banner: str
    version: str
    fingerprint: str
    ts: float
    mac: str = ""
    vendor: str = ""
    arch: str = ""
    notes: str = ""
    payload_status: str = "none"
