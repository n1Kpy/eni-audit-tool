import json
import csv
import logging
from typing import List
from .models import ScanResult

logger = logging.getLogger('eni_scanner')

def export_to_txt(results: List[ScanResult], filename: str):
    with open(filename, "w", encoding="utf-8") as f:
        for r in results:
            if r.service in ("http","https") and r.banner.startswith("{"):
                try:
                    bdata = json.loads(r.banner)
                    title = bdata.get("title","")
                    server = bdata.get("server","")
                    favicon = bdata.get("favicon_hash","")
                    paths = ", ".join(bdata.get("detected_paths",[]))
                    line = (f"{r.ip}:{r.port} | {r.service} | {r.status} | "
                            f"Title: {title} | Server: {server} | Favicon: {favicon} | Paths: {paths} | "
                            f"MAC: {r.mac} | Vendor: {r.vendor} | Arch: {r.arch} | Payload: {r.payload_status}")
                except:
                    line = f"{r.ip}:{r.port} | {r.service} | {r.status} | {r.banner} | MAC: {r.mac} | Vendor: {r.vendor} | Arch: {r.arch} | Payload: {r.payload_status}"
            else:
                line = f"{r.ip}:{r.port} | {r.service} | {r.status} | {r.banner} | MAC: {r.mac} | Vendor: {r.vendor} | Arch: {r.arch} | Payload: {r.payload_status}"
            f.write(line + "\n")
    logger.info("Results saved to %s (txt)", filename)

def export_to_csv(results: List[ScanResult], filename: str):
    with open(filename, "w", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ScanResult.__dataclass_fields__.keys())
        writer.writeheader()
        for r in results:
            writer.writerow(r.__dict__)
    logger.info("Results saved to %s (csv)", filename)

def export_to_json(results: List[ScanResult], filename: str):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump([r.__dict__ for r in results], f, indent=2, ensure_ascii=False)
    logger.info("Results saved to %s (json)", filename)

def export_to_excel(results: List[ScanResult], filename: str):
    try:
        import openpyxl
    except ImportError:
        logger.error("openpyxl not installed, cannot export to Excel")
        return
    try:
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Scan Results"
        headers = ["IP", "Port", "Service", "Status", "Banner", "Version", "Fingerprint",
                   "Timestamp", "MAC", "Vendor", "Arch", "Notes", "PayloadStatus"]
        ws.append(headers)
        for r in results:
            ws.append([
                r.ip, r.port, r.service, r.status, r.banner, r.version, r.fingerprint,
                r.ts, r.mac, r.vendor, r.arch, r.notes, r.payload_status
            ])
        wb.save(filename)
        logger.info("Results saved to %s (xlsx)", filename)
    except Exception as e:
        logger.error("Error exporting to Excel: %s", e)

def export_to_xml(results: List[ScanResult], filename: str):
    import xml.etree.ElementTree as ET
    try:
        root = ET.Element("scan_results")
        for r in results:
            elem = ET.SubElement(root, "result")
            for k, v in r.__dict__.items():
                child = ET.SubElement(elem, k)
                child.text = str(v)
        tree = ET.ElementTree(root)
        tree.write(filename, encoding="utf-8", xml_declaration=True)
        logger.info("Results saved to %s (xml)", filename)
    except Exception as e:
        logger.error("Error exporting to XML: %s", e)

def export_results(results: List[ScanResult], filename: str, fmt: str):
    if fmt == "txt":
        export_to_txt(results, filename)
    elif fmt == "csv":
        export_to_csv(results, filename)
    elif fmt == "json":
        export_to_json(results, filename)
    elif fmt == "xlsx":
        export_to_excel(results, filename)
    elif fmt == "xml":
        export_to_xml(results, filename)
    else:
        logger.error("Unsupported format: %s", fmt)
