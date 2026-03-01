#!/usr/bin/env python3
"""
output.py — Save scan results to TXT, JSON, or XML formats
"""

import json
import xml.etree.ElementTree as ET
from datetime import datetime


def _build_report_data(target, target_ip, open_ports, port_list, scan_duration, risk_score, threads):
    """Build a shared dict of all scan data."""
    return {
        "meta": {
            "tool":        "KUMARAN v2.0",
            "developer":   "Ninshad",
            "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target":      target,
            "target_ip":   target_ip,
            "ports_scanned": len(port_list),
            "threads":     threads,
            "scan_duration_sec": scan_duration,
        },
        "summary": {
            "open_ports_count": len(open_ports),
            "risk_score":       risk_score,
            "risk_level": (
                "CRITICAL" if risk_score >= 7 else
                "HIGH"     if risk_score >= 5 else
                "MEDIUM"   if risk_score >= 3 else
                "LOW"      if risk_score > 0  else
                "SAFE"
            )
        },
        "results": [
            {
                "port":    port,
                "service": service,
                "banner":  banner,
                "risk":    risk,
            }
            for port, service, banner, risk in open_ports
        ]
    }


def save_txt(filename, data):
    lines = []
    m = data["meta"]
    s = data["summary"]

    lines.append("=" * 62)
    lines.append(f"  KUMARAN v2.0 — Scan Report")
    lines.append("=" * 62)
    lines.append(f"  Timestamp      : {m['timestamp']}")
    lines.append(f"  Target         : {m['target']} ({m['target_ip']})")
    lines.append(f"  Ports Scanned  : {m['ports_scanned']}")
    lines.append(f"  Scan Duration  : {m['scan_duration_sec']}s")
    lines.append(f"  Threads        : {m['threads']}")
    lines.append("-" * 62)
    lines.append("{:<8} {:<20} {:<10} {}".format("PORT", "SERVICE", "RISK", "BANNER"))
    lines.append("-" * 62)

    for r in data["results"]:
        lines.append("{:<8} {:<20} {:<10} {}".format(
            r["port"], r["service"], r["risk"], r["banner"] or ""
        ))

    lines.append("=" * 62)
    lines.append(f"  Open Ports     : {s['open_ports_count']}")
    lines.append(f"  Risk Score     : {s['risk_score']}")
    lines.append(f"  Risk Level     : {s['risk_level']}")
    lines.append("=" * 62)

    with open(f"{filename}.txt", "w") as f:
        f.write("\n".join(lines))


def save_json(filename, data):
    with open(f"{filename}.json", "w") as f:
        json.dump(data, f, indent=4)


def save_xml(filename, data):
    m = data["meta"]
    s = data["summary"]

    root = ET.Element("KumaranScan")

    # Meta
    meta_el = ET.SubElement(root, "Meta")
    for k, v in m.items():
        el = ET.SubElement(meta_el, k)
        el.text = str(v)

    # Summary
    summ_el = ET.SubElement(root, "Summary")
    for k, v in s.items():
        el = ET.SubElement(summ_el, k)
        el.text = str(v)

    # Results
    results_el = ET.SubElement(root, "Results")
    for r in data["results"]:
        port_el = ET.SubElement(results_el, "Port")
        for k, v in r.items():
            el = ET.SubElement(port_el, k)
            el.text = str(v) if v is not None else ""

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(f"{filename}.xml", encoding="unicode", xml_declaration=True)


def save_results(filename, fmt, target, target_ip, open_ports,
                 port_list, scan_duration, risk_score, threads):
    data = _build_report_data(
        target, target_ip, open_ports, port_list,
        scan_duration, risk_score, threads
    )
    if fmt == "json":
        save_json(filename, data)
    elif fmt == "xml":
        save_xml(filename, data)
    else:
        save_txt(filename, data)

