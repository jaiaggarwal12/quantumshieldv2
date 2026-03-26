"""
QuantumShield — API Scanner & VPN Probe Router
Closes the two explicit gaps from PNB problem statement:
  - "Crypto inventory discovery (TLS Certificate, TLS-based VPN, APIs)"
Also adds:
  - CSV export (problem statement requires JSON, XML, CSV)
  - CERT-In CBOM elements mapping
"""

import csv
import io
import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.routers.auth import get_current_user
from app.services.api_scanner import scan_api_endpoints, scan_vpn_endpoints

router = APIRouter(prefix="/api/v1", tags=["API Scanner", "VPN", "Export"])


# ── Schemas ───────────────────────────────────────────────────────────────────
class APIScanRequest(BaseModel):
    base_url: str
    port: int = 443

class VPNScanRequest(BaseModel):
    hostname: str
    timeout: float = 2.5

class CSVExportRequest(BaseModel):
    results: list   # array of scan result objects


# ── API Scanner ───────────────────────────────────────────────────────────────
@router.post("/scan/api")
async def scan_api(request: APIScanRequest,
                   current_user: User = Depends(get_current_user)):
    """
    Discover and scan API endpoints on a target.
    Probes 20+ common API paths and reports TLS config per endpoint.
    Maps results to CERT-In CBOM elements.
    """
    if not request.base_url.strip():
        raise HTTPException(status_code=400, detail="base_url is required")

    result = scan_api_endpoints(request.base_url, timeout=5)
    return result


# ── VPN Probe ─────────────────────────────────────────────────────────────────
@router.post("/scan/vpn")
async def scan_vpn(request: VPNScanRequest,
                   current_user: User = Depends(get_current_user)):
    """
    Probe common VPN ports on a target:
    IKEv2 (UDP 500/4500), OpenVPN (UDP/TCP 1194), SSL-VPN (TCP 443/4433/8443),
    WireGuard (UDP 51820), PPTP (TCP 1723), L2TP (UDP 1701).
    Reports TLS version and cipher for TLS-based VPNs.
    """
    hostname = request.hostname.replace("https://", "").replace("http://", "").split("/")[0].strip()
    if not hostname:
        raise HTTPException(status_code=400, detail="hostname is required")

    result = scan_vpn_endpoints(hostname, timeout=request.timeout)
    return result


# ── Combined Full Scan (TLS + API + VPN) ──────────────────────────────────────
@router.post("/scan/full")
async def full_scan(request: APIScanRequest,
                    current_user: User = Depends(get_current_user)):
    """
    Full asset scan: TLS + API endpoints + VPN ports in one call.
    Returns unified CERT-In CBOM inventory.
    """
    from app.services.scanner_service import scan_tls_target, check_http_security_headers
    import asyncio, concurrent.futures

    base = request.base_url.replace("https://", "").replace("http://", "").split("/")[0].strip()

    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        tls_future = loop.run_in_executor(pool, scan_tls_target, base, request.port)
        api_future = loop.run_in_executor(pool, scan_api_endpoints, request.base_url, 4)
        vpn_future = loop.run_in_executor(pool, scan_vpn_endpoints, base, 2.0)
        tls_result, api_result, vpn_result = await asyncio.gather(tls_future, api_future, vpn_future)

    # Add HTTP headers to TLS result
    try:
        tls_result["http_headers"] = check_http_security_headers(base, request.port)
    except Exception:
        pass

    # Build unified CERT-In CBOM
    cert_in_cbom = _build_cert_in_cbom(tls_result, api_result, vpn_result)

    return {
        "target": base,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_type": "full",
        "tls_scan": tls_result,
        "api_scan": api_result,
        "vpn_scan": vpn_result,
        "cert_in_cbom": cert_in_cbom,
        "total_assets_found": (
            1 +  # web server
            len(api_result.get("endpoints_reachable", [])) +
            len([e for e in vpn_result.get("vpn_endpoints", []) if e.get("open")])
        ),
    }


def _build_cert_in_cbom(tls: dict, api: dict, vpn: dict) -> dict:
    """Build CERT-In Annexure-A compliant CBOM from all scan sources."""
    timestamp = datetime.now(timezone.utc).isoformat()
    components = []

    # Web server TLS
    tls_info = tls.get("tls_info", {})
    cert = tls.get("certificate", {})
    if tls_info:
        components.append({
            "cbom_element": "TLS Certificate",
            "asset_type": "Web Server",
            "asset_id": tls.get("target", ""),
            "protocol_version": tls_info.get("tls_version", ""),
            "cipher_suite": tls_info.get("cipher_suite", ""),
            "key_exchange": tls_info.get("key_exchange", ""),
            "certificate_algorithm": f"{cert.get('key_type','?')}-{cert.get('key_bits',0)}",
            "certificate_expiry": cert.get("not_after", ""),
            "forward_secrecy": tls_info.get("forward_secrecy", False),
            "quantum_safe": cert.get("pqc_cert", False),
            "pqc_status": tls.get("pqc_assessment", {}).get("status", "UNKNOWN"),
            "pqc_score": tls.get("pqc_assessment", {}).get("score", 0),
        })

    # API endpoints
    for ep in api.get("cert_in_cbom", []):
        components.append({
            "cbom_element": "API Endpoint",
            "asset_type": "API",
            "asset_id": ep.get("endpoint", ""),
            "protocol_version": ep.get("protocol", ""),
            "cipher_suite": ep.get("cipher_suite", ""),
            "key_exchange": "N/A",
            "certificate_algorithm": ep.get("cert_algorithm", ""),
            "forward_secrecy": ep.get("forward_secrecy", False),
            "quantum_safe": ep.get("quantum_safe", False),
            "pqc_status": "QUANTUM_SAFE" if ep.get("quantum_safe") else "TRANSITIONING",
            "pqc_score": None,
        })

    # VPN endpoints
    for ep in vpn.get("cert_in_cbom", []):
        components.append({
            "cbom_element": "TLS-VPN",
            "asset_type": "VPN",
            "asset_id": ep.get("endpoint", ""),
            "protocol_version": ep.get("protocol", ""),
            "cipher_suite": ep.get("cipher_suite", ""),
            "key_exchange": "IKEv2/TLS",
            "certificate_algorithm": "N/A",
            "forward_secrecy": None,
            "quantum_safe": ep.get("quantum_safe", False),
            "pqc_status": "QUANTUM_SAFE" if ep.get("quantum_safe") else "TRANSITIONING",
            "pqc_score": None,
        })

    return {
        "schema": "CERT-In CBOM Annexure-A",
        "generated_at": timestamp,
        "target": tls.get("target", ""),
        "total_components": len(components),
        "components": components,
        "quantum_safe_count": sum(1 for c in components if c.get("quantum_safe")),
        "quantum_vulnerable_count": sum(1 for c in components if not c.get("quantum_safe")),
    }


# ── CSV Export ────────────────────────────────────────────────────────────────
@router.post("/export/csv")
async def export_csv(request: CSVExportRequest,
                     _: User = Depends(get_current_user)):
    """
    Export scan results as CSV.
    Problem statement requires: JSON, XML, CSV machine-readable formats.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow([
        "Target", "Port", "Scan Status",
        "TLS Version", "Cipher Suite", "Cipher Grade", "Forward Secrecy",
        "Key Exchange",
        "Cert Type", "Cert Bits", "Cert Expires (Days)", "Self Signed", "CT Logs (SCTs)",
        "PQC Score", "PQC Status",
        "Vulnerabilities Count", "Vulnerabilities",
        "HSTS", "DNS CAA", "DNSSEC",
        "Scan Timestamp"
    ])

    for r in request.results:
        tls = r.get("tls_info", {})
        cert = r.get("certificate", {})
        pqc = r.get("pqc_assessment", {})
        dns = r.get("dns", {})
        http = r.get("http_headers", {})
        vulns = r.get("vulnerabilities", [])
        vuln_names = "|".join(v.get("name", "") for v in vulns)

        writer.writerow([
            r.get("target", ""),
            r.get("port", 443),
            r.get("status", ""),
            tls.get("tls_version", ""),
            tls.get("cipher_suite", ""),
            tls.get("cipher_grade", ""),
            "Yes" if tls.get("forward_secrecy") else "No",
            tls.get("key_exchange", ""),
            cert.get("key_type", ""),
            cert.get("key_bits", ""),
            cert.get("days_until_expiry", ""),
            "Yes" if cert.get("is_self_signed") else "No",
            cert.get("ct_sct_count", 0),
            pqc.get("score", ""),
            pqc.get("status", ""),
            len(vulns),
            vuln_names,
            "Yes" if http.get("hsts", {}).get("present") else "No",
            "Yes" if dns.get("caa_present") else "No",
            "Yes" if dns.get("dnssec_enabled") else "No",
            r.get("timestamp", ""),
        ])

    output.seek(0)
    filename = f"QuantumShield-{datetime.now().strftime('%Y%m%d-%H%M')}.csv"
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


# ── XML Export ────────────────────────────────────────────────────────────────
@router.post("/export/xml")
async def export_xml(request: CSVExportRequest,
                     _: User = Depends(get_current_user)):
    """Export scan results as XML (CERT-In compatible)."""
    timestamp = datetime.now(timezone.utc).isoformat()
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<QuantumShieldReport generated="{timestamp}" schema="CERT-In-CBOM-v1.0">',
    ]

    for r in request.results:
        tls  = r.get("tls_info", {})
        cert = r.get("certificate", {})
        pqc  = r.get("pqc_assessment", {})
        vulns = r.get("vulnerabilities", [])

        lines.append(f'  <Asset target="{r.get("target","")}" port="{r.get("port",443)}">')
        lines.append(f'    <TLS version="{tls.get("tls_version","")}" cipher="{tls.get("cipher_suite","")}" grade="{tls.get("cipher_grade","")}" forward_secrecy="{tls.get("forward_secrecy",False)}"/>')
        lines.append(f'    <Certificate type="{cert.get("key_type","")}" bits="{cert.get("key_bits","")}" expires_days="{cert.get("days_until_expiry","")}" quantum_safe="{cert.get("pqc_cert",False)}"/>')
        lines.append(f'    <PQCAssessment score="{pqc.get("score","")}" status="{pqc.get("status","")}">')
        for issue in pqc.get("issues", [])[:5]:
            lines.append(f'      <Issue severity="{issue.get("severity","")}" description="{issue.get("issue","").replace(chr(34), chr(39))}"/>')
        lines.append(f'    </PQCAssessment>')
        lines.append(f'    <Vulnerabilities count="{len(vulns)}">')
        for v in vulns:
            lines.append(f'      <Vulnerability name="{v.get("name","")}" cve="{v.get("cve","")}" severity="{v.get("severity","")}" quantum="true"/>')
        lines.append(f'    </Vulnerabilities>')
        lines.append(f'  </Asset>')

    lines.append('</QuantumShieldReport>')
    xml_content = "\n".join(lines)

    filename = f"QuantumShield-{datetime.now().strftime('%Y%m%d-%H%M')}.xml"
    return Response(
        content=xml_content,
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
