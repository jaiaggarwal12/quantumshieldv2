"""
QuantumShield — AI Explanation Router
Uses OpenAI GPT-4o to generate plain-English explanations of scan results.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import os
import json
import urllib.request
import urllib.error

router = APIRouter(prefix="/api/v1/ai", tags=["AI"])

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL   = os.getenv("OPENAI_MODEL", "gpt-4o-mini")  # cheap + fast


class ExplainRequest(BaseModel):
    target: str
    pqc_score: int
    pqc_status: str
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    key_exchange: Optional[str] = None
    cert_key_type: Optional[str] = None
    cert_key_bits: Optional[int] = None
    forward_secrecy: Optional[bool] = None
    days_until_expiry: Optional[int] = None
    vulnerabilities: Optional[list] = []
    top_issues: Optional[list] = []
    audience: str = "ceo"   # ceo | technical | board


def _build_prompt(req: ExplainRequest) -> str:
    vulns = [v.get("name","") for v in (req.vulnerabilities or [])[:6]]
    vuln_str = ", ".join(vulns) if vulns else "None detected"
    issues = [i.get("issue","") for i in (req.top_issues or [])[:4]]
    hndl = "HNDL" in vuln_str
    score = req.pqc_score
    cert = f"{req.cert_key_type or '?'}-{req.cert_key_bits or 0}"
    tls = req.tls_version or "Unknown"
    kex = req.key_exchange or "Unknown"

    if req.audience == "ceo":
        return f"""You are a cybersecurity consultant. Write a 3-paragraph CEO briefing — no technical jargon, no bullet points, flowing prose only.

Paragraph 1 (The situation): Explain in plain English what we found at {req.target}. Score is {score}/100. The encryption type is {cert}. Use an analogy — compare RSA encryption to a padlock that quantum computers can pick instantly.

Paragraph 2 (The risk): {"This site is exposed to Harvest Now Decrypt Later attacks — adversaries are recording encrypted traffic today to decrypt it once quantum computers exist. Explain this like explaining it to a non-technical CEO of a bank." if hndl else f"Explain why a score of {score}/100 is a problem for a bank and what data could be at risk."}

Paragraph 3 (What to do): Give 2-3 specific business actions — not technical ones. Budget timeframe, who owns it, what success looks like.

Tone: Calm but urgent. Like a trusted advisor, not an alarmist. No headers, no bullet points."""

    elif req.audience == "board":
        return f"""You are a CISO presenting to a bank board. Write a formal board-level briefing with these exact sections. Keep each section to 2-3 sentences max.

**EXECUTIVE RISK SUMMARY**
State the risk level ({score}/100) and what it means for the bank's regulatory standing.

**THREAT LANDSCAPE**  
Explain quantum computing timeline (2030-2035 estimate) and why {cert} encryption will be broken. Mention HNDL if relevant: {hndl}.

**REGULATORY EXPOSURE**
Reference RBI cybersecurity guidelines, DPDP Act 2023, and CERT-In requirements for cryptographic hygiene. State what audit findings could emerge.

**FINANCIAL IMPACT ESTIMATE**
Rough cost of migration vs cost of breach. Include reputational risk.

**BOARD RESOLUTION REQUIRED**
One clear ask from the board — budget approval / steering committee / timeline mandate.

Be formal, precise, governance-focused."""

    else:  # technical
        return f"""You are a senior security engineer. Write a technical briefing for the dev/security team. Be specific, clinical, no fluff.

FORMAT:
FINDINGS: List what was detected — TLS: {tls}, Cipher: {req.cipher_suite or 'unknown'}, KEX: {kex}, Cert: {cert}, FS: {"yes" if req.forward_secrecy else "no"}, Vulns: {vuln_str}

ROOT CAUSE: Explain exactly WHY each finding is a quantum risk. Name the specific algorithm (Shor's for RSA/ECC, Grover's for AES-128). Give the mathematical reason, not just "it's vulnerable."

CVSS/QUANTUM RISK: Score is {score}/100. Map which findings contributed most to deductions.

REMEDIATION STEPS (priority order):
Give exact, actionable steps with specific algorithm names (e.g. "Replace RSA-2048 with ML-DSA-65 per FIPS 204", "Deploy X25519+ML-KEM-768 hybrid KEX per RFC 9180"). Include config file examples where relevant.

TIMELINE: Emergency (0-30 days) / Short-term (3-6 months) / Long-term (12-24 months) breakdown.

Be terse. Engineers hate padding."""


@router.post("/explain")
async def explain_scan(req: ExplainRequest):
    """Generate AI explanation of scan results using OpenAI."""
    if not OPENAI_API_KEY:
        # Return helpful fallback if no API key configured
        return {
            "explanation": _fallback_explanation(req),
            "source": "rule-based",
            "model": None
        }

    prompt = _build_prompt(req)

    payload = json.dumps({
        "model": OPENAI_MODEL,
        "messages": [
            {"role": "system", "content": "You are QuantumShield AI, a post-quantum cryptography expert assistant integrated into a cybersecurity scanner used by banks and enterprises."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 400,
        "temperature": 0.7,
    }).encode("utf-8")

    try:
        request = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {OPENAI_API_KEY}",
            },
            method="POST"
        )
        with urllib.request.urlopen(request, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            text = data["choices"][0]["message"]["content"].strip()
            return {
                "explanation": text,
                "source": "openai",
                "model": OPENAI_MODEL,
                "tokens_used": data.get("usage", {}).get("total_tokens", 0)
            }
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=502, detail=f"OpenAI error: {body[:200]}")
    except Exception as e:
        # Graceful fallback
        return {
            "explanation": _fallback_explanation(req),
            "source": "rule-based",
            "model": None,
            "error": str(e)
        }


def _fallback_explanation(req: ExplainRequest) -> str:
    """Rule-based fallback when OpenAI is unavailable."""
    score = req.pqc_score
    target = req.target
    tls = req.tls_version or "unknown TLS version"
    cert = f"{req.cert_key_type or '?'}-{req.cert_key_bits or 0}"

    if score >= 75:
        risk = "low quantum risk"
        action = "Continue monitoring and plan full ML-DSA certificate migration."
    elif score >= 55:
        risk = "moderate quantum risk"
        action = "Priority: deploy ML-KEM-768 hybrid key exchange and plan certificate migration to ML-DSA-65."
    elif score >= 35:
        risk = "significant quantum risk"
        action = "Immediate action required: upgrade to TLS 1.3, replace weak ciphers, begin PQC migration planning."
    else:
        risk = "critical quantum risk"
        action = "Emergency: this site has critical cryptographic weaknesses. Engage security team immediately."

    hndl = any(v.get("name") == "HNDL" for v in (req.vulnerabilities or []))
    hndl_note = (
        " Nation-state adversaries may already be recording your encrypted traffic today to decrypt once quantum computers arrive — a threat known as Harvest Now, Decrypt Later."
        if hndl else ""
    )

    return (
        f"{target} scored {score}/100 on our Post-Quantum Cryptography assessment, indicating {risk}. "
        f"The site is using {tls} with a {cert} certificate — a type of encryption that would be broken by a sufficiently powerful quantum computer using Shor's Algorithm in hours, not years.{hndl_note} "
        f"{action}"
    )
