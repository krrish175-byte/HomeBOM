"""homebom_core.rank - Priority risk ranking and plain-language phrasing.

Zero MCP, zero AWS imports. Pure Python library module.
"""

from dataclasses import dataclass
from typing import Literal

from .match import VulnerabilityFinding

RiskTier = Literal["fix_now", "fix_soon", "low", "unknown", "not_affected"]

TIER_ORDER: dict[RiskTier, int] = {
    "fix_now": 0,
    "fix_soon": 1,
    "low": 2,
    "unknown": 3,
    "not_affected": 4,
}


@dataclass
class DeviceRiskProfile:
    """Consolidated risk profile for a smart-home device."""
    device_id: str
    device_name: str
    model: str
    firmware: str
    cpe: str
    overall_status: str
    tier: RiskTier
    max_epss: float
    max_cvss: float
    is_eol: bool
    findings: list[VulnerabilityFinding]
    spoken_summary: str
    fix_steps: str


def determine_device_tier(
    overall_status: str,
    findings: list[VulnerabilityFinding],
) -> RiskTier:
    """Rule 4: Priority Ranking based on real-world active exploitation & probability.
    
    Tiers:
      1. fix_now: affected + listed on CISA KEV
      2. fix_soon: affected and (EPSS >= 0.10 or CVSS >= 9.0)
      3. low: other affected devices
      4. unknown: cannot verify firmware or no NVD match data
      5. not_affected: clean in NVD records
    """
    if overall_status == "affected":
        # Check KEV
        if any(f.in_kev and f.status == "affected" for f in findings):
            return "fix_now"
        # Check EPSS >= 0.10 or CVSS >= 9.0
        if any((f.epss_score >= 0.10 or f.cvss_score >= 9.0) and f.status == "affected" for f in findings):
            return "fix_soon"
        return "low"

    if overall_status == "unknown":
        return "unknown"

    return "not_affected"


def generate_device_spoken_text(
    name: str,
    tier: RiskTier,
    is_eol: bool,
    top_finding: VulnerabilityFinding | None = None,
) -> str:
    """Requirement 2 & 3: Generate voice-optimized plain-language string.
    
    Rules:
      - Zero-CVE / clean devices speak as 'no known vulnerabilities in public databases', never 'safe'.
      - unknown speaks as "I can't verify this one".
      - EoL devices must include 'replace' in spoken text.
      - Never read CVE IDs aloud. Max 3 sentences.
    """
    if tier == "unknown":
        return f"I can't verify {name} because its firmware version cannot be verified against known security databases. I recommend checking the manufacturer's app for updates."

    if tier == "not_affected":
        return f"{name} currently has no known vulnerabilities in public databases."

    # Affected devices:
    if is_eol:
        return f"{name} has a critical security flaw and is officially discontinued by the manufacturer. You should replace this device immediately as no security updates are available."

    if tier == "fix_now":
        return f"{name} has an actively exploited vulnerability that needs immediate attention. You should update its firmware right away."

    if tier == "fix_soon":
        return f"{name} has a high-probability vulnerability that should be patched soon. Please check for a firmware update."

    return f"{name} has known software vulnerabilities. You should apply available firmware updates."


def generate_fix_steps(
    name: str,
    tier: RiskTier,
    is_eol: bool,
) -> str:
    """Generate concise, actionable one-sentence remediation instructions.
    
    Requirement 2: get_fix_steps must say 'replace' for EoL devices.
    """
    if is_eol:
        return f"Replace {name} with a supported model, as it is end-of-life and will not receive security patches."

    if tier in ("fix_now", "fix_soon", "low"):
        return f"Update {name} firmware to the latest release via the manufacturer app or administrative settings."

    if tier == "unknown":
        return f"Check {name} in the vendor app to ensure it is running official, up-to-date firmware."

    return f"No action needed for {name}; keep automatic updates enabled."


def rank_device(
    device_id: str,
    device_name: str,
    model: str,
    firmware: str,
    cpe: str,
    overall_status: str,
    findings: list[VulnerabilityFinding],
) -> DeviceRiskProfile:
    """Rank a single device and build its complete risk profile."""
    tier = determine_device_tier(overall_status, findings)
    
    # Calculate max scores and EoL status across affected findings
    affected_findings = [f for f in findings if f.status == "affected"]
    relevant_findings = affected_findings if affected_findings else findings

    max_epss = max((f.epss_score for f in relevant_findings), default=0.0)
    max_cvss = max((f.cvss_score for f in relevant_findings), default=0.0)
    is_eol = any(f.eol for f in relevant_findings)

    top_finding = max(relevant_findings, key=lambda f: (f.in_kev, f.epss_score, f.cvss_score), default=None)

    spoken = generate_device_spoken_text(device_name, tier, is_eol, top_finding)
    fix = generate_fix_steps(device_name, tier, is_eol)

    return DeviceRiskProfile(
        device_id=device_id,
        device_name=device_name,
        model=model,
        firmware=firmware,
        cpe=cpe,
        overall_status=overall_status,
        tier=tier,
        max_epss=max_epss,
        max_cvss=max_cvss,
        is_eol=is_eol,
        findings=findings,
        spoken_summary=spoken,
        fix_steps=fix,
    )


def sort_ranked_devices(profiles: list[DeviceRiskProfile]) -> list[DeviceRiskProfile]:
    """Sort profiles by: tier priority, EPSS desc, CVSS desc.
    
    Priority ranking orders actively exploited threats first, not raw CVSS.
    """
    return sorted(
        profiles,
        key=lambda p: (
            TIER_ORDER.get(p.tier, 99),
            -p.max_epss,
            -p.max_cvss,
        ),
    )
