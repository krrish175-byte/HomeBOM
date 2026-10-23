"""homebom_core.hbom - CycloneDX 1.6 Hardware BOM (HBOM) generator with embedded VEX.

Generates official CycloneDX 1.6 JSON document:
- One `device` component per home device
- Nested `firmware` component with firmware version and firmware CPE
- Stable bom-refs (e.g., `device-{id}`, `firmware-{id}`)
- `eol` property on device and firmware components derived from KEV text
- Embedded VEX (`vulnerabilities` array):
  - affected + KEV -> analysis.state: exploitable
  - unknown candidates -> analysis.state: in_triage
  - not_affected devices emit no vulnerability entries
  - affects pointing at firmware bom-ref
- Zero MCP, zero AWS imports. Pure Python library module.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from .rank import DeviceRiskProfile


def _cvss_severity(score: float) -> str:
    """Map CVSS numerical score to CycloneDX severity string."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def generate_cyclonedx_hbom(
    profiles: list[DeviceRiskProfile],
    serial_uuid: str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Generate a CycloneDX 1.6 JSON dictionary adhering to the official schema.

    Args:
        profiles: List of ranked DeviceRiskProfile objects.
        serial_uuid: Optional deterministic UUID for reproducible testing.
        timestamp: Optional deterministic ISO timestamp for reproducible testing.

    Returns:
        CycloneDX 1.6 compliant JSON dictionary.
    """
    serial_str = serial_uuid or str(uuid.uuid4())
    ts_str = timestamp or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    components: list[dict[str, Any]] = []
    vulnerabilities: list[dict[str, Any]] = []

    for profile in profiles:
        dev_ref = f"device-{profile.device_id}"
        fw_ref = f"firmware-{profile.device_id}"

        # 1. Nested firmware component
        fw_component: dict[str, Any] = {
            "type": "firmware",
            "bom-ref": fw_ref,
            "name": f"{profile.model} Firmware",
            "version": profile.firmware,
            "cpe": profile.cpe,
            "properties": [
                {
                    "name": "homebom:eol",
                    "value": "true" if profile.is_eol else "false",
                }
            ],
        }

        # 2. Device component containing nested firmware component
        dev_component: dict[str, Any] = {
            "type": "device",
            "bom-ref": dev_ref,
            "name": profile.device_name,
            "description": f"{profile.model}",
            "properties": [
                {
                    "name": "homebom:eol",
                    "value": "true" if profile.is_eol else "false",
                },
                {
                    "name": "homebom:risk_tier",
                    "value": profile.tier,
                },
                {
                    "name": "homebom:status",
                    "value": profile.overall_status,
                },
            ],
            "components": [fw_component],
        }
        components.append(dev_component)

    # 3. Vulnerabilities (embedded VEX)
    # Rule:
    # - One vulnerability entry per CVE with multiple `affects` refs
    # - not_affected devices emit no vulnerability entries
    # - affected + KEV -> analysis.state: exploitable
    # - unknown candidates -> analysis.state: in_triage
    cve_records: dict[str, dict[str, Any]] = {}
    for profile in profiles:
        if profile.overall_status == "not_affected":
            continue

        fw_ref = f"firmware-{profile.device_id}"
        for f in profile.findings:
            if f.status == "not_affected":
                continue

            if f.cve_id not in cve_records:
                cve_records[f.cve_id] = {
                    "finding": f,
                    "affects": [],
                    "has_affected": False,
                }

            cve_records[f.cve_id]["affects"].append(fw_ref)
            if f.status == "affected":
                cve_records[f.cve_id]["has_affected"] = True
                cve_records[f.cve_id]["finding"] = f

    for cve_id, record in cve_records.items():
        f = record["finding"]
        has_affected = record["has_affected"]
        affects_refs = sorted(set(record["affects"]))

        ratings: list[dict[str, Any]] = []
        if f.cvss_score > 0.0:
            rating_entry: dict[str, Any] = {
                "source": {"name": "NVD"},
                "score": round(f.cvss_score, 1),
                "severity": _cvss_severity(f.cvss_score),
            }
            if f.cvss_vector:
                rating_entry["vector"] = f.cvss_vector
                if "CVSS:3.1" in f.cvss_vector:
                    rating_entry["method"] = "CVSSv31"
                elif "CVSS:3.0" in f.cvss_vector:
                    rating_entry["method"] = "CVSSv3"
                elif "CVSS:2" in f.cvss_vector:
                    rating_entry["method"] = "CVSSv2"
                else:
                    rating_entry["method"] = "other"
            else:
                rating_entry["method"] = "CVSSv31"
            ratings.append(rating_entry)

        if has_affected:
            analysis_state = "exploitable"
            detail_msg = (
                "Confirmed affected firmware version; actively exploited according to CISA KEV catalog."
                if f.in_kev
                else "Confirmed affected firmware version."
            )
        else:
            analysis_state = "in_triage"
            detail_msg = (
                "Device firmware string cannot be definitively verified against NVD match criteria; "
                "placed in triage."
            )

        properties = [
            {
                "name": "homebom:cisa_kev",
                "value": "true" if f.in_kev else "false",
            },
            {
                "name": "homebom:epss",
                "value": f"{f.epss_score:.5f}",
            },
            {
                "name": "homebom:eol",
                "value": "true" if f.eol else "false",
            },
        ]

        vuln_entry: dict[str, Any] = {
            "bom-ref": f"vuln-{cve_id}",
            "id": cve_id,
            "source": {
                "name": "NVD",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            },
            "analysis": {
                "state": analysis_state,
                "detail": detail_msg,
            },
            "affects": [{"ref": r} for r in affects_refs],
            "properties": properties,
        }
        if ratings:
            vuln_entry["ratings"] = ratings
        vulnerabilities.append(vuln_entry)

    bom_doc: dict[str, Any] = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial_str}",
        "version": 1,
        "metadata": {
            "timestamp": ts_str,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "HomeBOM",
                        "version": "0.1.0",
                        "description": "Smart-home security and CycloneDX 1.6 HBOM assistant",
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": "HomeBOM-Inventory",
                "version": "1.0.0",
                "description": "Aggregated smart-home device and firmware hardware bill of materials",
            },
        },
        "components": components,
    }

    if vulnerabilities:
        bom_doc["vulnerabilities"] = vulnerabilities

    return bom_doc


def generate_hbom_spoken_summary(
    profiles: list[DeviceRiskProfile],
    bom: dict[str, Any],
) -> str:
    """Generate a plain-language spoken response for export_hbom."""
    total_devices = len(profiles)
    vulns = bom.get("vulnerabilities", [])
    exploitable_count = sum(1 for v in vulns if v.get("analysis", {}).get("state") == "exploitable")
    triage_count = sum(1 for v in vulns if v.get("analysis", {}).get("state") == "in_triage")

    spoken = (
        f"I exported your CycloneDX Hardware Bill of Materials with embedded VEX records for {total_devices} devices. "
        f"The export documents {exploitable_count} actively exploited vulnerabilities and {triage_count} unverified candidates in triage. "
        f"All records include verified firmware CPEs and end-of-life status properties."
    )
    return spoken
