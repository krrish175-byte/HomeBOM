"""homebom_core.match - Vulnerability matching and defensive three-state logic.

Zero MCP, zero AWS imports. Pure Python library module.
"""

from dataclasses import dataclass
from typing import Any, Literal

from .versions import extract_version_info, match_firmware_range

MatchState = Literal["affected", "not_affected", "unknown"]


@dataclass
class VulnerabilityFinding:
    """Represents a matched vulnerability finding for a specific device."""

    cve_id: str
    status: MatchState
    cvss_score: float
    cvss_vector: str | None
    epss_score: float
    in_kev: bool
    eol: bool
    description: str
    criteria_matched: str | None


def is_eol_vulnerability(kev_entry: dict[str, Any] | None) -> bool:
    """Requirement 2: Derive eol boolean by searching KEV shortDescription for 'end-of-life' or 'end-of-service'.

    Zero hardcoding. Strictly searches the text of the CISA KEV catalog entry.
    """
    if not kev_entry:
        return False

    short_desc = kev_entry.get("shortDescription", "").lower()
    return (
        "end-of-life" in short_desc
        or "end-of-service" in short_desc
        or "(eol)" in short_desc
        or "(eos)" in short_desc
    )


def extract_cvss(cve_dict: dict[str, Any]) -> tuple[float, str | None]:
    """Extract primary CVSS score and vector string from NVD CVE structure."""
    metrics = cve_dict.get("metrics", {})

    # Try CVSS v3.1 first
    v31_list = metrics.get("cvssMetricV31", [])
    if v31_list:
        data = v31_list[0].get("cvssData", {})
        score = data.get("baseScore", 0.0)
        vector = data.get("vectorString")
        return (float(score), vector)

    # Try CVSS v3.0 next
    v30_list = metrics.get("cvssMetricV30", [])
    if v30_list:
        data = v30_list[0].get("cvssData", {})
        score = data.get("baseScore", 0.0)
        vector = data.get("vectorString")
        return (float(score), vector)

    # Fallback to CVSS v2.0
    v2_list = metrics.get("cvssMetricV2", [])
    if v2_list:
        data = v2_list[0].get("cvssData", {})
        score = data.get("baseScore", 0.0)
        vector = data.get("vectorString")
        return (float(score), vector)

    return (0.0, None)


def evaluate_cve_match(
    cve_dict: dict[str, Any],
    device_firmware: str,
    device_cpe: str,
    kev_catalog: dict[str, Any] | set[str] | None = None,
    epss_scores: dict[str, float] | None = None,
) -> VulnerabilityFinding | None:
    """Evaluate whether a device's firmware matches a single NVD CVE record.

    Returns VulnerabilityFinding or None if the device's CPE is not part of this CVE's configurations.
    """
    cve_id = cve_dict.get("id", "UNKNOWN")
    descriptions = cve_dict.get("descriptions", [])
    en_desc = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")

    cvss_score, cvss_vector = extract_cvss(cve_dict)

    # EPSS score lookup
    epss_score = 0.0
    if epss_scores and cve_id in epss_scores:
        epss_score = float(epss_scores[cve_id])

    # KEV catalog lookup
    in_kev = False
    kev_entry = None
    if isinstance(kev_catalog, dict) and cve_id in kev_catalog:
        in_kev = True
        kev_entry = kev_catalog[cve_id]
    elif isinstance(kev_catalog, set) and cve_id in kev_catalog:
        in_kev = True

    eol = is_eol_vulnerability(kev_entry)

    # Check configurations
    configs = cve_dict.get("configurations", [])
    cpe_prefix = ":".join(device_cpe.split(":")[:5])  # e.g. cpe:2.3:o:vendor:product

    found_cpe_match = False
    overall_status: MatchState = "not_affected"
    matched_criteria = None

    for cfg in configs:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue

                criteria = match.get("criteria", "")
                if not criteria.startswith(cpe_prefix):
                    continue

                found_cpe_match = True
                matched_criteria = criteria

                v_start_incl = match.get("versionStartIncluding")
                v_start_excl = match.get("versionStartExcluding")
                v_end_incl = match.get("versionEndIncluding")
                v_end_excl = match.get("versionEndExcluding")

                # If no ranges are defined:
                if not any([v_start_incl, v_start_excl, v_end_incl, v_end_excl]):
                    # Exact criteria version check
                    crit_tokens = criteria.split(":")
                    crit_version = crit_tokens[5] if len(crit_tokens) > 5 else "*"
                    if crit_version in ("*", "-"):
                        # Cannot determine version boundary defensively
                        if overall_status != "affected":
                            overall_status = "unknown"
                    else:
                        # Exact version check
                        if crit_version in device_firmware:
                            overall_status = "affected"
                    continue

                # Range match check
                status = match_firmware_range(
                    firmware_str=device_firmware,
                    version_start_including=v_start_incl,
                    version_start_excluding=v_start_excl,
                    version_end_including=v_end_incl,
                    version_end_excluding=v_end_excl,
                )

                if status == "affected":
                    overall_status = "affected"
                    break
                elif status == "unknown" and overall_status != "affected":
                    overall_status = "unknown"

            if overall_status == "affected":
                break
        if overall_status == "affected":
            break

    if not found_cpe_match:
        return None

    return VulnerabilityFinding(
        cve_id=cve_id,
        status=overall_status,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        epss_score=epss_score,
        in_kev=in_kev,
        eol=eol,
        description=en_desc,
        criteria_matched=matched_criteria,
    )


def match_device_vulnerabilities(
    device_firmware: str,
    device_cpe: str,
    nvd_vulnerabilities: list[dict[str, Any]],
    kev_catalog: dict[str, Any] | set[str] | None = None,
    epss_scores: dict[str, float] | None = None,
) -> tuple[MatchState, list[VulnerabilityFinding]]:
    """Match a device against a list of NVD CVE records.

    Returns:
      (device_overall_state, list_of_findings)

    Rule 3: unknown must NEVER be reported as safe.
    """
    fw_info = extract_version_info(device_firmware)
    findings: list[VulnerabilityFinding] = []
    for item in nvd_vulnerabilities:
        cve_dict = item.get("cve", item)
        finding = evaluate_cve_match(
            cve_dict=cve_dict,
            device_firmware=device_firmware,
            device_cpe=device_cpe,
            kev_catalog=kev_catalog,
            epss_scores=epss_scores,
        )
        if finding:
            findings.append(finding)

    # Rule 3: Defensive check - unparseable firmware can never be evaluated as not_affected
    if fw_info.is_unparseable:
        return ("unknown", findings)

    # Determine overall device status
    if any(f.status == "affected" for f in findings):
        overall_state: MatchState = "affected"
    elif any(f.status == "unknown" for f in findings):
        overall_state = "unknown"
    else:
        overall_state = "not_affected"

    return (overall_state, findings)
