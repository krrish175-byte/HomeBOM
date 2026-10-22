"""homebom_core - Independent, MIT-licensed core engine for HomeBOM.

Zero MCP, zero AWS dependencies. Pure Python package.
"""

from .cpe import CPE, is_valid_firmware_cpe, match_candidate_cpe, parse_cpe
from .match import VulnerabilityFinding, is_eol_vulnerability, match_device_vulnerabilities
from .rank import (
    DeviceRiskProfile,
    RiskTier,
    determine_device_tier,
    generate_device_spoken_text,
    generate_fix_steps,
    rank_device,
    sort_ranked_devices,
)
from .versions import (
    MatchState,
    VersionInfo,
    compare_like_with_like,
    extract_version_info,
    match_firmware_range,
)

__version__ = "0.1.0"

__all__ = [
    "CPE",
    "DeviceRiskProfile",
    "MatchState",
    "RiskTier",
    "VersionInfo",
    "VulnerabilityFinding",
    "compare_like_with_like",
    "determine_device_tier",
    "extract_version_info",
    "generate_device_spoken_text",
    "generate_fix_steps",
    "is_eol_vulnerability",
    "is_valid_firmware_cpe",
    "match_candidate_cpe",
    "match_device_vulnerabilities",
    "match_firmware_range",
    "parse_cpe",
    "rank_device",
    "sort_ranked_devices",
]
