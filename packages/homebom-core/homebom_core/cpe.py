"""homebom_core.cpe - CPE validation, parsing, and candidate resolution.

Zero MCP, zero AWS imports. Pure Python library module.
"""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class CPE:
    """Structured representation of a CPE 2.3 formatted string."""
    part: str        # 'o' for operating system / firmware, 'h' for hardware, 'a' for application
    vendor: str
    product: str
    version: str
    update: str
    edition: str
    language: str
    sw_edition: str
    target_sw: str
    target_hw: str
    other: str
    raw: str

    @property
    def is_firmware(self) -> bool:
        """Rule 2: Devices must resolve to firmware CPEs (part == 'o')."""
        return self.part == "o"


def parse_cpe(cpe_str: str) -> CPE:
    """Parse a CPE 2.3 formatted string into components."""
    if not cpe_str.startswith("cpe:2.3:"):
        raise ValueError(f"Invalid CPE 2.3 format: {cpe_str}")

    tokens = cpe_str[len("cpe:2.3:"):].split(":")
    if len(tokens) < 11:
        # Pad with wildcards if truncated
        tokens.extend(["*"] * (11 - len(tokens)))

    return CPE(
        part=tokens[0],
        vendor=tokens[1],
        product=tokens[2],
        version=tokens[3],
        update=tokens[4],
        edition=tokens[5],
        language=tokens[6],
        sw_edition=tokens[7],
        target_sw=tokens[8],
        target_hw=tokens[9],
        other=tokens[10],
        raw=cpe_str,
    )


def is_valid_firmware_cpe(cpe_str: str) -> bool:
    """Check if the string is a valid firmware CPE (cpe:2.3:o:...)."""
    try:
        parsed = parse_cpe(cpe_str)
        return parsed.is_firmware
    except (ValueError, IndexError):
        return False


def normalize_token(text: str) -> str:
    """Normalize names for candidate matching."""
    return re.sub(r"[^a-z0-9]", "", text.lower())


def match_candidate_cpe(
    query_text: str,
    candidates: list[str],
) -> tuple[str | None, list[str]]:
    """Match device query text against candidate firmware CPEs.
    
    Returns:
      (best_match_cpe, possible_candidates)
    """
    clean_query = normalize_token(query_text)
    if not clean_query:
        return (None, [])

    matches = []
    for cpe_str in candidates:
        parsed = parse_cpe(cpe_str)
        v_norm = normalize_token(parsed.vendor)
        p_norm = normalize_token(parsed.product)

        score = 0
        if v_norm in clean_query or clean_query in v_norm:
            score += 2
        if p_norm in clean_query or clean_query in p_norm:
            score += 3

        # Substring checks for model numbers
        for part in re.split(r"[\s-_]+", query_text.lower()):
            if len(part) >= 3 and (part in parsed.product.lower() or part in parsed.vendor.lower()):
                score += 1

        if score > 0:
            matches.append((score, cpe_str))

    matches.sort(key=lambda x: x[0], reverse=True)
    if not matches:
        return (None, [])

    top_score = matches[0][0]
    best_cpe = matches[0][1]

    # Return top candidates
    candidate_cpes = [m[1] for m in matches if m[0] >= max(1, top_score - 1)]
    return (best_cpe, candidate_cpes)
