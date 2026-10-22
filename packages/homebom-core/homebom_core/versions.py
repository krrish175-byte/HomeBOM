"""homebom_core.versions - Firmware version extraction and defensive range comparison.

Zero MCP, zero AWS imports. Pure Python library module.
"""

import re
from dataclasses import dataclass
from typing import Literal

MatchState = Literal["affected", "not_affected", "unknown"]


@dataclass(frozen=True)
class VersionInfo:
    """Structured representation of parsed firmware strings."""

    raw: str
    version_tuple: tuple[int, ...] | None
    build_token: int | None
    is_date_only: bool = False
    is_unparseable: bool = False


# Regex patterns for build dates and numeric version tuples
BUILD_TOKEN_REGEX = re.compile(
    r"(?:build|rel|release)?[\s_:-]*(\b\d{6}\b|\b\d{8}\b)",
    re.IGNORECASE,
)
DATE_DASH_REGEX = re.compile(r"\b(\d{4})[-_](\d{2})[-_](\d{2})\b")
DOTTED_VERSION_REGEX = re.compile(
    r"(?:v|ver|version|fireos|rel)?[\s_:-]*(\d+(?:\.\d+)+)",
    re.IGNORECASE,
)


def extract_version_info(firmware_str: str) -> VersionInfo:
    """Extract numeric semver tuple and build-date tokens from messy firmware strings.

    Examples:
        '1.1.2 Build 20220624' -> version_tuple=(1, 1, 2), build_token=20220624
        '1.0.0 Build 200508'   -> version_tuple=(1, 0, 0), build_token=200508
        '1.05.00'              -> version_tuple=(1, 5, 0), build_token=None
        '3.0.0.4.386.41700'    -> version_tuple=(3, 0, 0, 4, 386, 41700), build_token=None
        '2018-04-27'           -> version_tuple=None, build_token=20180427, is_date_only=True
        'CUSTOM-BETA-REV-???'  -> is_unparseable=True
    """
    if not firmware_str or not isinstance(firmware_str, str):
        return VersionInfo(
            raw=str(firmware_str), version_tuple=None, build_token=None, is_unparseable=True
        )

    raw = firmware_str.strip()

    # 1. Look for date-dash format e.g. 2018-04-27
    date_dash = DATE_DASH_REGEX.search(raw)
    build_token = None
    if date_dash:
        y, m, d = date_dash.groups()
        build_token = int(f"{y}{m}{d}")

    # 2. Look for explicit 'Build XXXXXX' or 6-8 digit tokens if not already found
    if build_token is None:
        build_match = BUILD_TOKEN_REGEX.search(raw)
        if build_match:
            try:
                build_token = int(build_match.group(1))
            except (ValueError, IndexError):
                build_token = None

    # 3. Look for dotted version tuple (e.g. 1.1.2 or 3.0.0.4.386)
    dotted_match = DOTTED_VERSION_REGEX.search(raw)
    version_tuple = None
    if dotted_match:
        try:
            parts = [int(p) for p in dotted_match.group(1).split(".")]
            version_tuple = tuple(parts)
        except ValueError:
            version_tuple = None

    # Determine if purely date-based
    is_date_only = version_tuple is None and build_token is not None

    # Determine unparseable
    is_unparseable = version_tuple is None and build_token is None

    return VersionInfo(
        raw=raw,
        version_tuple=version_tuple,
        build_token=build_token,
        is_date_only=is_date_only,
        is_unparseable=is_unparseable,
    )


def parse_bound_token(
    bound_str: str,
) -> tuple[Literal["date", "tuple", "unknown"], int | tuple[int, ...] | None]:
    """Parse a range boundary string from NVD configurations.

    Can be:
      - 6-8 digit single date token: e.g. '200731', '20230219', '2018-04-27'
      - Dotted semver tuple: e.g. '1.1.4', '1.05.05', '3.0.0.4.386.42643'
    """
    if not bound_str or not isinstance(bound_str, str):
        return ("unknown", None)

    s = bound_str.strip()

    # Check for date-dash format
    date_dash = DATE_DASH_REGEX.match(s)
    if date_dash:
        y, m, d = date_dash.groups()
        return ("date", int(f"{y}{m}{d}"))

    # Check for pure 6-8 digit token (e.g. '200731' or '20230219')
    if re.fullmatch(r"\d{6,8}", s):
        return ("date", int(s))

    # Check for dotted version tuple
    if "." in s and not re.search(r"[^\d.]", s):
        try:
            parts = tuple(int(p) for p in s.split("."))
            return ("tuple", parts)
        except ValueError:
            pass

    # Check for leading numbers e.g. '1.1.4'
    dotted_match = DOTTED_VERSION_REGEX.match(s)
    if dotted_match:
        try:
            parts = tuple(int(p) for p in dotted_match.group(1).split("."))
            return ("tuple", parts)
        except ValueError:
            pass

    return ("unknown", None)


def compare_like_with_like(
    fw_info: VersionInfo,
    bound_str: str,
) -> int | None:
    """Compare firmware version against a boundary string comparing like with like.

    Rules:
      - If range bound is a single 6-8 digit token ('200731'), compare it against
        the build-date token extracted from the firmware string ('Build 200508').
      - If bound is a single date token but firmware has no build token -> return None (unknown).
      - Never compare a multi-part dotted tuple against a single-token bound.
      - If bound is a dotted tuple, compare against fw_info.version_tuple.
      - Returns:
          -1 if firmware < bound
           0 if firmware == bound
           1 if firmware > bound
          None if formats are incompatible or unparseable (evaluates to unknown).
    """
    if fw_info.is_unparseable:
        return None

    bound_kind, bound_val = parse_bound_token(bound_str)
    if bound_kind == "unknown" or bound_val is None:
        return None

    # Case A: Boundary is a single date/build token (e.g. '200731')
    if bound_kind == "date":
        if fw_info.build_token is None:
            # Cannot compare dotted version tuple to a date bound
            return None
        # Compare integer date/build tokens
        b_val = int(bound_val)
        if fw_info.build_token < b_val:
            return -1
        if fw_info.build_token > b_val:
            return 1
        return 0

    # Case B: Boundary is a dotted version tuple (e.g. (1, 1, 4))
    if bound_kind == "tuple":
        if fw_info.version_tuple is None:
            # Cannot compare date-only to a semver tuple
            return None

        # Compare version tuples component by component, padding with 0
        fw_parts = list(fw_info.version_tuple)
        bound_parts = list(bound_val)

        max_len = max(len(fw_parts), len(bound_parts))
        fw_parts.extend([0] * (max_len - len(fw_parts)))
        bound_parts.extend([0] * (max_len - len(bound_parts)))

        for f_comp, b_comp in zip(fw_parts, bound_parts, strict=True):
            if f_comp < b_comp:
                return -1
            if f_comp > b_comp:
                return 1
        return 0

    return None


def match_firmware_range(
    firmware_str: str,
    version_start_including: str | None = None,
    version_start_excluding: str | None = None,
    version_end_including: str | None = None,
    version_end_excluding: str | None = None,
) -> MatchState:
    """Evaluate whether firmware falls within NVD version boundary ranges.

    Defensive Three-State Logic:
      - 'affected'
      - 'not_affected'
      - 'unknown'

    Boundary Rules:
      - versionEndExcluding: A version equal to versionEndExcluding is NOT affected.
        (In accordance with NVD's range data, versionEndExcluding marks the first fixed release).
      - Incompatible or unparseable formats return 'unknown', never 'not_affected'.
    """
    fw_info = extract_version_info(firmware_str)
    if fw_info.is_unparseable:
        return "unknown"

    # Must have at least one boundary to match a range
    has_any_bound = any(
        b is not None
        for b in [
            version_start_including,
            version_start_excluding,
            version_end_including,
            version_end_excluding,
        ]
    )
    if not has_any_bound:
        return "unknown"

    # 1. Check versionStartIncluding
    if version_start_including:
        cmp_start = compare_like_with_like(fw_info, version_start_including)
        if cmp_start is None:
            return "unknown"
        if cmp_start < 0:
            return "not_affected"

    # 2. Check versionStartExcluding
    if version_start_excluding:
        cmp_start = compare_like_with_like(fw_info, version_start_excluding)
        if cmp_start is None:
            return "unknown"
        if cmp_start <= 0:
            return "not_affected"

    # 3. Check versionEndIncluding
    if version_end_including:
        cmp_end = compare_like_with_like(fw_info, version_end_including)
        if cmp_end is None:
            return "unknown"
        if cmp_end > 0:
            return "not_affected"

    # 4. Check versionEndExcluding
    if version_end_excluding:
        cmp_end = compare_like_with_like(fw_info, version_end_excluding)
        if cmp_end is None:
            return "unknown"
        # Boundary rule: Equal to versionEndExcluding is NOT affected
        # We strictly follow NVD's range data where versionEndExcluding is the patched release.
        if cmp_end >= 0:
            return "not_affected"

    return "affected"
