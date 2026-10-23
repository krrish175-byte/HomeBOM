"""server.storage - Stateless persistence, atomic device writes, and CPE candidate resolution.

Enforces:
- Seeded devices in server/data/devices.json stay strictly read-only.
- User-added devices persist to server/data/user_devices.json via atomic writes.
- Never invent CPEs: add_device resolves only from server/data/cpe_index.json.
- Returns clarifying questions and closest candidates if no confident match.
"""

import json
import os
import re
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).resolve().parent / "data"
SEEDED_DEVICES_PATH = DATA_DIR / "devices.json"
CPE_INDEX_PATH = DATA_DIR / "cpe_index.json"
METADATA_PATH = DATA_DIR / "metadata.json"


def get_user_devices_path() -> Path:
    """Return path to user_devices.json, configurable via HOMEBOM_USER_DEVICES_PATH."""
    custom = os.environ.get("HOMEBOM_USER_DEVICES_PATH")
    if custom:
        return Path(custom)
    return DATA_DIR / "user_devices.json"


def normalize_token(text: str) -> str:
    """Normalize strings for alphanumeric matching."""
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _strip_notes(device: dict[str, Any]) -> dict[str, Any]:
    """Strip any internal notes from device dictionaries."""
    return {k: v for k, v in device.items() if k != "notes"}


def is_public_demo_mode() -> bool:
    """Return True if HOMEBOM_PUBLIC_DEMO mode is active."""
    return os.environ.get("HOMEBOM_PUBLIC_DEMO", "").strip().lower() in ("1", "true", "yes")


def load_seeded_devices() -> list[dict[str, Any]]:
    """Load seeded devices (strictly read-only)."""
    if not SEEDED_DEVICES_PATH.exists():
        return []
    with open(SEEDED_DEVICES_PATH, "r", encoding="utf-8") as f:
        raw = json.load(f)
        return [_strip_notes(d) for d in raw]


def load_user_devices() -> list[dict[str, Any]]:
    """Load dynamically added user devices. Returns empty list in public demo mode."""
    if is_public_demo_mode():
        return []
    path = get_user_devices_path()
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
            return [_strip_notes(d) for d in raw]
    except (json.JSONDecodeError, OSError):
        return []


def save_user_devices(user_devices: list[dict[str, Any]]) -> None:
    """Persist user devices atomically. Disabled entirely in public demo mode."""
    if is_public_demo_mode():
        raise RuntimeError("User-device writes are disabled in public demo mode.")
    path = get_user_devices_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.parent / f"{path.name}.{os.getpid()}.tmp"
    clean_devices = [_strip_notes(d) for d in user_devices]
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(clean_devices, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)


def get_all_devices() -> list[dict[str, Any]]:
    """Combine read-only seeded devices and user-persisted devices."""
    return load_seeded_devices() + load_user_devices()


def load_cpe_index() -> list[dict[str, Any]]:
    """Load pre-indexed candidate firmware CPEs."""
    if not CPE_INDEX_PATH.exists():
        return []
    with open(CPE_INDEX_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def resolve_candidate_cpe(
    model: str,
    name: str = "",
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """Resolve a device model and name against candidate firmware CPEs.

    Rule 2 & Condition 3: Never invent a CPE.
    Returns:
      (best_candidate, closest_candidates)
      If no confident match is found, best_candidate is None.
    """
    cpe_index = load_cpe_index()
    q = f"{name} {model}".strip().lower()
    q_norm = normalize_token(q)
    model_norm = normalize_token(model)
    q_tokens = set(re.findall(r"[a-z0-9]+", q))

    scored: list[tuple[int, dict[str, Any]]] = []
    for entry in cpe_index:
        score = 0
        p_name = entry.get("product", "").lower()
        v_name = entry.get("vendor", "").lower()
        m_key = entry.get("model_key", "").lower()

        # 1. Exact model or product match (high confidence)
        if model_norm and (
            normalize_token(m_key) == model_norm or normalize_token(p_name) == model_norm
        ):
            score += 15
        elif model_norm and (normalize_token(m_key) in q_norm or normalize_token(p_name) in q_norm):
            score += 8
        elif q_norm and q_norm in normalize_token(p_name):
            score += 6

        # 2. Vendor match
        if v_name and normalize_token(v_name) in q_norm:
            score += 3

        # 3. Token keyword overlaps
        keywords = set(entry.get("keywords", []))
        common = q_tokens.intersection(keywords)
        score += len(common) * 2

        if score > 0:
            scored.append((score, entry))

    scored.sort(key=lambda x: x[0], reverse=True)

    # Confidence threshold: must score at least 6 points to count as a match
    if not scored or scored[0][0] < 6:
        # Return closest potential candidates for clarifying questions
        closest = [s[1] for s in scored[:3]]
        return (None, closest)

    best = scored[0][1]
    top_candidates = [s[1] for s in scored[:3]]
    return (best, top_candidates)


def find_device_by_query(query: str) -> dict[str, Any] | None:
    """Find a device by ID, exact name, substring, or token overlap."""
    devices = get_all_devices()
    q_clean = query.strip().lower()
    if not q_clean:
        return None

    # 1. Exact ID match
    for d in devices:
        if d.get("id", "").lower() == q_clean:
            return d

    # 2. Exact name or model match
    for d in devices:
        if d.get("name", "").lower() == q_clean or d.get("model", "").lower() == q_clean:
            return d

    # 3. Substring match in full text (vendor + name + model)
    for d in devices:
        full = f"{d.get('vendor', '')} {d.get('name', '')} {d.get('model', '')}".lower()
        if q_clean in full:
            return d

    # 4. Token overlap scoring for conversational voice queries (e.g. 'Amazon Echo Dot')
    q_tokens = set(re.findall(r"[a-z0-9]+", q_clean))
    best_match = None
    best_score = 0
    for d in devices:
        full = f"{d.get('vendor', '')} {d.get('name', '')} {d.get('model', '')}".lower()
        dev_tokens = set(re.findall(r"[a-z0-9]+", full))
        overlap = len(q_tokens.intersection(dev_tokens))
        if overlap > best_score:
            best_score = overlap
            best_match = d

    if best_score >= 1:
        return best_match

    return None


def get_epss_metadata() -> dict[str, str]:
    """Retrieve EPSS snapshot date from metadata.json."""
    if METADATA_PATH.exists():
        try:
            with open(METADATA_PATH, "r", encoding="utf-8") as f:
                meta = json.load(f)
                return {
                    "as_of_string": meta.get("as_of_string", "as of 2026-10-21"),
                    "epss_score_date": meta.get("epss_score_date", "2026-10-21"),
                }
        except (json.JSONDecodeError, OSError):
            pass
    return {
        "as_of_string": "as of 2026-10-21",
        "epss_score_date": "2026-10-21",
    }
