"""Utilities shared."""

from __future__ import annotations
import ipaddress
import re
from pathlib import Path
from .constants import PREFIX_TO_MASK

# Characters allowed in a path component. Everything else is replaced with "_", 
# including separators (/\), two unit points (C:), and NUL.
_UNSAFE_PATH_CHARS = re.compile(r"[^A-Za-z0-9._-]")

# Names reserved by Windows: Creating "CON.txt" or "NUL" fails opaquely.
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

_MAX_COMPONENT_LEN = 100


def safe_name_component(name: str, fallback: str = "topology") -> str:
    """Reduces a name to a safe path component (single-level, no leaks). 
    
    Neutralizes separators, "..", drive letters, and reserved Windows names. 
    Spaces are mapped to "_" — historical behavior is preserved so that no 
    Change the names of projects that already exist on disk. 
    """

    cleaned = _UNSAFE_PATH_CHARS.sub("_", (name or "").strip())
    # A component composed only of dots ("." or "..") is an escape, not a name.

    if not cleaned.strip("._-") or set(cleaned) <= {"."}:
        return fallback
    if cleaned.split(".")[0].upper() in _WINDOWS_RESERVED:
        cleaned = f"_{cleaned}"
    return cleaned[:_MAX_COMPONENT_LEN]


def js_escape(s: str) -> str:
    """Escapes a string to insert it into a JS literal. 
    
    A JS literal cannot cross an end of line, and JS treats U+2028/U+2029 as such. 
    Without escaping them, a name with a jump does not "sneak in" as a code: 
    it breaks parsing and the whole command is silently lost inside the catch of the bridge, 
    which is worse than failing loudly. 
    
    To build an entire call I preferred 'json.dumps'; this is for the cases 
    in which it is necessary to interpolate within an already existing literal. 
    """

    return (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("'", "\\'")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def classify_ping(stat_line: str) -> str:
    """Classifies a ping statistic line to "ok" | "partial" | "none". 
    
    `interpret_ping` only says "at least one arrived", so 1 out of 4 packages is 
    reported as OK CONNECTIVITY equal to 4 out of 4 — an agonizing link 
    was identical to a healthy one. Partial loss is different information and 
    it deserves a different verdict. 
    
    It covers the two formats that Packet Tracer produces: 
    - Host (PC/Server): "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)" 
    - IOS (router/switch): "Success rate is 100 percent (4/5)" 
    """

    if not stat_line:
        return "none"

    received = re.search(r"Received\s*=\s*(\d+)", stat_line)
    if received:
        got = int(received.group(1))
        sent_m = re.search(r"Sent\s*=\s*(\d+)", stat_line)
        if sent_m:
            sent = int(sent_m.group(1))
        else:
            lost_m = re.search(r"Lost\s*=\s*(\d+)", stat_line)
            sent = got + (int(lost_m.group(1)) if lost_m else 0)
        if got <= 0:
            return "none"
        return "ok" if got >= sent else "partial"

    rate = re.search(r"Success rate is (\d+) percent", stat_line)
    if rate:
        pct = int(rate.group(1))
        if pct <= 0:
            return "none"
        return "ok" if pct >= 100 else "partial"

    ratio = re.search(r"\((\d+)/(\d+)\)", stat_line)
    if ratio:
        got, sent = int(ratio.group(1)), int(ratio.group(2))
        if got <= 0:
            return "none"
        return "ok" if got >= sent else "partial"

    return "none"


def interpret_ping(stat_line: str) -> bool:
    """True if a ping statistic line indicates at least one packet received. 
    
    It is maintained by compatibility with those who already depended on the Boolean; 
    the Verdict with degrees lives in 'classify_ping'. 
    """

    return classify_ping(stat_line) != "none"


def resolve_within(base: Path, *parts: str) -> Path:
    """Solve 'parts' under 'base' and verify that the result does not escape. 
    
    Sanitizing the name is the first barrier; this post-check resolve() is the one that 
    really decides, because it covers symlinks and any case that sanitation has not foreseen. 
    """

    base_resolved = Path(base).resolve()
    candidate = base_resolved.joinpath(*parts).resolve()
    if candidate != base_resolved and not candidate.is_relative_to(base_resolved):
        raise ValueError(
            f"Path outside the base directory: {candidate} is not inside {base_resolved}"
        )
    return candidate


def prefix_to_mask(prefix: int) -> str:
    """Converts a CIDR prefix to decimal mask."""

    if prefix in PREFIX_TO_MASK:
        return PREFIX_TO_MASK[prefix]
    bits = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return f"{(bits >> 24) & 0xFF}.{(bits >> 16) & 0xFF}.{(bits >> 8) & 0xFF}.{bits & 0xFF}"


def wildcard_mask(network: ipaddress.IPv4Network) -> str:
    """Calculate the wildcard mask of a network."""

    mask_int = int(network.netmask)
    wildcard_int = mask_int ^ 0xFFFFFFFF
    return str(ipaddress.IPv4Address(wildcard_int))


def first_ip(interfaces: dict[str, str]) -> str:
    """Returns the first IP of an interface dict."""    
    
    for ip_cidr in interfaces.values():
        return ip_cidr.split("/")[0]
    return "0.0.0.0"
