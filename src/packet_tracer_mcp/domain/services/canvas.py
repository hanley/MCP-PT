"""
Annotations and capture of the Packet Tracer logical canvas. 

Pure logic, without bridge — testable with synthetic data, just like topology_diff. 

The bulk of this module exists because of how PT returns an image: it doesn't send 
binary nor base64, but the bytes in decimal separated by comma and **with sign** (the 'byte' 
of Qt ranges from -128 to 127). To reconstruct the file is to translate each negative into 
its unsigned value. Verified against PT 9.0.0.0810: The first eight values of a 
PNG come back as '-119,80,78,71,13,10,26,10', which is exactly the signature 
'89 50 4E 47 0D 0A 1A 0A'.
"""

from __future__ import annotations

# Formats that getWorkspaceImage accepts. Measured: PNG ~33 KB and JPG ~105 KB for the 
# # same canvas — PNG compresses a flat line diagram much better.
IMAGE_FORMATS = ("PNG", "JPG", "JPEG", "BMP")

# Signatures to verify that what was decoded is really what was requested, instead of 
# of writing a corrupt file to disk and only notifying when someone opens it.
_MAGIC = {
    "PNG": bytes([0x89, 0x50, 0x4E, 0x47]),
    "JPG": bytes([0xFF, 0xD8, 0xFF]),
    "JPEG": bytes([0xFF, 0xD8, 0xFF]),
    "BMP": b"BM",
}


class CanvasImageError(ValueError):
    """PT's response could not be converted into an image."""

def normalize_format(fmt: str) -> str:
    upper = (fmt or "PNG").strip().upper()
    if upper not in IMAGE_FORMATS:
        raise CanvasImageError(
            f"Format '{fmt}' not supported. Valid: {', '.join(IMAGE_FORMATS)}."
        )
    return upper


def decode_pt_image(raw: str, fmt: str = "PNG") -> bytes:
    """Converts the list of PT-signed bytes to the image binary."""
    if not raw or not raw.strip():
        raise CanvasImageError("PT returned an empty image.")

    out = bytearray()
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            value = int(chunk)
        except ValueError as exc:
            raise CanvasImageError(
                f"Nonnumeric value in the bytes of the image: '{chunk[:20]}'."
            ) from exc
        if not -128 <= value <= 255:
            raise CanvasImageError(f"Byte out of range: {value}.")
        # A 'byte' of Qt is signed; -119 and 137 are the same octet (0x89).
        out.append(value + 256 if value < 0 else value)

    if not out:
        raise CanvasImageError("PT returned an image with no bytes.")

    magic = _MAGIC.get(normalize_format(fmt))
    if magic and not bytes(out).startswith(magic):
        raise CanvasImageError(
            f"Bytes do not correspond to a {fmt}: starts with "
            f"{list(out[:4])} and {list(magic)} was expected."
        )
    return bytes(out)


def validate_color(r: int, g: int, b: int, a: int) -> None:
    """The four channels range from 0 to 255; PT does not warn if it misses something else."""
    for name, value in (("r", r), ("g", g), ("b", b), ("a", a)):
        if not 0 <= value <= 255:
            raise ValueError(f"The channel {name}={value} is out of range (0-255).")

def parse_uuid_list(raw) -> list[str]:
    """Normalizes to list the canvas ids returned by PT. 
    
    Depending on the case, they arrive as a list already parsed by JSON or as a single chain 
    with the UUIDs in curly brackets separated by commas. 
    """
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    return [part.strip() for part in str(raw).split(",") if part.strip()]
