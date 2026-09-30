"""Packet Tracer MCP - Servidor MCP para Cisco Packet Tracer."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as _dist_version

# The version is declared ONLY once, in 'pyproject.toml', and read from the 
# metadata of the installed package. Copying it here as literal is the 
# classic release that comes out announcing the previous issue.
try:
    __version__ = _dist_version("packet-tracer-mcp")
except PackageNotFoundError:  # Pragma: No Cover - Just Running Without Installing
    # Executed from the font tree without 'pip install -e.'. Not a 
    # error: the server starts the same, it just doesn't know which version 
    # this. Better an honest marker than a plausible lie.
    __version__ = "0.0.0+source"

__all__ = ["__version__"]
