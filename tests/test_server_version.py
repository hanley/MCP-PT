"""The handshake has to announce the server version, not the SDK version. 

'Server.create_initialization_options()' resolves the number like this: 

    server_version=self.version if self.version else pkg_version("mcp") 

FastMCP never passes 'version' to the lowlevel server -- there is no parameter 
in Your '__init__' --, so without the fix the fallback wins and the server shows 
up With the 'MCP' library version. Measured against PT 9.0.1 with a handshake 
real by stdio, the server answered: 

    {"name": "Packet Tracer MCP", "version": "1.28.1"} 

1.28.1 is the SDK. The server was on 0.8.0. Every MCP client shows that number 
in your panel, and it also moves only when the dependency is updated: A user 
reporting "I'm on 1.28.1" doesn't say anything helpful about what code he's running. 

They do not require Packet Tracer.
"""

import tomllib
from importlib.metadata import version as dist_version
from pathlib import Path

from src.packet_tracer_mcp import __version__
from src.packet_tracer_mcp.server import mcp

RAIZ = Path(__file__).resolve().parents[1]


def _opciones():
    """The same as the server replies to a client in 'initialize'."""
    return mcp._mcp_server.create_initialization_options()


def test_el_handshake_anuncia_nuestra_version():
    assert _opciones().server_version == __version__


def test_el_handshake_no_anuncia_la_version_del_sdk():
    # The regression guard: if someone pulls out the line setting the version, 
    # This number reverts to the 'MCP' packet and the test drops.
    assert _opciones().server_version != dist_version("mcp")


def test_el_nombre_sigue_siendo_el_del_servidor():
    # Fixing the version doesn't have to touch the name, which is what the 
    # user sees in the list of servers of their client.
    assert _opciones().server_name == "Packet Tracer MCP"


def test_la_version_del_paquete_coincide_con_pyproject():
    # A single source of truth: '__version__' comes out of the installed metadata, 
    # which in turn comes out of 'pyproject.toml'. If they come off, the package 
    # installed is old and everything above measures something else.
    declarada = tomllib.loads(
        (RAIZ / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]["version"]
    assert __version__ == declarada
