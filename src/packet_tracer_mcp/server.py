"""
MCP server for Packet Tracer. 

Entry point: creates the server, registers tools/resources, 

and boots in streamable-http (:39000) or stdio depending on the --stdio flag.
"""

from __future__ import annotations

import sys

from mcp.server.fastmcp import FastMCP

from . import __version__
from .adapters.mcp.resource_registry import register_resources
from .adapters.mcp.tool_registry import register_tools
from .settings import SERVER_NAME, SERVER_INSTRUCTIONS

TRANSPORT_PORT = 39000

mcp = FastMCP(
    SERVER_NAME,
    instructions=SERVER_INSTRUCTIONS,
    host="127.0.0.1",
    port=TRANSPORT_PORT,
    stateless_http=True,
)

# Say OUR version in the handshake, not the SDK. 
# 
# 'create_initialization_options()' resolves the number with 
# 'self.version if self.version else pkg_version("mcp")', and FastMCP does not expose 
# 'version' in your '__init__' or a property for the lowlevel server, so 
# the fallback always won: the server presented itself as "1.28.1" —the 
# bookstore—instead of "0.8.0". That number is the one shown by Claude Desktop, 
# Cursor and PacketSmith in your server panel, and on top of that it changed only to the 
# Update the dependency.
#
# '_mcp_server' is private and there is no public alternative; it goes with a guard to 
# that a future version of the SDK that renames it demotes it to what it was before instead 
# to break the start, which is the only thing that cannot be allowed here.
_lowlevel = getattr(mcp, "_mcp_server", None)
if _lowlevel is not None:
    _lowlevel.version = __version__

register_tools(mcp)
register_resources(mcp)


def main():
    """Boot the MCP server. 
    
    By default it uses streamable-http in :39000. 
    With --stdio uses stdio transport (for debug or legacy clients). 
    """
    if "--stdio" in sys.argv:
        mcp.run(transport="stdio")
    else:
        mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
