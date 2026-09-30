"""
MCP Resources registration. 

Defines static resources that the LLM can query.
"""

from __future__ import annotations
import json
from mcp.server.fastmcp import FastMCP

from ...infrastructure.catalog.devices import ALL_MODELS
from ...infrastructure.catalog.cables import CABLE_TYPES
from ...infrastructure.catalog.aliases import MODEL_ALIASES
from ...infrastructure.catalog.templates import list_templates
from ...shared.constants import CAPABILITIES


def register_resources(mcp: FastMCP) -> None:
    """Registers all resources on the MCP server."""

    @mcp.resource("pt://catalog/devices")
    def resource_device_catalog() -> str:
        """Complete catalog of devices available on Packet Tracer."""
        catalog = {}
        for name, model in ALL_MODELS.items():
            catalog[name] = {
                "display_name": model.display_name,
                "category": model.category,
                "ports": [p.full_name for p in model.ports],
            }
        return json.dumps(catalog, indent=2, ensure_ascii=False)

    @mcp.resource("pt://catalog/cables")
    def resource_cable_catalog() -> str:
        """Cable types available at Packet Tracer."""
        return json.dumps(CABLE_TYPES, indent=2, ensure_ascii=False)

    @mcp.resource("pt://catalog/aliases")
    def resource_aliases() -> str:
        """Common aliases for device models."""
        return json.dumps(MODEL_ALIASES, indent=2, ensure_ascii=False)

    @mcp.resource("pt://catalog/templates")
    def resource_templates() -> str:
        """Topology templates available with description."""
        templates = list_templates()
        data = []
        for t in templates:
            data.append({
                "name": t.name,
                "key": t.key.value,
                "description": t.description,
                "routers": f"{t.min_routers}-{t.max_routers}",
                "default_routing": t.default_routing.value,
                "tags": list(t.tags),
            })
        return json.dumps(data, indent=2, ensure_ascii=False)

    @mcp.resource("pt://capabilities")
    async def resource_capabilities() -> str:
        """MCP server capabilities and version. 
        
        It DERIVES from the live tools log: instead of keeping a list at hand that 
        can be out of phase (it used to say nat="unsupported" while pt_apply_nat existed), 
        introspects the tools actually registered and reports the support of each 
        feature depending on whether your tool exists. If introspection fails for 
        for any reason, it falls to the static values of CAPABILITIES.
        """
        caps = dict(CAPABILITIES)
        try:
            tools = await mcp.list_tools()
            names = sorted(t.name for t in tools)
            caps["tools_count"] = len(names)
            caps["tools"] = names
            # Feature → support derived from the actual presence of the tool (no drift possible)
            caps["supported_live"] = {
                "nat": any(n.startswith("pt_apply_nat") for n in names),
                "acl": any(n.startswith("pt_apply_acl") for n in names),
                "modules": any("module" in n for n in names),
                "live_deploy": "pt_live_deploy" in names,
                "raw_js": "pt_send_raw" in names,
            }
        except Exception:
            pass
        return json.dumps(caps, indent=2, ensure_ascii=False)
