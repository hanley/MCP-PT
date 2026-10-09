""" Formal topology templates. 

Each template defines defaults and constraints 
that the orchestrator uses to generate plans. 
"""

from __future__ import annotations
from dataclasses import dataclass, field
from ...shared.enums import TopologyTemplate, RoutingProtocol


@dataclass(frozen=True)
class TemplateSpec:
    """Specifying a topology template."""
    name: str
    key: TopologyTemplate
    description: str
    min_routers: int = 1
    max_routers: int = 20
    default_routers: int = 2
    default_pcs_per_lan: int = 3
    default_switches_per_router: int = 1
    requires_wan: bool = False
    default_routing: RoutingProtocol = RoutingProtocol.STATIC
    tags: tuple[str, ...] = ()


TEMPLATES: dict[TopologyTemplate, TemplateSpec] = {
    TopologyTemplate.SINGLE_LAN: TemplateSpec(
        name="Single LAN",
        key=TopologyTemplate.SINGLE_LAN,
        description="1 router + 1 switch + PCs. Red local simple.",
        min_routers=1, max_routers=1, default_routers=1,
        default_pcs_per_lan=5,
        tags=("basic", "lan", "beginner"),
    ),
    TopologyTemplate.MULTI_LAN: TemplateSpec(
        name="Multi LAN",
        key=TopologyTemplate.MULTI_LAN,
        description="N daisy-chain routers, each with its LAN.",
        default_routers=2, default_pcs_per_lan=3,
        tags=("intermediate", "multi-lan", "routing"),
    ),
    TopologyTemplate.MULTI_LAN_WAN: TemplateSpec(
        name="Multi LAN + WAN",
        key=TopologyTemplate.MULTI_LAN_WAN,
        description="N routers with LANs + WAN (Cloud) connection.",
        default_routers=3, default_pcs_per_lan=3,
        requires_wan=True,
        tags=("intermediate", "wan", "cloud"),
    ),
    TopologyTemplate.STAR: TemplateSpec(
        name="Star (Hub & Spoke)",
        key=TopologyTemplate.STAR,
        description="1 central router connected to N switches.",
        min_routers=1, max_routers=1, default_routers=1,
        default_switches_per_router=3, default_pcs_per_lan=4,
        tags=("basic", "star", "centralized"),
    ),
    TopologyTemplate.HUB_SPOKE: TemplateSpec(
        name="Hub and Spoke",
        key=TopologyTemplate.HUB_SPOKE,
        description="1 central hub router + N spoke routers, each with its LAN.",
        default_routers=4, default_pcs_per_lan=2,
        tags=("advanced", "wan", "hub-spoke"),
    ),
    TopologyTemplate.BRANCH_OFFICE: TemplateSpec(
        name="Branch Office",
        key=TopologyTemplate.BRANCH_OFFICE,
        description="Head office + WAN-connected branches.",
        default_routers=3, default_pcs_per_lan=5,
        requires_wan=True,
        tags=("enterprise", "branch", "wan"),
    ),
    TopologyTemplate.THREE_ROUTER_TRIANGLE: TemplateSpec(
        name="Three Router Triangle",
        key=TopologyTemplate.THREE_ROUTER_TRIANGLE,
        description="3 triangle routers with redundancy.",
        min_routers=3, max_routers=3, default_routers=3,
        default_pcs_per_lan=3,
        default_routing=RoutingProtocol.OSPF,
        tags=("advanced", "redundancy", "ospf"),
    ),
    TopologyTemplate.ROUTER_ON_A_STICK: TemplateSpec(
        name="Router on a Stick",
        key=TopologyTemplate.ROUTER_ON_A_STICK,
        description="1 router + 1 switch with inter-VLAN routing (subinterfaces .1q).",
        min_routers=1, max_routers=1, default_routers=1,
        default_switches_per_router=1, default_pcs_per_lan=6,
        tags=("advanced", "vlan", "inter-vlan"),
    ),
    TopologyTemplate.SPINE_LEAF: TemplateSpec(
	name="Spine-Leaf",
	key=TopologyTemplate.SPINE_LEAF,
	description=("2 Cisco 3650-24PS spine switches and "
	"4 Cisco 2960-24TT leaf switches. "
	"Each leaf connects redundantly to both spines "
	"using GigabitEthernet."),
	min_routers=1, max_routers=1, default_routers=1,
	default_pcs_per_lan=0, default_switches_per_router=0,
	requires_wan=False,
	tags=("advanced","redundancy","spine-leaf"),
    ),
    TopologyTemplate.CUSTOM: TemplateSpec(
        name="Custom",
        key=TopologyTemplate.CUSTOM,
        description="Free topology — all manual parameters.",
        tags=("free", "custom"),
    ),
}


def get_template(key: TopologyTemplate) -> TemplateSpec:
    """Gets the spec from a template."""
    return TEMPLATES[key]


def list_templates() -> list[TemplateSpec]:
    """List all templates with their details."""
    return list(TEMPLATES.values())
