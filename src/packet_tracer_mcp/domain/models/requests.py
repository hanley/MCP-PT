"""Request models — what comes in from the LLM."""

from __future__ import annotations
import ipaddress
from pydantic import BaseModel, Field, ValidationInfo, field_validator

from ...shared.enums import RoutingProtocol, TopologyTemplate
from ...shared.constants import (
    DEFAULT_ROUTER, DEFAULT_SWITCH,
    DEFAULT_LAN_BASE, DEFAULT_LINK_BASE,
)

# How big the IPPlanner subnets get from each pool. A base with a prefix 
# Longer than this cannot give a single subnet.
_REQUIRED_PREFIX = {
    "base_network": 24,          # one /24 per LAN
    "inter_router_network": 30,  # One /30 per router link↔
}


class TopologyRequest(BaseModel):
    """High-level request — what the LLM generates from the user."""
    template: TopologyTemplate = TopologyTemplate.MULTI_LAN
    routers: int = Field(ge=1, le=20, default=2)
    switches_per_router: int = Field(ge=0, le=4, default=1)
    pcs_per_lan: list[int] | int = Field(default=3)
    laptops_per_lan: list[int] | int = Field(default=0)
    servers: int = Field(ge=0, le=10, default=0)
    access_points: int = Field(ge=0, le=20, default=0)
    has_wan: bool = False
    dhcp: bool = True
    routing: RoutingProtocol = RoutingProtocol.STATIC
    router_model: str = DEFAULT_ROUTER
    switch_model: str = DEFAULT_SWITCH
    base_network: str = DEFAULT_LAN_BASE
    inter_router_network: str = DEFAULT_LINK_BASE
    # Advanced routing options
    floating_routes: bool = False          # Generates static backup paths (AD=254)
    ospf_process_id: int = Field(ge=1, le=65535, default=1)
    eigrp_as: int = Field(ge=1, le=65535, default=100)
    # VLAN (router-on-a-stick): number of VLANs to be distributed among PCs (0 = default 2)
    vlans: int = Field(ge=0, le=64, default=0)
    # IPv6 dual-stack
    dual_stack: bool = False
    ipv6_base: str = "2001:db8::/32"
    # WiFi-connected laptops (wireless NIC + auto-associated AP over LAN)
    wireless_laptops: bool = False

    @field_validator("base_network", "inter_router_network")
    @classmethod
    def _pool_can_yield_subnets(cls, v: str, info: ValidationInfo) -> str:
        """The base has to be a valid network and give at least one subnet. 
        
        Without this the value would come raw to 'IPPlanner', where a '/25' would 
        die with 'new prefix must be longer', a '/24' with a bare 'StopIteration' when 
        requesting the second LAN, and any text with 'AddressValueError'. 
        All three came out as stacktrace rather than something the LLM could correct. 
        """
        needed = _REQUIRED_PREFIX[info.field_name]
        # strict=True same as 'IPPlanner': if host bits were accepted here, 
        # The validation would pass and the planner would burst later.
        try:
            net = ipaddress.IPv4Network(v)
        except ValueError as exc:
            raise ValueError(
                f"'{v}' is not a valid IPv4 network ({exc}). Example: 192.168.0.0/16"
            ) from None
        if net.prefixlen > needed:
            raise ValueError(
                f"'{v}' is a /{net.prefixlen} and from here come subnets /{needed}, "
                f"So none fits. Use /{needed} or shorter "
                f"(192.168.0.0/16 from 256 nets /24; 10.0.0.0/16 from 16384 /30)."
            )
        return v

    @field_validator("ipv6_base")
    @classmethod
    def _ipv6_pool_can_yield_subnets(cls, v: str) -> str:
        """Same deal for IPv6, where the planner gets /64."""
        try:
            net = ipaddress.IPv6Network(v)
        except ValueError as exc:
            raise ValueError(
                f"'{v}' is not a valid IPv6 network ({exc}). Example: 2001:db8::/32"
            ) from None
        if net.prefixlen > 64:
            raise ValueError(
                f"'{v}' is a /{net.prefixlen} and from here come /64 subnets, "
                f"So none fits. Use /64 or shorter (e.g. 2001:db8::/32)."
            )
        return v
