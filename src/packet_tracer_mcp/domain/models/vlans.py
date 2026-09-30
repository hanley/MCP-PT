"""VLAN/trunk/inter-VLAN routing (router-on-a-stick) models."""

from __future__ import annotations
from pydantic import BaseModel, Field


class VLANConfig(BaseModel):
    """A VLAN. 'subnet' is populated by the IP planner (e.g. "192.168.10.0/24")."""
    vlan_id: int
    name: str = ""
    subnet: str = ""


class AccessPortConfig(BaseModel):
    """An access mode switch port assigned to a VLAN."""
    switch: str
    port: str
    vlan_id: int


class TrunkConfig(BaseModel):
    """A switch port in trunk mode. 
    
    'allowed_vlans' empty = all. 'encapsulation' is only emitted on switches 
    multi-encap (3560); the 2960 is dot1q-only and rejects the command.
    """
    switch: str
    port: str
    allowed_vlans: list[int] = Field(default_factory=list)
    native_vlan: int = 1
    encapsulation: str = "dot1q"


class SubinterfaceConfig(BaseModel):
    """A.1q subinterface on a router (inter-VLAN routing)."""
    router: str
    parent_port: str
    vlan_id: int
    ip_cidr: str = ""  # "192.168.10.1/24"
    encapsulation: str = "dot1Q"


class VLANPlan(BaseModel):
    """Added for the 'pt_apply_vlan' post-deploy tool."""
    router: str = ""
    switch: str = ""
    vlans: list[VLANConfig] = Field(default_factory=list)
    access_ports: list[AccessPortConfig] = Field(default_factory=list)
    trunks: list[TrunkConfig] = Field(default_factory=list)
    subinterfaces: list[SubinterfaceConfig] = Field(default_factory=list)
