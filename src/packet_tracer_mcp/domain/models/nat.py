"""NAT/PAT models — configuration and modes. 

NAT is applied post-deploy to an existing router via configureIosDevice 
through bridge, just like ACLs. 

Three modes: 
static — fixed 1:1. Each private IP is mapped to a permanent public IP. 
Use when: An internal server must be reachable from the internet always 
with the same public IP (e.g.: web server, FTP, email).

dynamic — Pool of public IPs assigned on demand. 
The router chooses which Public IP assign to each internal host based on 
availability. 
Use when: You have more public IPs than the overload justifies but less 
than internal hosts; or when public IP tracking matters. 
Rare in today's networks. 

pat — PAT (Port Address Translation) / NAT Overload. 
Many internal hosts share ONE single public IP using port numbers such 
as differentiator. It's what almost all home routers do and business when 
they have a single ISP IP. 
Use when: You have 1 (or few) public IPs and N internal hosts. 

Sub-modes: 
use_interface_overload=True → ip nat inside source list X interface overload 
use_interface_overload=False → ip nat inside source list X pool POOL overload
"""

from __future__ import annotations
from typing import Literal
from pydantic import BaseModel, Field

NATMode = Literal["static", "dynamic", "pat"]


class NATStaticMapping(BaseModel):
    """Inside-local ↔ inside-global pair for static NAT."""
    inside_local: str   # Private IP, e.g.: "192.168.1.10"
    inside_global: str  # Fixed public IP, e.g.: "200.1.1.5"


class NATPool(BaseModel):
    """Public IP pool for dynamic NAT or pooled PAT."""
    name: str = "NAT-POOL"
    start_ip: str         # first IP in the pool, e.g.: "200.1.1.1"
    end_ip: str           # last IP in the pool, e.g.: "200.1.1.10"
    netmask: str          # network mask, e.g.: "255.255.255.0"


class NATConfig(BaseModel):
    """Complete NAT/PAT configuration for a router."""
    router: str
    mode: NATMode

    # Private Network (LAN) Connected Interface 
    inside_interface: str # ex: "GigabitEthernet0/0" 
    # Interface connected to the public network (WAN/Internet) 
    outside_interface: str # ex: "GigabitEthernet0/1" # 

    # --- Static mode --- 
    # List of inside-local ↔ inside-global pairs. 
    # Required when mode="static". 
    static_mappings: list[NATStaticMapping] = Field(default_factory=list)

    # --- Dynamic / pat modes --- 
    # Number or name of ACL that identifies the internal hosts to be translated. 
    acl_number:str="1" 
    # Internal networks in "network wildcard" format, e.g.: "192.168.1.0 0.0.0.255". 
    # They are used to generate the inline access-list. If the ACL already exists in PT 
    # You can leave this list empty and the generator skips the access-list. 
    inside_networks: list[str] = Field(default_factory=list) 

    # Public IP pool. Required for dynamic; optional on PAT when 
    # use_interface_overload=True. 
    pool: NATPool | None = None 

    # PAT only: if True generates "ip nat inside source list X interface overload" 
    # instead of using a pool. Typical when the ISP assigns a single IP to the WAN interface. 
    use_interface_overload: bool = False