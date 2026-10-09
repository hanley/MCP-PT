""" CLI Configuration Generator (IOS) for Packet Tracer devices. 

Starting with the TopologyPlan, generate ready-to-use command blocks 
Paste into the terminal of each router/switch. 
"""

from __future__ import annotations
from ...domain.models.plans import TopologyPlan, DevicePlan
from ...shared.utils import prefix_to_mask
from .vlan_cli_generator import (
    generate_switch_vlan_cli, generate_router_subinterface_cli, switch_supports_encap,
)

def generate_all_configs(plan: TopologyPlan) -> dict[str, str]:
    """ Generate CLI configs for all devices that need them. 
    Return {Device_name: block_cli}. 
    """

    configs: dict[str, str] = {}

    for dev in plan.devices:
        if dev.category == "router":
            configs[dev.name] = _router_config(dev, plan)
        elif dev.category == "switch":
            cfg = _switch_config(dev, plan)
            if cfg.strip():
                configs[dev.name] = cfg

    return configs


def _router_config(router: DevicePlan, plan: TopologyPlan) -> str:
    """Generates the complete config of a router."""
    lines: list[str] = []

    lines.append("enable")
    lines.append("configure terminal")
    lines.append(f"hostname {router.name}")
    lines.append("no ip domain-lookup")
    if router.interfaces_v6:
        lines.append("ipv6 unicast-routing")
    lines.append("")

    # --- Physical interfaces (the "Gig0/0.10" subinterfaces are emitted separately with 
    # its 'dot1Q encapsulation', so we skip them here) ---
    for iface, ip_cidr in router.interfaces.items():
        if "." in iface:
            continue
        ip, prefix = ip_cidr.split("/")
        mask = prefix_to_mask(int(prefix))
        lines.append(f"interface {iface}")
        lines.append(f" ip address {ip} {mask}")
        # IPv6 on the same physical interface (dual-stack), if applicable
        v6 = router.interfaces_v6.get(iface)
        if v6:
            lines.append(f" ipv6 address {v6}")
            lines.append(" ipv6 enable")
        lines.append(" no shutdown")
        lines.append(" exit")
        lines.append("")

    # --- Subinterfaces .1q (inter-VLAN routing / router-on-a-stick) ---
    subifs = [s for s in plan.subinterfaces if s.router == router.name]
    if subifs:
        lines.extend(generate_router_subinterface_cli(subifs))
        lines.append("")

    # --- DHCP ---
    pools = [p for p in plan.dhcp_pools if p.router == router.name]
    for pool in pools:
        lines.append(f"ip dhcp excluded-address {pool.excluded_start} {pool.excluded_end}")
    for pool in pools:
        lines.append(f"ip dhcp pool {pool.pool_name}")
        lines.append(f" network {pool.network} {pool.mask}")
        lines.append(f" default-router {pool.gateway}")
        lines.append(f" dns-server {pool.dns}")
        lines.append(" exit")
        lines.append("")

    # --- Static Routes ---
    static_routes = [r for r in plan.static_routes if r.router == router.name]
    for route in static_routes:
        line = f"ip route {route.destination} {route.mask} {route.next_hop}"
        if route.admin_distance != 1:
            line += f" {route.admin_distance}"
        lines.append(line)
    if static_routes:
        lines.append("")

    # --- OSPF ---
    ospf_cfgs = [o for o in plan.ospf_configs if o.router == router.name]
    for ospf in ospf_cfgs:
        lines.append(f"router ospf {ospf.process_id}")
        if ospf.router_id:
            lines.append(f" router-id {ospf.router_id}")
        for net in ospf.networks:
            lines.append(
                f" network {net['network']} {net['wildcard']} area {net['area']}"
            )
        lines.append(" exit")
        lines.append("")

    # --- RIP ---
    rip_cfgs = [r for r in plan.rip_configs if r.router == router.name]
    for rip in rip_cfgs:
        lines.append(f"router rip")
        lines.append(f" version {rip.version}")
        for net in rip.networks:
            lines.append(f" network {net}")
        if rip.no_auto_summary:
            lines.append(" no auto-summary")
        lines.append(" exit")
        lines.append("")

    # --- EIGRP ---
    eigrp_cfgs = [e for e in plan.eigrp_configs if e.router == router.name]
    for eigrp in eigrp_cfgs:
        lines.append(f"router eigrp {eigrp.as_number}")
        for net in eigrp.networks:
            lines.append(f" network {net['network']} {net['wildcard']}")
        if eigrp.no_auto_summary:
            lines.append(" no auto-summary")
        lines.append(" exit")
        lines.append("")

    lines.append("end")
    lines.append("write memory")

    return "\n".join(lines)

def _switch_config(switch: DevicePlan, plan: TopologyPlan) -> str:
    """
    Generates switch configuration:

    - hostname
    - VLANs
    - access ports
    - trunk ports
    - management SVI IP address
    """

    lines: list[str] = []

    lines.append("enable")
    lines.append("configure terminal")
    lines.append(f"hostname {switch.name}")
    lines.append("")

    # ---------------------------------------------------------
    # VLAN / access / trunk
    # ---------------------------------------------------------
    access = [
        a for a in plan.access_ports
        if a.switch == switch.name
    ]

    trunks = [
        t for t in plan.trunks
        if t.switch == switch.name
    ]

    if access or trunks or plan.vlans:
        vlan_lines = generate_switch_vlan_cli(
            plan.vlans,
            access,
            trunks,
            supports_encap=switch_supports_encap(switch.model),
        )

        lines.extend(vlan_lines)
        lines.append("")

    # ---------------------------------------------------------
    # Switch management SVI
    # ---------------------------------------------------------
    for iface, ip_cidr in switch.interfaces.items():

        # Only process SVI interfaces here
        if not iface.lower().startswith("vlan"):
            continue

        ip, prefix = ip_cidr.split("/")
        mask = prefix_to_mask(int(prefix))

        lines.append(f"interface {iface}")
        lines.append(f" ip address {ip} {mask}")
        lines.append(" no shutdown")
        lines.append(" exit")
        lines.append("")

    # ---------------------------------------------------------
    # Optional management default gateway
    # ---------------------------------------------------------
    if switch.gateway:
        lines.append(
            f"ip default-gateway {switch.gateway}"
        )
        lines.append("")

    lines.append("end")
    lines.append("write memory")

    return "\n".join(lines)

def generate_pc_config(device: DevicePlan, use_dhcp: bool | None = None) -> str:
    """Generates setup instructions for a PC."""
    lines: list[str] = []
    lines.append(f"--- {device.name} ---")

    if device.interfaces:
        for iface, ip_cidr in device.interfaces.items():
            ip, prefix = ip_cidr.split("/")
            mask = prefix_to_mask(int(prefix))
            lines.append(f"IP Address: {ip}")
            lines.append(f"Subnet Mask: {mask}")
    if device.gateway:
        lines.append(f"Default Gateway: {device.gateway}")
    lines.append("DNS Server: 8.8.8.8")
    if use_dhcp:
        lines.append("Configure as DHCP to get IPs automatically.")
    else:
        lines.append("Configure static IP with the above values.")
    return "\n".join(lines)
