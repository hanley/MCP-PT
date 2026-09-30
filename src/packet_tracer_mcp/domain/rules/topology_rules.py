"""Rules on the SHAPE of the graph and the coherence of routing. 

The other rules look at devices, ports, and IPs one at a time. These two look at the 
entire plan, which is where the worst silent failure of the pipeline was hidden: 

'hub_spoke' asks for the hub to link to each spoke, but a 2911 has three 
Gigabit ports. With six routers, the hub runs out of ports in the room and 
'_link_routers' just wouldn't create the link — without warning. The result was a 
plan with two single routers, no interfaces, no links, and an OSPF of 
'router-id 0.0.0.0' and zero networks... which the validator approved with 'valid=true'. 

An island-split topology looks identical to a healthy one in all checks 
per-device: every device exists, every port is valid, no IP it clashes. 
The only thing that gives it away is going through the graph. 
"""

from __future__ import annotations

from ..models.plans import TopologyPlan
from ..models.errors import PlanError, ErrorCode


def validate_connectivity(plan: TopologyPlan) -> list[PlanError]:
    """Verify that all wired devices form ONE component. 
    
    WiFi laptops are left out of the graph on purpose: they don't have a cable 
    because they don't have a cable because they don't have a cable they are 
    associated by RF, so counting them as islands would mark each topology wireless 
    as broken. 
    """
    wired = [d for d in plan.devices if not d.wireless]
    if len(wired) <= 1:
        # Zero or a device is, trivially, a single component.
        return []

    names = {d.name for d in wired}
    adjacency: dict[str, set[str]] = {name: set() for name in names}
    for link in plan.links:
        if link.device_a in names and link.device_b in names:
            adjacency[link.device_a].add(link.device_b)
            adjacency[link.device_b].add(link.device_a)

    # BFS from the first device: what is not reached is another island.
    start = wired[0].name
    seen = {start}
    queue = [start]
    while queue:
        current = queue.pop()
        for neighbour in adjacency[current]:
            if neighbour not in seen:
                seen.add(neighbour)
                queue.append(neighbour)

    unreachable = [d for d in wired if d.name not in seen]
    if not unreachable:
        return []

    orphan_names = ", ".join(d.name for d in unreachable)

    # A router with NO interface assigned is the signature of the hub that was left 
    # no ports: The IP planner only addresses what is bound.
    starved = [d for d in unreachable if d.category == "router" and not d.interfaces]
    if starved:
        suggestion = (
            "The router that acts as a hub ran out of free ports for so many" 
            "links. Use a model with more ports, add a "
            "Expand, or reduce the number of routers."
        )
    else:
        suggestion = (
            f"Add a link that connects {unreachable.name} to the rest "
            "of topology."
        )

    return [PlanError(
        code=ErrorCode.TOPOLOGY_DISCONNECTED,
        device=unreachable[0].name,
        message=(
            f"Topology is broken: {orphan_names} has no path to "
            f"{start}. Isolated devices cannot route or receive traffic."
        ),
        suggestion=suggestion,
    )]


def validate_routing(plan: TopologyPlan) -> list[PlanError]:
    """Basic coherence of the declared OSPF processes. 
    
    A router that the planner couldn't assign interfaces to ends up with a 
    'OSPF router' without networks and with 'router-id 0.0.0.0'. The two things are 
    config invalid on IOS and both left the pipeline without a single complaint. 
    """
    errors: list[PlanError] = []

    for cfg in plan.ospf_configs:
        if not cfg.networks:
            errors.append(PlanError(
                code=ErrorCode.OSPF_NO_NETWORKS,
                device=cfg.router,
                message=(
                    f"OSPF process {cfg.process_id} on {cfg.router} does not advertise "
                    "No network."
                ),
                suggestion=(
                    "An OSPF process without 'network' sentences does not form" 
                    "Adjacencies. Check that the router has interfaces "
                    "directed and linked."
                ),
            ))

        # 'router_id' empty is legit: IOS chooses the highest IP. The one that doesn't 
        # is 0.0.0.0, which is what's left when there's no interface.
        if cfg.router_id.strip() == "0.0.0.0":
            errors.append(PlanError(
                code=ErrorCode.OSPF_INVALID_ROUTER_ID,
                device=cfg.router,
                message=(
                    f"OSPF in {cfg.router} has router-id 0.0.0.0, which IOS "
                    "reject."
                ),
                suggestion=(
                    "The router-id is derived from the router's interfaces; "
                    "0.0.0.0 means it doesn't have any addressing."
                ),
            ))

    return errors


def validate_wireless(plan: TopologyPlan) -> list[PlanError]:
    """Warns when WiFi association cannot be predicted. Returns WARNINGS. 
    
    An AP over LAN makes it POSSIBLE for each laptop to take direction of its own 
    subnet, but does not guarantee it. Measured against PT 9.0.1 over 6 LANs: with AP 
    LAN 1 on, a laptop that had SU LAN AP next to it followed with 192.168.0.5 — from 
    LAN pool 1. By shutting down the other AP and rebooting it, Volume 192.168.4.25, 
    which corresponded to him. 
    
    In other words, PT does not choose the nearest PA: the association is sticky and, 
    between APs that share the SSID by default, arbitrary. And there's no way to 
    disambiguate it, because PT does not expose SSID API (verified: neither the AP 
    nor its port have setSsid). The only honest thing is that the plan says so instead 
    of Promising an address that it does not control. 
    """
    aps = plan.devices_by_category("accesspoint")
    wireless_hosts = [d for d in plan.devices if d.wireless]
    if len(aps) < 2 or not wireless_hosts:
        return []

    return [PlanError(
        code=ErrorCode.WIRELESS_AMBIGUOUS_ASSOCIATION,
        device=wireless_hosts[0].name,
        message=(
            f"There are {len(aps)} access points sharing the SSID by default and "
            f"{len(wireless_hosts)} wireless host(s). In the logical view of "
            "PT RF reach is global, so each host can be associated with "
            "ANY of them and receive address from another LAN's DHCP pool."
        ),
        suggestion=(
            "PT doesn't expose SSID APIs, so this can't be fixed from the "
            "plan. Check with pt_inspect_ports which subnet each host was left in "
            "wireless; if you need deterministic addressing, use "
            "wireless_laptops=False and wires the laptops to your switch."
        ),
    )]
