"""Arrangement of the devices in the logical canvas. 

Regressions observed deploying 6 routers x 4 PCs against PT 9.0.1: 

- PC1 came out at x=-60, i.e. OUTSIDE the canvas on the left. 
- Neighboring LAN clusters were stepped on (PC4 at x=180 and PC5 at x=190) 
because the cluster width (n_pcs * 80) exceeded the spacing between LANs (250). 
- Servers were placed on the far right but are wired to the PRIMER switch, 
drawing diagonals that crossed the entire diagram.
"""

import pytest

from src.packet_tracer_mcp.domain.models.requests import TopologyRequest
from src.packet_tracer_mcp.domain.services.orchestrator import plan_from_request
from src.packet_tracer_mcp.shared.constants import LAYOUT_PC_X_SPACING


def _big_plan(**kw):
    params = dict(routers=6, pcs_per_lan=4, laptops_per_lan=2,
                  servers=3, has_wan=True)
    params.update(kw)
    plan, _ = plan_from_request(TopologyRequest(**params))
    return plan


class TestNoOffCanvasDevices:
    def test_no_negative_coordinates(self):
        plan = _big_plan()
        off = [(d.name, d.x, d.y) for d in plan.devices if d.x < 0 or d.y < 0]
        assert not off, f"Off-Canvas Devices: {off}"

    def test_no_negative_coordinates_with_crowded_lans(self):
        plan = _big_plan(routers=2, pcs_per_lan=8, laptops_per_lan=6)
        off = [(d.name, d.x, d.y) for d in plan.devices if d.x < 0 or d.y < 0]
        assert not off, f"Off-Canvas Devices: {off}"


class TestNoOverlap:
    def test_no_two_devices_share_a_position(self):
        plan = _big_plan()
        seen: dict[tuple[int, int], str] = {}
        clashes = []
        for d in plan.devices:
            key = (d.x, d.y)
            if key in seen:
                clashes.append((seen[key], d.name, key))
            seen[key] = d.name
        assert not clashes, f"Overlapping devices: {clashes}"

    def test_neighbouring_lan_clusters_keep_a_full_slot_of_air(self):
        """Between the last PC on one LAN and the first PC on the next, 
        you have to Fit at least one host space. 
        
        "They are not interspersed" is not enough: with the old spacing they 
        were at 10 px, which on ~40 px icons is indistinguishable from being stacked.
        """
        plan = _big_plan(routers=4, pcs_per_lan=4, laptops_per_lan=0, servers=0)
        pcs = [d for d in plan.devices if d.category == "pc"]
        # 4 PCs per LAN, in order of creation
        lans = [pcs[i * 4:(i + 1) * 4] for i in range(4)]
        for i in range(len(lans) - 1):
            rightmost = max(d.x for d in lans[i])
            leftmost = min(d.x for d in lans[i + 1])
            gap = leftmost - rightmost
            assert gap >= LAYOUT_PC_X_SPACING, (
                f"LAN{i + 1} ends in x={rightmost} and LAN{i + 2} starts in "
                f"x={leftmost}: only {gap} px separation"
            )


class TestServersNearTheirSwitch:
    def test_servers_sit_close_to_the_switch_they_cable_to(self):
        plan = _big_plan()
        servers = [d for d in plan.devices if d.category == "server"]
        switches = [d for d in plan.devices if d.category == "switch"]
        assert servers and switches

        # They are wired to the first switch: they should be on their column, not on the other 
        # Tip of the diagram.
        sw0 = switches[0]
        far = [(s.name, s.x, sw0.x) for s in servers
               if abs(s.x - sw0.x) > 300]
        assert not far, f"servers far from {sw0.name}: {far}"

    def test_servers_are_actually_cabled_to_that_switch(self):
        """Save from the previous test: if you change which switch they are wired to, you find out."""
        plan = _big_plan()
        switches = [d for d in plan.devices if d.category == "switch"]
        server_names = {d.name for d in plan.devices if d.category == "server"}
        for link in plan.links:
            if link.device_b in server_names:
                assert link.device_a == switches[0].name
            elif link.device_a in server_names:
                assert link.device_b == switches[0].name
