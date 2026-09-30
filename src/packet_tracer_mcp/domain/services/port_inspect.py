"""
PT Live Port Inspection Summary. 

Pure logic, without bridge — testable with synthetic dicts, just like topology_diff. 

The detail per port is returned by the bridge reader; here it is only added and 
mark the anomalies that a human would look at first. pt_health_check already covers 
the sweep of the entire topology (links down, IPs duplicated): this is the view of 
detail of ONE device, so it does not repeat those global checks.
"""

from __future__ import annotations

# Verified against PT 9.0.0.0810: getNatMode() returns 0 on a clean port and 
# 1 after 'ip nat inside'. 2 is the only value remaining in IOS ('ip nat 
# outside') — inferred, not observed.
NAT_MODES = {0: "none", 1: "inside", 2: "outside"}


def nat_mode_label(raw) -> str:
    """NAT mode readable label; lets crude oil pass through if a new value appears."""
    return NAT_MODES.get(raw, f"unknown({raw})")


def summarize_ports(devices: list[dict]) -> dict:
    """Adds the detail by port and marks anomalies. 
    
    'devices' is [{name, model, ports: [{name, up, linked, ip,...}]}].
    """
    total = 0
    up = 0
    linked = 0
    anomalies: list[dict] = []

    for dev in devices:
        dname = dev.get("name", "?")
        for port in dev.get("ports", []):
            total += 1
            p_up = bool(port.get("up"))
            p_linked = bool(port.get("linked"))
            if p_up:
                up += 1
            if p_linked:
                linked += 1

            pname = port.get("name", "?")
            # Cable put on and the port does not lift: it is the classic symptom of a 
            # Forgotten shutdown or the wrong type of cable.
            if p_linked and not p_up:
                anomalies.append({
                    "device": dname, "port": pname, "issue": "linked_but_down", 
                    "detail": "You have cable but the port is down (shutdown or wrong cable?).",
                })
            # Layer 1 above but protocol below: encapsulation or keepalive.
            elif p_up and not port.get("protocol_up", True):
                anomalies.append({
                    "device": dname, "port": pname, "issue": "protocol_down",
                    "detail": "Line up but down protocol (encapsulation or keepalive).",
                })

    return {
        "devices_inspected": len(devices),
        "ports_total": total,
        "ports_up": up,
        "ports_linked": linked,
        "anomalies": anomalies,
    }
