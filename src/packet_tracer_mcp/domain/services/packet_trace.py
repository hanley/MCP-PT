"""
Reading the PT simulation event list: what each package did and why. 

Pure logic, without bridge — testable with synthetic dicts, just like topology_diff. 

What makes this useful is not the list of packages but the decision log: PT 
expounds, by frame and by OSI layer, the same prose explanation that he shows in the 
"PDU Details" panel of your GUI. Verified against PT 9.0.0.0810 with a ping of PC1 to 
your gateway: 

L3 :: The source IP address is not specified. The device sets it to the port's IP address. 
L3 :: The destination IP address is in the same subnet. The device sets the next-hop to destination. 
L2 :: The next-hop IP address is not in the ARP table. The ARP process... buffers this packet. 

That makes "ping not working" a concrete cause.
"""

from __future__ import annotations

# getUserTrafficType() returns an integer. 0 and ICMP and 5 and ARP are MEASURED (ping 
# of PC1 to its gateway: the ICMP is buffered and the ARP broadcast goes out first). 
# The rest were not observed, so the crude oil is returned instead of inventing names.
TRAFFIC_TYPES = {0: "ICMP", 5: "ARP"}

# Order of precedence when deriving ONE state per frame. What blocks comes first: 
# A discarded frame matters more than one "sent" in the same tick.

_STATUS_ORDER = (
    ("dropped", "dropped"),
    ("collided_on_link", "collided_on_link"),
    ("collided_at_device", "collided_at_device"),
    ("not_forwarded", "not_forwarded"),
    ("unexpected", "unexpected"),
    ("buffered", "buffered"),
    ("in_transit", "in_transit"),
    ("accepted", "accepted"),
    ("sent", "sent"),
)

# Statuses that mean "this package did not arrive at its destination".
FAILURE_STATUSES = frozenset({
    "dropped", "collided_on_link", "collided_at_device",
    "not_forwarded", "unexpected",
})


def traffic_type_label(raw) -> str:
    """Label of the type of traffic; let crude oil pass if it was not observed."""
    return TRAFFIC_TYPES.get(raw, f"type{raw}")


def frame_status(frame: dict) -> str:
    """A single state per frame, based on PT's Boolean flags."""
    for flag, status in _STATUS_ORDER:
        if frame.get(flag):
            return status
    return "pending"


def summarize_trace(frames: list[dict]) -> dict:
    """Group the event list and separate what failed from what didn't."""    
    by_status: dict[str, int] = {}
    by_device: dict[str, int] = {}
    failures: list[dict] = []

    for frame in frames:
        status = frame_status(frame)
        frame["status"] = status
        by_status[status] = by_status.get(status, 0) + 1

        device = frame.get("device") or "?"
        by_device[device] = by_device.get(device, 0) + 1

        if status in FAILURE_STATUSES:
            failures.append({
                "device": device,
                "status": status,
                "destination": frame.get("destination", ""),
                "traffic": frame.get("traffic_type", ""),
                # The last decision is the one that explains the outcome.
                "reason": (frame.get("decisions") or [{}])[-1].get("description", ""),
            })

    return {
        "frames": len(frames),
        "by_status": dict(sorted(by_status.items())),
        "by_device": dict(sorted(by_device.items())),
        "failures": failures,
        "clean": not failures,
    }
