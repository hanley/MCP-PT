"""Simulation trace tests (pt_read_packet_trace and company). 

The shape of the data is verified against PT 9.0.0.0810: a 'ping' 
from a PC-PT to your gateway generates two frames — ICMP is buffered 
(traffic type 0) while the ARP broadcast (type 5) comes out first 
— and each one brings its own decisions per OSI layer.
"""

from pathlib import Path

import pytest

from src.packet_tracer_mcp.domain.services.packet_trace import (
    FAILURE_STATUSES,
    TRAFFIC_TYPES,
    frame_status,
    summarize_trace,
    traffic_type_label,
)

# Captured actual PT frame: The ICMP that is left waiting for ARP resolution.
ICMP_BUFFERED = {
    "device": "PC1",
    "destination": "192.168.0.1",
    "traffic_type": "ICMP",
    "buffered": True,
    "decisions": [
        {"layer": 3, "inbound": False,
         "description": "The Ping process starts the next ping request."},
        {"layer": 2, "inbound": False,
         "description": "The next-hop IP address is not in the ARP table. The ARP "
                        "process tries to send an ARP request for that IP address "
                        "and buffers this packet."},
    ],
}


def _frame(**overrides) -> dict:
    base = {"device": "PC1", "destination": "192.168.0.1", "traffic_type": "ICMP",
            "decisions": []}
    base.update(overrides)
    return base


class TestTrafficTypeLabel:
    @pytest.mark.parametrize("raw,label", [(0, "ICMP"), (5, "ARP")])
    def test_measured_types(self, raw, label):
        """Only 0 and 5 were observed against real PT."""
        assert traffic_type_label(raw) == label
        assert TRAFFIC_TYPES[raw] == label

    def test_unobserved_type_is_not_invented(self):
        """To invent a name for an unobserved value would be a false claim."""
        assert traffic_type_label(9) == "type9"


class TestFrameStatus:
    def test_pending_when_nothing_is_set(self):
        assert frame_status(_frame()) == "pending"

    @pytest.mark.parametrize("flag,status", [
        ("dropped", "dropped"),
        ("collided_on_link", "collided_on_link"),
        ("collided_at_device", "collided_at_device"),
        ("not_forwarded", "not_forwarded"),
        ("unexpected", "unexpected"),
        ("buffered", "buffered"),
        ("in_transit", "in_transit"),
        ("accepted", "accepted"),
        ("sent", "sent"),
    ])
    def test_each_flag_maps_to_its_status(self, flag, status):
        assert frame_status(_frame(**{flag: True})) == status

    def test_failure_wins_over_success(self):
        """A discarded frame matters more than one 'sent' in the same tick."""
        assert frame_status(_frame(sent=True, dropped=True)) == "dropped"

    def test_collision_wins_over_buffered(self):
        assert frame_status(_frame(buffered=True, collided_on_link=True)) == "collided_on_link"

    def test_failure_statuses_are_the_ones_that_block(self):
        assert "sent" not in FAILURE_STATUSES
        assert "buffered" not in FAILURE_STATUSES
        assert "dropped" in FAILURE_STATUSES


class TestSummarizeTrace:
    def test_empty_trace(self):
        result = summarize_trace([])
        assert result["frames"] == 0
        assert result["clean"]
        assert result["failures"] == []

    def test_real_ping_pair_is_clean(self):
        """A buffered ARP + ICMP is the normal boot of a ping, not a failure."""
        result = summarize_trace([
            dict(ICMP_BUFFERED),
            _frame(traffic_type="ARP", destination="Broadcast", sent=True),
        ])
        assert result["clean"]
        assert result["frames"] == 2
        assert result["by_status"] == {"buffered": 1, "sent": 1}

    def test_status_is_written_back_onto_each_frame(self):
        frames = [_frame(sent=True)]
        summarize_trace(frames)
        assert frames[0]["status"] == "sent"

    def test_counts_group_by_device(self):
        result = summarize_trace([
            _frame(device="PC1", sent=True),
            _frame(device="SW1", sent=True),
            _frame(device="SW1", dropped=True),
        ])
        assert result["by_device"] == {"PC1": 1, "SW1": 2}

    def test_failure_carries_the_last_decision_as_the_reason(self):
        """The last decision is the one that explains the outcome."""
        result = summarize_trace([_frame(dropped=True, device="R1", decisions=[
            {"layer": 3, "inbound": True, "description": "The device receives the frame."},
            {"layer": 3, "inbound": False,
             "description": "The routing table has no matching route. The device drops the packet."},
        ])])
        assert not result["clean"]
        failure = result["failures"][0]
        assert failure["device"] == "R1"
        assert failure["status"] == "dropped"
        assert "no matching route" in failure["reason"]

    def test_failure_without_decisions_does_not_crash(self):
        result = summarize_trace([_frame(dropped=True, decisions=[])])
        assert result["failures"][0]["reason"] == ""

    def test_missing_device_is_tolerated(self):
        result = summarize_trace([{"dropped": True}])
        assert result["by_device"] == {"?": 1}


class TestSimulationReaders:
    """Guards on the JS. They are closures in register_tools, so they are verified 
    by text, same as TestReconcileWiring in test_live_reconcile.py."""

    def _src(self) -> str:
        return Path("src/packet_tracer_mcp/adapters/mcp/tool_registry.py").read_text(
            encoding="utf-8"
        )

    def test_uses_pts_misspelled_decision_getter(self):
        """PT exposes 'getFrameDecsionAt', with the typo. Correcting it breaks the reading."""
        assert "getFrameDecsionAt(__j)" in self._src()

    def test_out_port_access_is_guarded_by_count(self):
        """getOutPort(0) launches when the frame is buffered and has no output."""
        src = self._src()
        assert "__f.getOutPortCount() > 0" in src

    def test_decisions_are_read_as_properties_not_methods(self):
        """FrameDecsion exposes description/osiLayer/osiIn as properties."""
        src = self._src()
        assert "__d.osiLayer" in src
        assert "__d.description" in src

    def test_step_refuses_to_act_in_realtime(self):
        assert "if (!__s.isSimulationMode())" in self._src()

    def test_step_action_is_validated_before_reaching_js(self):
        """'action' is not interpolated: it maps to a call from a closed list."""
        src = self._src()
        assert 'if act not in ("forward", "back", "reset")' in src
