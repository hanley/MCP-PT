"""Port inspection tests (pt_inspect_ports) and the rest of Phase 1. 

Numeric values are verified against PT 9.0.0.0810: getNatMode() returns 0 
on a clean port and 1 after 'IP Nat Inside'.
"""

from pathlib import Path

import pytest

from src.packet_tracer_mcp.domain.services.port_inspect import (
    NAT_MODES,
    nat_mode_label,
    summarize_ports,
)


def _port(**overrides) -> dict:
    base = {"name": "GigabitEthernet0/0", "up": True, "protocol_up": True, "linked": True}
    base.update(overrides)
    return base


def _dev(name: str = "R1", ports=None) -> dict:
    return {"name": name, "model": "2911", "ports": ports if ports is not None else [_port()]}


class TestNatModeLabel:
    @pytest.mark.parametrize("raw,label", [(0, "none"), (1, "inside"), (2, "outside")])
    def test_known_modes(self, raw, label):
        assert nat_mode_label(raw) == label

    def test_unknown_mode_keeps_the_raw_value(self):
        """A new PT value should not be lost or broken by the tool."""
        assert nat_mode_label(7) == "unknown(7)"

    def test_none_is_not_confused_with_mode_zero(self):
        assert nat_mode_label(None) == "unknown(None)"
        assert NAT_MODES[0] == "none"


class TestSummarizePorts:
    def test_counts(self):
        result = summarize_ports([_dev(ports=[
            _port(name="Gi0/0", up=True, linked=True),
            _port(name="Gi0/1", up=False, linked=False),
            _port(name="Gi0/2", up=True, linked=False),
        ])])
        assert result["devices_inspected"] == 1
        assert result["ports_total"] == 3
        assert result["ports_up"] == 2
        assert result["ports_linked"] == 1

    def test_empty_input(self):
        result = summarize_ports([])
        assert result["ports_total"] == 0
        assert result["anomalies"] == []

    def test_healthy_ports_raise_nothing(self):
        assert summarize_ports([_dev()])["anomalies"] == []

    def test_linked_but_down_is_flagged(self):
        """Cable on and port down: shutdown forgotten or wrong cable."""
        result = summarize_ports([_dev(ports=[_port(up=False, linked=True)])])
        assert len(result["anomalies"]) == 1
        anomaly = result["anomalies"][0]
        assert anomaly["issue"] == "linked_but_down"
        assert anomaly["device"] == "R1"
        assert anomaly["port"] == "GigabitEthernet0/0"

    def test_protocol_down_is_flagged(self):
        result = summarize_ports([_dev(ports=[_port(up=True, protocol_up=False)])])
        assert result["anomalies"][0]["issue"] == "protocol_down"

    def test_down_and_unlinked_is_not_an_anomaly(self):
        """A free and shut down port is the norm, not a find."""
        assert summarize_ports([_dev(ports=[_port(up=False, linked=False)])])["anomalies"] == []

    def test_anomalies_are_not_double_counted(self):
        """linked_but_down and protocol_down are exclusive: a port gives a find."""
        result = summarize_ports([_dev(ports=[_port(up=False, protocol_up=False, linked=True)])])
        assert len(result["anomalies"]) == 1

    def test_missing_protocol_up_defaults_to_ok(self):
        """Models that do not expose isProtocolUp send null: do not invent an anomaly."""
        port = _port()
        del port["protocol_up"]
        assert summarize_ports([_dev(ports=[port])])["anomalies"] == []

    def test_multiple_devices(self):
        result = summarize_ports([
            _dev("R1", [_port(up=False, linked=True)]),
            _dev("R2", [_port()]),
        ])
        assert result["devices_inspected"] == 2
        assert [a["device"] for a in result["anomalies"]] == ["R1"]


class TestPhase1Readers:
    """Guards on JS readers. They are closures in register_tools, so they are They 
    verify by text, just like TestReconcileWiring in test_live_reconcile.py."""

    def _src(self) -> str:
        return Path("src/packet_tracer_mcp/adapters/mcp/tool_registry.py").read_text(
            encoding="utf-8"
        )

    def test_port_getters_are_feature_detected(self):
        """The surface of Port changes by model; an absent method launches and 
        opens a modal that freezes the bridge."""
        src = self._src()
        for method in ("isProtocolUp", "getMacAddress", "getNatMode", "getAclInID", "getMtu"):
            assert f"typeof __p.{method} === 'function'" in src

    def test_power_control_is_feature_detected(self):
        """Defensive Guard: The surface area varies by build. 
        
        Measured in PT 9.0.0.0810 ALL devices expose setPower/getPower 
        —routers, switches, PC-PTs, and even the "Power Distribution Device"
        — so today this branch is not taken. It is maintained because an absent 
        method launches and Open a modal that freezes the bridge until a human closes it.
        """
        src = self._src()
        assert "typeof __d.setPower !== 'function'" in src
        assert "supported: false" in src

    def test_skipboot_is_guarded_separately_from_power(self):
        """skipBoot/isBooting IS missing from the hosts: PC-PT does not have them."""
        src = self._src()
        assert "typeof __d.skipBoot === 'function'" in src
        assert "typeof __d.isBooting === 'function'" in src

    def test_vlan_reader_guards_each_entry(self):
        src = self._src()
        assert "getProcess('VlanManager')" in src
        assert "catch (__ve) {}" in src

    def test_device_names_go_through_json_dumps(self):
        """Rule of AGENTS.md: Never interpolate a raw name in the JS."""
        src = self._src()
        assert "name = json.dumps(switch.strip())" in src
        assert "name = json.dumps(device.strip())" in src
        assert "want = json.dumps(device.strip())" in src
