"""Regressions from the second audit pass (tested against PT 9.0.1). 

A default test found handling the MCP against real Packet Tracer. 
Each one fails if the fix is reversed.
"""

from pathlib import Path

import pytest

from src.packet_tracer_mcp.infrastructure.catalog.modules import (
    resolve_module,
    ports_for_slot,
)
from src.packet_tracer_mcp.infrastructure.catalog.devices import category_of_model
from src.packet_tracer_mcp.infrastructure.catalog.cables import infer_cable
from src.packet_tracer_mcp.domain.services.auto_fixer import fix_plan
from src.packet_tracer_mcp.domain.models.plans import TopologyPlan, DevicePlan, LinkPlan


# --- Puertos de un módulo según el slot -----------------------------------


class TestPortsForSlot:
    """An HWIC-2T on "0/1" gives Serial0/1/x, not Serial0/0/x. 
    
    'ModuleSpec.ports_added' lists them for the first slot in the family. 
    To return them raw, a batch of two HWIC-2T reported the SAME ports for both, 
    and wiring to the reported name failed.
    """

    def test_hwic_in_first_slot_is_unchanged(self):
        spec = resolve_module("HWIC-2T")
        assert ports_for_slot(spec, "0/0") == ["Serial0/0/0", "Serial0/0/1"]

    @pytest.mark.parametrize(
        "slot,expected",
        [
            ("0/1", ["Serial0/1/0", "Serial0/1/1"]),
            ("0/2", ["Serial0/2/0", "Serial0/2/1"]),
            ("0/3", ["Serial0/3/0", "Serial0/3/1"]),
        ],
    )
    def test_hwic_carries_the_slot_into_the_port_name(self, slot, expected):
        assert ports_for_slot(resolve_module("HWIC-2T"), slot) == expected

    def test_two_modules_on_one_router_do_not_collide(self):
        """The real case: 4 serial ports with two HWIC-2T."""
        spec = resolve_module("HWIC-2T")
        combined = ports_for_slot(spec, "0/0") + ports_for_slot(spec, "0/1")
        assert len(set(combined)) == 4, f"Duplicate ports: {combined}"

    def test_nim_slot_is_rewritten_too(self):
        spec = resolve_module("NIM-2T")
        assert ports_for_slot(spec, "0/2") == ["Serial0/2/0", "Serial0/2/1"]

    def test_nm_slot_without_subslot_is_left_alone(self):
        """An NM uses slot "1" and its ports are already well from the catalog."""
        spec = resolve_module("NM-4A/S")
        assert ports_for_slot(spec, "1") == list(spec.ports_added)

    def test_garbage_slot_falls_back_to_the_catalog(self):
        spec = resolve_module("HWIC-2T")
        assert ports_for_slot(spec, "no/is-a-slot") == list(spec.ports_added)


# --- Inferencia de cable por modelo ---------------------------------------


class TestCableInferenceUsesModel:
    """PT ranks by behavior, not by network role. 
    
    'getClassName()' returns "Router" for a 3560 (multilayer switch) and 
    "CiscoDevice" for a 2960, so the "switch" category never arrived to 
    CABLE_RULES and every switch router↔was crossed wired. The category 
    comes out of the MODEL, which does discriminate.
    """

    @pytest.mark.parametrize(
        "model,expected",
        [
            ("1941", "router"),
            ("2911", "router"),
            ("3560-24PS", "switch"),   # the one PT calls "Router"
            ("2960-24TT", "switch"),   # which PT calls "CiscoDevice"
            ("PC-PT", "pc"),
            ("Server-PT", "server"),
        ],
    )
    def test_model_maps_to_catalog_category(self, model, expected):
        assert category_of_model(model) == expected

    def test_unknown_model_is_empty_not_a_guess(self):
        assert category_of_model("This Model does not exist") == ""

    @pytest.mark.parametrize("switch", ["3560-24PS", "2960-24TT"])
    def test_router_to_switch_is_straight(self, switch):
        """The bug: it gave 'cross' for the 3560 to come as a "Router"."""
        cable = infer_cable(category_of_model("1941"), category_of_model(switch))
        assert cable == "straight"

    def test_router_to_router_is_still_cross(self):
        cable = infer_cable(category_of_model("2911"), category_of_model("1941"))
        assert cable == "cross"

    def test_switch_to_pc_is_straight(self):
        cable = infer_cable(category_of_model("3560-24PS"), category_of_model("PC-PT"))
        assert cable == "straight"


# --- fix_plan moves the IP with the port ------------------------------------


class TestRenameRejectsDuplicates:
    """Renaming a busy name left TWO devices the same. 
    
    PT allows it without a murmur, and from there 'getDevice(name)' only 
    resolves one: the other is still on the canvas but is unreachable by name, 
    so any tool that references it works silently on the wrong. Played against 
    PT 9.0.1 renaming a 2960 to "R1", which it was a 2911: 'getDevices("")' 
    went on to list "R1" twice. 
    
    'pt_add_device' did validate; 'pt_rename_device' did not.
    """

    def _src(self) -> str:
        return Path(
            "src/packet_tracer_mcp/adapters/mcp/tool_registry.py"
        ).read_text(encoding="utf-8")

    def test_rename_checks_the_target_name_is_free(self):
        block = self._src().split("def pt_rename_device", 1)[1][:2000]
        assert 'getDevice("{safe_new}")' in block, "not checking if the name already exists"
        assert "ERROR:DUPLICATE" in block

    def test_duplicate_is_reported_with_a_reason(self):
        block = self._src().split("def pt_rename_device", 1)[1][:3000]
        assert "there is already a device called" in block


def test_fix_plan_moves_the_ip_to_the_corrected_port():
    """Correcting the port of a link has to drag its address. 
    
    Before, the link went to the new interface and the IP stayed on the old one 
    —who no longer used any link—, so the plan was "fixed" but internally inconsistent.
    """
    plan = TopologyPlan(
        name="t",
        devices=[
            DevicePlan(
                name="R1", model="2911", category="router", role="core_router",
                x=0, y=0,
                interfaces={"GigabitEthernet0/9": "192.168.0.1/24"},
                interfaces_v6={"GigabitEthernet0/9": "2001:db8::1/64"},
            ),
            DevicePlan(
                name="SW1", model="2960-24TT", category="switch",
                role="access_switch", x=0, y=0,
            ),
        ],
        links=[
            LinkPlan(
                device_a="R1", port_a="GigabitEthernet0/9",
                device_b="SW1", port_b="GigabitEthernet0/1", cable="straight",
            )
        ],
    )

    fixed, _ = fix_plan(plan)
    r1 = fixed.device_by_name("R1")
    new_port = fixed.links[0].port_a

    assert new_port != "GigabitEthernet0/9", "Link port not fixed"
    assert "GigabitEthernet0/9" not in r1.interfaces, "the IP remained in the old port"
    assert r1.interfaces[new_port] == "192.168.0.1/24"
    assert r1.interfaces_v6[new_port] == "2001:db8::1/64"
