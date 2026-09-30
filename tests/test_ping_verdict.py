"""Ping verdict and IOS console. 

Two distinct regressions, both in pt_verify_connectivity: 

1. 'interpret_ping' returned a bool "at least one arrived", so 1 of 4 packets 
were reported as "OK CONNECTIVITY" the same as 4 out of 4. A link looked 
identical to a healthy one. 
2. The JS asked for 'getCommandPrompt()', which ONLY exists on hosts. 
Against a router burst with 'TypeError: Property 'getCommandPrompt' of 
object is not a function' file, even though the docstring documents the 
IOS format. Verified against PT 9.0.1: routers expose 'getCommandLine()', 
and PCs expose both, so 'getCommandLine()' works for both.
"""

import pytest

from src.packet_tracer_mcp.shared.utils import classify_ping, interpret_ping
from src.packet_tracer_mcp.adapters.mcp.tool_registry import (
    console_ping_arm_js, console_ping_poll_js,
)


HOST_FULL = "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)"
HOST_PARTIAL = "Packets: Sent = 4, Received = 1, Lost = 3 (75% loss)"
HOST_NONE = "Packets: Sent = 4, Received = 0, Lost = 4 (100% loss)"
IOS_FULL = "Success rate is 100 percent (5/5)"
IOS_PARTIAL = "Success rate is 80 percent (4/5)"
IOS_NONE = "Success rate is 0 percent (0/5)"


class TestClassifyPing:
    @pytest.mark.parametrize("stat,expected", [
        (HOST_FULL, "ok"),
        (HOST_PARTIAL, "partial"),
        (HOST_NONE, "none"),
        (IOS_FULL, "ok"),
        (IOS_PARTIAL, "partial"),
        (IOS_NONE, "none"),
        ("", "none"),
        ("basura sin estadisticas", "none"),
    ])
    def test_classification(self, stat, expected):
        assert classify_ping(stat) == expected

    def test_partial_loss_is_not_the_same_as_full_success(self):
        """Bug: 1 of 4 was reported the same as 4 of 4."""
        assert classify_ping(HOST_PARTIAL) != classify_ping(HOST_FULL)

    def test_interpret_ping_keeps_its_boolean_contract(self):
        """It is still 'at least one' for those who already used it."""
        assert interpret_ping(HOST_PARTIAL) is True
        assert interpret_ping(HOST_NONE) is False
        assert interpret_ping(IOS_FULL) is True


class TestIosConsoleJs:
    def test_arm_js_uses_getcommandline(self):
        js = console_ping_arm_js("R1", "192.168.5.1")
        assert "getCommandLine()" in js

    def test_arm_js_never_uses_the_host_only_api(self):
        """getCommandPrompt doesn't exist on IOS: it's what broke the ping."""
        js = console_ping_arm_js("R1", "192.168.5.1")
        assert "getCommandPrompt" not in js

    def test_poll_js_never_uses_the_host_only_api(self):
        js = console_ping_poll_js("R1", 0)
        assert "getCommandPrompt" not in js
        assert "getCommandLine()" in js

    def test_arm_js_answers_the_setup_dialog(self):
        """Routers start standing in the initial configuration dialog. 
        
        Verified against PT 9.0.1: without responding to it, the ping is 
        consumed as Yes/No response and never executes.
        """
        js = console_ping_arm_js("R1", "192.168.5.1")
        assert "yes/no" in js

    def test_arm_js_carries_the_target(self):
        js = console_ping_arm_js("R1", "10.0.0.9")
        assert "ping 10.0.0.9" in js

    def test_device_name_is_escaped(self):
        """A name with quotation marks cannot break the generated JS."""
        js = console_ping_arm_js('R"1', "10.0.0.9")
        assert 'getDevice("R\\"1")' in js or "getDevice(\"R\\\"1\")" in js
