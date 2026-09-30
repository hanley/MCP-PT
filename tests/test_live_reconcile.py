"""Reconcile (F16) and DHCP fallback tests of the last host (F17)."""
import re
from pathlib import Path

import pytest

from src.packet_tracer_mcp.domain.models.requests import TopologyRequest
from src.packet_tracer_mcp.domain.services.orchestrator import plan_from_request
from src.packet_tracer_mcp.infrastructure.generator.ptbuilder_generator import (
    generate_executable_script,
)


class TestDHCPFallback:
    def test_last_host_per_lan_is_static(self):
        # 1 router, 3 PCs, DHCP on → 2 DHCP + 1 static (the one with the highest IP)
        req = TopologyRequest(routers=1, pcs_per_lan=3, dhcp=True)
        plan, _ = plan_from_request(req)
        script = generate_executable_script(plan)

        dhcp_calls = re.findall(r"configurePcIp\([^,]+, true\)", script)
        static_calls = re.findall(r"configurePcIp\([^,]+, false,", script)
        assert len(dhcp_calls) == 2
        assert len(static_calls) == 1
        # static is the one with the highest IP (.4)
        assert "192.168.0.4" in script

    def test_two_lans_one_static_each(self):
        req = TopologyRequest(routers=2, pcs_per_lan=2, dhcp=True, routing="static")
        plan, _ = plan_from_request(req)
        script = generate_executable_script(plan)
        static_calls = re.findall(r"configurePcIp\([^,]+, false,", script)
        # one static host per LAN (2 LANs)
        assert len(static_calls) == 2

    def test_no_dhcp_all_static(self):
        req = TopologyRequest(routers=1, pcs_per_lan=3, dhcp=False)
        plan, _ = plan_from_request(req)
        script = generate_executable_script(plan)
        assert "configurePcIp" in script
        assert ", true)" not in script  # no DHCP


class TestReconcileWiring:
    def test_pt_live_deploy_has_reconcile(self):
        src = Path("src/packet_tracer_mcp/adapters/mcp/tool_registry.py").read_text(encoding="utf-8")
        assert "Reconcile (fix F16)" in src
        assert "reconciled" in src
        assert "link_fail_objs" in src

    def test_lwadddevice_has_global_fallback(self):
        """F16 root cause: lw.addDevice fails for Laptop-PT (type 17) → returns" and does 
        not creates nothing. lwAddDevice drops to the global addDevice (resolves by model name), 
        Reliable. Verified live. This guard avoids losing the fallback. Helper lives now in the 
        extension (installMcpHelpers), not in an injected patch."""
        js = Path("EXTENSION/script-engine/main.js").read_text(encoding="utf-8")
        assert "GLOBAL.lwAddDevice = function" in js
        assert "if (!ipc.network().getDevice(name))" in js
        assert "addDevice(name, model, x, y)" in js
