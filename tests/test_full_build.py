"""Integration test: full build complete."""

from pathlib import Path

import pytest
from src.packet_tracer_mcp.application.dto.requests import PlanTopologyDTO
from src.packet_tracer_mcp.application.use_cases.full_build import full_build


class TestFullBuild:
    def test_basic_2_routers(self):
        dto = PlanTopologyDTO(routers=2, pcs_per_lan=2, dhcp=True, routing="static")
        result = full_build(dto)
        assert result.is_valid
        assert len(result.errors) == 0
        assert len(result.explanation) > 0
        assert "lwAddDevice" in result.script
        assert len(result.configs) >= 2  # at least 2 routers

    def test_3_routers_wan(self):
        dto = PlanTopologyDTO(routers=3, pcs_per_lan=3, has_wan=True, dhcp=True)
        result = full_build(dto)
        assert result.is_valid
        assert "WAN" in result.script or "Cloud" in result.script

    def test_ospf_routing(self):
        dto = PlanTopologyDTO(routers=3, pcs_per_lan=2, routing="ospf")
        result = full_build(dto)
        assert result.is_valid
        # OSPF config should appear
        any_ospf = any("router ospf" in cfg for cfg in result.configs.values())
        assert any_ospf

    def test_single_router(self):
        dto = PlanTopologyDTO(routers=1, pcs_per_lan=5)
        result = full_build(dto)
        assert result.is_valid

    def test_no_dhcp(self):
        dto = PlanTopologyDTO(routers=2, pcs_per_lan=2, dhcp=False)
        result = full_build(dto)
        assert result.is_valid
        # No DHCP pools expected
        assert "ip dhcp pool" not in result.script

    def test_with_servers(self):
        dto = PlanTopologyDTO(routers=2, pcs_per_lan=2, servers=2)
        result = full_build(dto)
        assert result.is_valid

    def test_estimation_fields(self):
        dto = PlanTopologyDTO(routers=2, pcs_per_lan=2)
        result = full_build(dto)
        assert "devices_to_create" in result.estimation
        assert "links_to_create" in result.estimation
        assert result.estimation["devices_to_create"] > 0


class TestFullBuildLiveDeploy:
    """pt_full_build(deploy=True) has to deploy to PT when there is a channel. 
    
    I used to ALWAYS go to the clipboard: with the bridge connected by HTTP and by file, 
    'pt_full_build' returned "✅ Validation: PASS" and left the canvas empty 
    ('pt_query_topology' → DEVICES:0| LINKS:0). The "complete" pipeline I ended up not 
    building anything. 
    
    'pt_full_build' is a closure within 'register_tools', so you can't import; is 
    text-verified just like TestReconcileWiring in test_live_reconcile.py.
    """

    def _src(self) -> str:
        return Path("src/packet_tracer_mcp/adapters/mcp/tool_registry.py").read_text(
            encoding="utf-8"
        )

    def test_deploy_branches_on_live_channel(self):
        src = self._src()
        deploy_block = src.split("DEPLOY IN PACKET TRACER", 1)[1][:1600]
        # Decide by channel before falling to the clipboard.
        assert '_pick_channel() != ""' in deploy_block
        # And with live channel, delegate to the actual deploy path (with reconcile).
        assert "pt_live_deploy(" in deploy_block

    def test_clipboard_is_the_fallback_not_the_default(self):
        src = self._src()
        deploy_block = src.split("DEPLOY IN PACKET TRACER", 1)[1][:1600]
        live_at = deploy_block.index('_pick_channel() != ""')
        clip_at = deploy_block.index("SCRIPT COPIED TO CLIPBOARD")
        # The clipboard lives in the 'else', after channel checking.
        assert live_at < clip_at

    def test_files_still_exported_when_deploying_live(self):
        src = self._src()
        deploy_block = src.split("DEPLOY IN PACKET TRACER", 1)[1][:1600]
        # Deploy live should not lose the project on disk.
        assert "ManualExecutor(output_dir=\"projects\")" in deploy_block
