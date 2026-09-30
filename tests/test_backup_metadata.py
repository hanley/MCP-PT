"""Supporting tests and metadata of the project. 

Both tools are closures in register_tools, so they are verified by equal text 
than TestReconcileWiring in test_live_reconcile.py. The shape of the data is 
taken from an actual reading against PT 9.0.0.0810.
"""

from pathlib import Path


def _src() -> str:
    return Path("src/packet_tracer_mcp/adapters/mcp/tool_registry.py").read_text(
        encoding="utf-8"
    )


class TestBackupConfig:
    def test_startup_is_split_on_commas(self):
        """PT returns the startup-config with the lines separated by COMAS. 
        
        Without rebuilding it, the backrest comes out on a single line and cannot be 
        paste into a CLI.
        """
        src = _src()
        assert 'startup.split(",")' in src
        assert r'"\n".join(lines)' in src

    def test_xml_dump_is_capped(self):
        """serializeToXml returns ~19k chars per device; roofless, one Medium 
        topology overwhelms the response of the tool."""
        src = _src()
        assert "_MAX_BACKUP_XML" in src
        assert "substring(0, {_MAX_BACKUP_XML})" in src

    def test_xml_is_opt_in(self):
        assert "include_xml: bool = False" in _src()

    def test_hosts_are_reported_not_crashed(self):
        src = _src()
        assert "typeof __d.getStartupFile !== 'function'" in src

    def test_empty_startup_tells_the_user_what_to_do(self):
        """A computer without 'write memory' does not have startup-config: it is not a mistake."""
        assert "write memory' on the computer before backing up" in _src()


class TestProjectMetadata:
    def test_description_write_is_opt_in(self):
        """Without argument, the tool is read-only."""
        src = _src()
        assert 'description: str = ""' in src
        assert "if new_desc else \"\"" in src

    def test_description_goes_through_json_dumps(self):
        assert "setNetworkDescription({json.dumps(new_desc)})" in _src()

    def test_unsaved_project_is_flagged(self):
        """An unsaved project is lost when PT closes; it must be said."""
        assert "Project NOT saved" in _src()

    def test_setter_is_feature_detected(self):
        assert "typeof __f.setNetworkDescription === 'function'" in _src()


class TestWorkspaceOptions:
    """They execute logic instead of reading the source: polarity is just 
    the kind of rule that a refactor can reverse without any 'assert "..." 
    in src' find out."""

    def test_negative_polarity_setters_are_inverted(self):
        """PT exposes two of these in negative ('setDisableAutoCabling', 'setHideDevLabel'). 
        If the friendly flag is not reversed, the tool does exactly the opposite of what the 
        user asks for and silently."""
        from src.packet_tracer_mcp.adapters.mcp.tool_registry import (
            workspace_setter_call,
        )

        # activate auto-cabling => DISABLE the "disable"
        assert workspace_setter_call("auto_cabling", 1) == ("setDisableAutoCabling", "false")
        assert workspace_setter_call("auto_cabling", 0) == ("setDisableAutoCabling", "true")
        # show tags => DO NOT hide them (and with the 2nd argument required)
        assert workspace_setter_call("show_device_labels", 1) == ("setHideDevLabel", "false, true")
        assert workspace_setter_call("show_device_labels", 0) == ("setHideDevLabel", "true, true")

    def test_positive_polarity_setters_are_not_inverted(self):
        from src.packet_tracer_mcp.adapters.mcp.tool_registry import (
            workspace_setter_call,
        )

        assert workspace_setter_call("show_port_labels", 1) == ("setIsPortShown", "true")
        assert workspace_setter_call("show_port_labels", 0) == ("setIsPortShown", "false")
        assert workspace_setter_call("show_link_lights", 1) == ("setIsLinkLightShown", "true")
        assert workspace_setter_call("external_network_access", 0) == (
            "setEnableExternalNetworkAccess", "false")

    def test_hide_dev_label_carries_its_second_argument(self):
        """PT rejects 'setHideDevLabel(x)' with a single argument: 
        'Invalid arguments for IPC call'. Verified against PT 9.0.1."""
        from src.packet_tracer_mcp.adapters.mcp.tool_registry import (
            workspace_setter_call,
        )

        _, args = workspace_setter_call("show_device_labels", 1)
        assert args.count(",") == 1, f"setHideDevLabel needs 2 arguments, it came out: {args}"

    def test_readback_undoes_the_inversion(self):
        """What is returned has to be in the same polarity as the input."""
        src = _src()
        assert "auto_cabling: !__o.isAutoCablingDisabled()" in src
        assert "show_device_labels: !__o.isHideDevLabel()" in src

    def test_all_flags_default_to_no_change(self):
        src = _src()
        for flag in ("auto_cabling", "external_network_access", "show_port_labels",
                     "show_link_lights", "show_device_labels"):
            assert f"{flag}: int = -1" in src

    def test_external_network_access_is_called_out(self):
        """Pulling traffic from the simulator to the real network deserves a warning."""
        assert "REAL network access enabled" in _src()
