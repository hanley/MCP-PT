"""NetFlow (pt_apply_netflow) and QoS reader (pt_read_qos) tests. 

Signatures taken from the IpcAPI reference installed by PT and verified 
live against a 2911: 'createNFExporter(name)' returns the exporter, the 
setters apply and 'isFullyConfigured()' goes to true with destination and port set.
"""

from pathlib import Path

import pytest

from src.packet_tracer_mcp.domain.models.errors import ErrorCode
from src.packet_tracer_mcp.domain.models.netflow import NetflowExporter
from src.packet_tracer_mcp.domain.rules.netflow_rules import (
    VALID_VERSIONS,
    validate_netflow,
    validate_netflow_against_topology,
)


def _cfg(**overrides) -> NetflowExporter:
    base = {"device": "R1", "name": "COLLECTOR-1", "destination_ip": "192.168.0.50"}
    base.update(overrides)
    return NetflowExporter(**base)


def _codes(result) -> set[str]:
    return {e.code for e in result.errors}


class TestNetflowValidation:
    def test_sane_config_passes(self):
        result = validate_netflow(_cfg())
        assert result.is_valid
        assert not result.warnings

    def test_defaults_match_the_common_collector(self):
        cfg = _cfg()
        assert cfg.udp_port == 2055
        assert cfg.version == 9

    def test_empty_name_is_rejected(self):
        assert ErrorCode.NETFLOW_INVALID_NAME in _codes(validate_netflow(_cfg(name="   ")))

    @pytest.mark.parametrize("bad", ["A\nB", "A\rB"])
    def test_newline_in_name_is_rejected_not_escaped(self, bad):
        """The name travels within a single-line JS literal."""
        assert ErrorCode.NETFLOW_INVALID_NAME in _codes(validate_netflow(_cfg(name=bad)))

    @pytest.mark.parametrize("bad", ["999.1.1.1", "192.168.0", "no-una-ip", "::1"])
    def test_invalid_destination_is_rejected(self, bad):
        result = validate_netflow(_cfg(destination_ip=bad))
        assert ErrorCode.NETFLOW_INVALID_DESTINATION in _codes(result)

    @pytest.mark.parametrize("port", [0, -1, 65536])
    def test_port_out_of_range(self, port):
        assert ErrorCode.NETFLOW_INVALID_PORT in _codes(validate_netflow(_cfg(udp_port=port)))

    @pytest.mark.parametrize("version", [5, 9])
    def test_supported_versions(self, version):
        assert validate_netflow(_cfg(version=version)).is_valid
        assert version in VALID_VERSIONS

    @pytest.mark.parametrize("version", [1, 7, 10])
    def test_unsupported_version_is_rejected(self, version):
        assert ErrorCode.NETFLOW_INVALID_VERSION in _codes(validate_netflow(_cfg(version=version)))

    def test_missing_destination_warns_but_is_valid(self):
        """You can create the exporter and complete it later; PT marks it incomplete."""
        result = validate_netflow(_cfg(destination_ip=""))
        assert result.is_valid
        assert any(w.code == ErrorCode.NETFLOW_INCOMPLETE for w in result.warnings)

    def test_bad_monitor_name_is_rejected(self):
        assert ErrorCode.NETFLOW_INVALID_NAME in _codes(validate_netflow(_cfg(monitors=["ok", ""])))

    def test_every_error_carries_a_suggestion(self):
        result = validate_netflow(_cfg(name="", destination_ip="x", udp_port=0, version=3))
        assert result.errors
        for err in result.errors:
            assert err.suggestion.strip()


class TestNetflowAgainstTopology:
    LIVE = [{"name": "R1", "model": "2911", "ports": [
        {"name": "GigabitEthernet0/0"}, {"name": "GigabitEthernet0/1"}]}]

    def test_device_must_exist(self):
        result = validate_netflow_against_topology(_cfg(device="R9"), self.LIVE)
        assert ErrorCode.NETFLOW_DEVICE_NOT_FOUND in _codes(result)

    def test_source_port_must_exist(self):
        result = validate_netflow_against_topology(
            _cfg(source_port="GigabitEthernet0/5"), self.LIVE)
        assert ErrorCode.NETFLOW_PORT_NOT_FOUND in _codes(result)

    def test_real_source_port_passes(self):
        result = validate_netflow_against_topology(
            _cfg(source_port="GigabitEthernet0/0"), self.LIVE)
        assert result.is_valid

    def test_unreadable_ports_fail_open(self):
        """To reject a correct config because of an incomplete read would be worse."""
        result = validate_netflow_against_topology(
            _cfg(source_port="GigabitEthernet0/0"), [{"name": "R1", "model": "2911"}])
        assert result.is_valid


class TestPhase3Readers:
    """Guards over JS. Closures in register_tools → text verification."""

    def _src(self) -> str:
        return Path("src/packet_tracer_mcp/adapters/mcp/tool_registry.py").read_text(
            encoding="utf-8"
        )

    def test_netflow_reuses_an_existing_exporter(self):
        """Reapplying the same config should not duplicate the exporter. 
        
        The JS is armed with an f-string, so in the SOURCE the keys go ('{{') 
        even if the payload issued has only one.
        """
        src = self._src()
        assert "getNFExporterByName(" in src
        assert "if (!__e) {{ __e = __m.createNFExporter(" in src

    def test_netflow_is_feature_detected(self):
        assert "typeof __d.getNetflowExporterManager !== 'function'" in self._src()

    def test_netflow_reads_back_after_writing(self):
        """Without readback it is not known if PT accepted the config."""
        src = self._src()
        assert "fully_configured: !!__e.isFullyConfigured()" in src

    def test_qos_tool_does_not_pretend_to_write(self):
        """The PT API does not have createClassMap: pt_read_qos is read-only. 
        
        The CALL ('createClassMap('), is searched, not the name itself: the Docstring 
        mentions it precisely to explain why it can't.
        """
        src = self._src()
        assert "def pt_read_qos(" in src
        assert "createClassMap(" not in src
        assert "getClassMapAt(__i)" in src

    def test_error_types_are_imported(self):
        """PlanError/ErrorCode are used in the pt_apply_netflow except."""
        src = self._src()
        assert "from ...domain.models.errors import ErrorCode, PlanError" in src
