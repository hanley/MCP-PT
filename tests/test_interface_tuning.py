"""Interface fine-tuning tests."""

import pytest

from src.packet_tracer_mcp.domain.models.errors import ErrorCode
from src.packet_tracer_mcp.domain.models.interface_tuning import InterfaceTuning
from src.packet_tracer_mcp.domain.rules.interface_tuning_rules import (
    validate_interface_tuning, validate_interface_tuning_against_topology,
)
from src.packet_tracer_mcp.infrastructure.generator.interface_tuning_cli_generator import (
    generate_interface_tuning_cli,
)
from src.packet_tracer_mcp.application.use_cases.apply_interface_tuning import (
    apply_interface_tuning_uc,
)


class TestInterfaceTuningValidation:
    def test_clock_rate_on_non_serial_rejected(self):
        cfg = InterfaceTuning(router="R1", interface="GigabitEthernet0/0", clock_rate=64000)
        assert not validate_interface_tuning(cfg).is_valid

    def test_clock_rate_on_serial_passes(self):
        cfg = InterfaceTuning(router="R1", interface="Serial0/0/0", clock_rate=64000)
        assert validate_interface_tuning(cfg).is_valid

    def test_nonstandard_clock_rate_warns(self):
        cfg = InterfaceTuning(router="R1", interface="Serial0/0/0", clock_rate=12345)
        result = validate_interface_tuning(cfg)
        assert result.is_valid
        assert result.warnings

    def test_interface_not_found(self):
        cfg = InterfaceTuning(router="R1", interface="Serial9/9/9", clock_rate=64000)
        live = [{"name": "R1", "model": "2911",
                 "ports": [{"name": "GigabitEthernet0/0"}, {"name": "GigabitEthernet0/1"}]}]
        result = validate_interface_tuning_against_topology(cfg, live)
        assert not result.is_valid


class TestInterfaceTuningGenerator:
    def test_cli_lines(self):
        cfg = InterfaceTuning(router="R1", interface="Serial0/0/0",
                              clock_rate=64000, bandwidth=64, ospf_cost=10)
        lines = generate_interface_tuning_cli(cfg)
        assert "interface Serial0/0/0" in lines
        assert " clock rate 64000" in lines
        assert " bandwidth 64" in lines
        assert " ip ospf cost 10" in lines


class TestApplyInterfaceTuningUseCase:
    def test_dry_run_payload(self):
        cfg = InterfaceTuning(router="R1", interface="Serial0/0/0", clock_rate=64000)
        result = apply_interface_tuning_uc(cfg, dry_run=True)
        assert result["valid"]
        assert not result["sent"]
        assert "\n" not in result["js_payload"]
        assert 'configureIosDevice("R1"' in result["js_payload"]


class TestOspfAuthentication:
    """Authentication and OSPF timers per interface. 
    
    Without authentication, anyone who hangs on the segment can inject LSAs. 
    It's the reason why these fields exist.
    """

    def _cfg(self, **kw) -> InterfaceTuning:
        base = {"router": "R1", "interface": "GigabitEthernet0/0"}
        base.update(kw)
        return InterfaceTuning(**base)

    def _codes(self, result) -> set:
        return {e.code for e in result.errors}

    def test_md5_emits_key_before_enabling_auth(self):
        """On the contrary, the interface demands auth without having anything to respond with."""
        lines = generate_interface_tuning_cli(
            self._cfg(ospf_md5_key_id=1, ospf_md5_key="s3cr3t"))
        key_at = lines.index(" ip ospf message-digest-key 1 md5 s3cr3t")
        auth_at = lines.index(" ip ospf authentication message-digest")
        assert key_at < auth_at

    def test_plaintext_auth_emits_both_lines(self):
        lines = generate_interface_tuning_cli(self._cfg(ospf_auth_key="key"))
        assert " ip ospf authentication-key key" in lines
        assert " ip ospf authentication" in lines

    def test_md5_wins_over_plaintext(self):
        """Passing the two should not issue two conflicting authentication modes."""
        cfg = self._cfg(ospf_auth_key="flat", ospf_md5_key_id=1, ospf_md5_key="md5")
        lines = generate_interface_tuning_cli(cfg)
        assert " ip ospf authentication message-digest" in lines
        assert " ip ospf authentication-key flat" not in lines
        assert validate_interface_tuning(cfg).warnings

    def test_plaintext_auth_warns_but_is_valid(self):
        result = validate_interface_tuning(self._cfg(ospf_auth_key="key"))
        assert result.is_valid
        assert result.warnings

    def test_md5_key_requires_an_id(self):
        result = validate_interface_tuning(self._cfg(ospf_md5_key="s3cr3t"))
        assert ErrorCode.IFTUNE_INVALID_OSPF_AUTH in self._codes(result)

    @pytest.mark.parametrize("bad_id", [0, 256, -1])
    def test_md5_key_id_range(self, bad_id):
        result = validate_interface_tuning(
            self._cfg(ospf_md5_key="s3cr3t", ospf_md5_key_id=bad_id))
        assert ErrorCode.IFTUNE_INVALID_OSPF_AUTH in self._codes(result)

    @pytest.mark.parametrize("bad", ["with space", "with\njump", "  "])
    def test_key_with_spaces_or_newlines_is_rejected(self, bad):
        """The key travels on a single-line IOS payload."""
        result = validate_interface_tuning(self._cfg(ospf_auth_key=bad))
        assert ErrorCode.IFTUNE_INVALID_OSPF_AUTH in self._codes(result)

    def test_dead_interval_must_exceed_hello(self):
        result = validate_interface_tuning(
            self._cfg(ospf_hello_interval=10, ospf_dead_interval=10))
        assert ErrorCode.IFTUNE_INVALID_OSPF_TIMERS in self._codes(result)

    def test_conventional_timers_pass(self):
        result = validate_interface_tuning(
            self._cfg(ospf_hello_interval=10, ospf_dead_interval=40))
        assert result.is_valid

    def test_dead_interval_alone_is_emitted(self):
        lines = generate_interface_tuning_cli(self._cfg(ospf_dead_interval=40))
        assert " ip ospf dead-interval 40" in lines

    def test_nothing_ospf_emits_nothing_ospf(self):
        lines = generate_interface_tuning_cli(self._cfg(bandwidth=1000))
        assert not any("ospf" in line for line in lines)
