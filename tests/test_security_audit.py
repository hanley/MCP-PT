"""Security audit tests (pt_audit_security). 

The form of the input dicts is checked against PT 9.0.0.0810: a 2911 
With 'enable secret cisco123', 'service password-encryption', 'username admin secret', 
'username oper password' and 'banner motd' returned enable secret with prefix "$1$", 
admin with "$1$" and oper with hex type-7.
"""

from pathlib import Path

import pytest

from src.packet_tracer_mcp.domain.services.security_audit import (
    CONFIG_REGISTER_BYPASS,
    CONFIG_REGISTER_NORMAL,
    audit_security,
)


def _device(**overrides) -> dict:
    """A hardened device; tests degrade what they want to test."""
    base = {
        "name": "R1",
        "model": "2911",
        "hostname": "R1",
        "enable_secret_set": True,
        "enable_secret_algo": "scrypt",
        "enable_password_set": False,
        "service_password_encryption": True,
        "banner_set": True,
        "users": [{"name": "admin", "algo": "scrypt"}],
        "config_register": CONFIG_REGISTER_NORMAL,
    }
    base.update(overrides)
    return base


def _codes(result: dict) -> set[str]:
    return {f["code"] for f in result["findings"]}


def _by_code(result: dict, code: str) -> dict:
    return next(f for f in result["findings"] if f["code"] == code)


class TestSecurityAuditBaseline:
    def test_hardened_device_is_clean(self):
        result = audit_security([_device()])
        assert result["secure"]
        assert result["findings"] == []
        assert result["devices_audited"] == 1

    def test_empty_topology(self):
        result = audit_security([])
        assert result["devices_audited"] == 0
        assert result["findings"] == []

    def test_bare_device_reports_the_obvious_gaps(self):
        result = audit_security([_device(
            enable_secret_set=False,
            enable_secret_algo=None,
            service_password_encryption=False,
            banner_set=False,
            users=[],
        )])
        assert not result["secure"]
        assert "NO_ENABLE_SECRET" in _codes(result)
        assert "NO_SERVICE_PASSWORD_ENCRYPTION" in _codes(result)
        assert "NO_LOCAL_USERS" in _codes(result)
        assert "NO_BANNER_MOTD" in _codes(result)

    def test_every_finding_carries_a_suggestion(self):
        """The consumer is an LLM who has to be able to self-correct."""
        result = audit_security([_device(
            enable_secret_set=False,
            service_password_encryption=False,
            banner_set=False,
            users=[{"name": "oper", "algo": "type7"}],
            config_register=CONFIG_REGISTER_BYPASS,
        )])
        assert result["findings"]
        for f in result["findings"]:
            assert f["suggestion"].strip()
            assert f["severity"] in ("high", "medium", "low")
            assert f["device"] == "R1"


class TestCredentialAlgorithms:
    def test_reversible_user_credential_is_high(self):
        result = audit_security([_device(users=[{"name": "oper", "algo": "type7"}])])
        finding = _by_code(result, "USER_CREDENTIAL_REVERSIBLE")
        assert finding["severity"] == "high"
        assert "oper" in finding["message"]

    def test_md5_user_credential_is_only_low(self):
        """MD5 is crackable but not reversible: one degree less than type 7."""
        result = audit_security([_device(users=[{"name": "admin", "algo": "md5"}])])
        assert _by_code(result, "USER_CREDENTIAL_WEAK_ALGO")["severity"] == "low"
        assert "USER_CREDENTIAL_REVERSIBLE" not in _codes(result)

    def test_md5_enable_secret_is_medium(self):
        result = audit_security([_device(enable_secret_algo="md5")])
        assert _by_code(result, "ENABLE_SECRET_WEAK_ALGO")["severity"] == "medium"

    def test_reversible_enable_secret_is_high(self):
        result = audit_security([_device(enable_secret_algo="plaintext")])
        assert _by_code(result, "ENABLE_SECRET_REVERSIBLE")["severity"] == "high"

    @pytest.mark.parametrize("algo", ["scrypt", "pbkdf2"])
    def test_modern_hashes_raise_nothing(self, algo):
        result = audit_security([_device(enable_secret_algo=algo, users=[{"name": "a", "algo": algo}])])
        assert result["findings"] == []

    def test_enable_password_flagged_even_with_a_secret(self):
        """They can coexist; the password is stored reversibly."""
        result = audit_security([_device(enable_password_set=True)])
        assert _by_code(result, "ENABLE_PASSWORD_PRESENT")["severity"] == "medium"


class TestConfigRegister:
    def test_bypass_register_is_high(self):
        result = audit_security([_device(config_register=CONFIG_REGISTER_BYPASS)])
        finding = _by_code(result, "CONFIG_REGISTER_BYPASS")
        assert finding["severity"] == "high"
        assert "0x2142" in finding["message"]

    def test_normal_register_is_silent(self):
        result = audit_security([_device(config_register=CONFIG_REGISTER_NORMAL)])
        assert "CONFIG_REGISTER_BYPASS" not in _codes(result)

    def test_unknown_register_is_silent(self):
        """A model that does not expose the record should not generate noise."""
        result = audit_security([_device(config_register=None)])
        assert "CONFIG_REGISTER_BYPASS" not in _codes(result)


class TestAggregation:
    def test_counts_and_ordering(self):
        result = audit_security([
            _device(name="R1", enable_secret_set=False),          # high
            _device(name="R2", service_password_encryption=False),  # medium
            _device(name="R3", banner_set=False),                   # low
        ])
        assert result["devices_audited"] == 3
        assert result["counts"] == {"high": 1, "medium": 1, "low": 1}
        # The serious thing first: the LLM can truncate the list.
        assert [f["severity"] for f in result["findings"]] == ["high", "medium", "low"]

    def test_low_only_still_counts_as_secure(self):
        """'Secure' measures highs and mids; a missing banner does not knock down the audit."""
        result = audit_security([_device(banner_set=False)])
        assert result["secure"]
        assert result["counts"]["low"] == 1


class TestSecurityAuditReader:
    """Guards over the JS reading from the bridge. It's a closure in register_tools, 
    as well which is verified by text, just like TestReconcileWiring in 
    test_live_reconcile.py."""

    def _src(self) -> str:
        return Path("src/packet_tracer_mcp/adapters/mcp/tool_registry.py").read_text(
            encoding="utf-8"
        )

    def _js(self) -> str:
        src = self._src()
        block = src.split("_SECURITY_AUDIT_JS = (", 1)[1]
        return block.split("\n    )", 1)[0]

    def test_reader_never_ships_a_credential(self):
        """The hash cannot cross the bridge: it would end up in the context of the LLM. 
        Only the algorithm tag and Boolean flags are sent. """
        js = self._js()
        assert "enable_secret_algo: __algo(__sec)" in js
        assert "enable_secret_set: !!__sec" in js
        # No key in the payload carries the raw value.
        assert "getEnableSecret()," not in js
        assert "__d.getUserPass(__u) }" not in js
        assert "algo: __algo(__d.getUserPass(__u))" in js

    def test_reader_skips_hosts(self):
        """Call IOS getters on a PC launches and opens a modal that freezes the bridge."""
        assert "typeof __d.getEnableSecret !== 'function'" in self._js()

    def test_user_enumeration_is_guarded(self):
        """getUserEntryAt throws 'out of bound' instead of returning null."""
        js = self._js()
        assert "getUserPassCount()" in js
        assert "catch (__ue) {}" in js

    def test_payload_stays_single_line(self):
        """PT rules out real hops when executing code: the JS goes on one line."""
        src = self._src()
        marker = "_SECURITY_AUDIT_JS = ("
        assert marker in src
        # Each fragment is an adjacent literal with no embedded \n.
        assert "\\n" not in self._js()
