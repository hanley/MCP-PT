"""The bridge token: provisioning, rotation, and validation. 

This module is the security anchor for ALL HTTP bridge. 'bridge_token.py' 
It says it in its own headline: binding a loopback does not protect anything, 
because a 'POST /queue' with 'Content-Type: text/plain' is a simple and any 
open web page could queue JS that PT runs with 'new Function()'. The only thing 
that closes that hole is this secret.

And I didn't have a single test. 'grep -rln bridge_token tests/' didn't give 
anything back: 'test_bridge_security.py' covers the PROTOCOL (that token, host, sizes), 
but PROVISIONING -- the race with O_EXCL, the rotation before Corrupted file, the 
ephemeral fallback, the '_is_valid' gate -- I was blind. 

Worse: IQ sets 'PT_MCP_BRIDGE_TOKEN' for all jobs and 'get_bridge_token()' returns it in 
its FIRST line, so even if these tests were written the Camino Real would never run there. 
That's why the fixture removes that variable and redirects 'token_dir()' to a TMP: to make 
the file path run for real, also in CI, and without touching the actual token of whoever 
runs the suite.
"""

import os

import pytest

from src.packet_tracer_mcp.infrastructure.execution import bridge_token
from src.packet_tracer_mcp.infrastructure.execution.bridge_token import (
    BridgeTokenError, get_bridge_token, token_path, token_fingerprint,
    token_was_rotated, token_is_ephemeral, reset_cache,
)

VALID_ENV_TOKEN = "ci-token-long-enough-to-be-considered-valid-0123456789"


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Isolate the token: without env var and with the directory in tmp."""
    monkeypatch.delenv("PT_MCP_BRIDGE_TOKEN", raising=False)
    # token_dir() look at these, according to the SW.
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    reset_cache()
    yield tmp_path
    reset_cache()


class TestEnvOverrideIsValidated:
    """The override jumped the gate: 'PT_MCP_BRIDGE_TOKEN=x' gave a token of ONE character. 
    
    The disk file goes through '_is_valid' (>=32 chars, bounded charset); the environment 
    variable didn't happen at all. A short token is guessable, and with The guessed token 
    all the defense against the attacking website goes down.
    """

    def test_a_valid_env_token_is_used(self, isolated, monkeypatch):
        monkeypatch.setenv("PT_MCP_BRIDGE_TOKEN", VALID_ENV_TOKEN)
        reset_cache()
        assert get_bridge_token() == VALID_ENV_TOKEN

    def test_a_short_env_token_is_rejected(self, isolated, monkeypatch):
        monkeypatch.setenv("PT_MCP_BRIDGE_TOKEN", "x")
        reset_cache()
        with pytest.raises(BridgeTokenError):
            get_bridge_token()

    def test_an_env_token_with_bad_characters_is_rejected(self, isolated, monkeypatch):
        # The charset is [A-Za-z0-9_-]: it goes inside a query string without escaping.
        monkeypatch.setenv("PT_MCP_BRIDGE_TOKEN", "a" * 40 + "&evil=1")
        reset_cache()
        with pytest.raises(BridgeTokenError):
            get_bridge_token()

    def test_the_error_says_which_variable_is_wrong(self, isolated, monkeypatch):
        monkeypatch.setenv("PT_MCP_BRIDGE_TOKEN", "corto")
        reset_cache()
        with pytest.raises(BridgeTokenError, match="PT_MCP_BRIDGE_TOKEN"):
            get_bridge_token()

    def test_surrounding_whitespace_is_tolerated(self, isolated, monkeypatch):
        monkeypatch.setenv("PT_MCP_BRIDGE_TOKEN", f"  {VALID_ENV_TOKEN}  ")
        reset_cache()
        assert get_bridge_token() == VALID_ENV_TOKEN

    def test_an_empty_env_var_falls_back_to_the_file(self, isolated, monkeypatch):
        """Empty means "unset", not "invalid token"."""
        monkeypatch.setenv("PT_MCP_BRIDGE_TOKEN", "   ")
        reset_cache()
        token = get_bridge_token()
        assert len(token) >= 32
        assert token_path().exists()


class TestFileProvisioning:
    def test_first_call_creates_a_valid_token_file(self, isolated):
        token = get_bridge_token()
        assert token_path().exists()
        assert token_path().read_text(encoding="utf-8").strip() == token
        assert len(token) >= 32

    def test_the_token_persists_across_processes(self, isolated):
        """Second read without cache: the SAME must exit the disk."""
        first = get_bridge_token()
        reset_cache()
        assert get_bridge_token() == first

    def test_a_bom_and_whitespace_in_the_file_are_tolerated(self, isolated):
        """Someone is going to open the file with the Notepad sooner or later."""
        get_bridge_token()
        good = token_path().read_text(encoding="utf-8").strip()
        token_path().write_text(f"﻿  {good}  \n", encoding="utf-8")
        reset_cache()
        assert get_bridge_token() == good


class TestRotationOnCorruptFile:
    @pytest.mark.parametrize("bad", ["", "   ", "Short", "a" * 20, "with spaces inside!!"])
    def test_an_invalid_file_is_rotated(self, isolated, bad):
        get_bridge_token()
        token_path().write_text(bad, encoding="utf-8")
        reset_cache()

        token = get_bridge_token()
        assert len(token) >= 32
        assert token != bad
        assert token_was_rotated(), "Rotate silently renders the paired client obsolete"

    def test_a_healthy_file_is_not_rotated(self, isolated):
        get_bridge_token()
        reset_cache()
        get_bridge_token()
        assert not token_was_rotated()


class TestEphemeralFallback:
    def test_an_unwritable_directory_falls_back_instead_of_crashing(
        self, isolated, monkeypatch
    ):
        """A server that does not start is worse than one that warns."""
        import pathlib

        def boom(*args, **kwargs):
            raise OSError("read-only directory")

        monkeypatch.setattr(pathlib.Path, "mkdir", boom)
        reset_cache()

        token = get_bridge_token()
        assert len(token) >= 32
        assert token_is_ephemeral()


class TestWriteRace:
    def test_the_loser_of_the_race_does_not_overwrite(self, isolated):
        """O_EXCL and don't replace: with replace, two servers at the same time 
        stayed with DIFFERENT tokens and the customer could only talk to one."""
        first = get_bridge_token()
        # It simulates the second process: the file already exists.
        assert bridge_token._write_new(token_path()) is None
        assert token_path().read_text(encoding="utf-8").strip() == first


class TestFingerprint:
    def test_the_fingerprint_never_contains_the_token(self, isolated):
        token = get_bridge_token()
        fp = token_fingerprint(token)
        assert token not in fp
        assert len(fp) == 16

    def test_the_fingerprint_is_stable(self, isolated):
        token = get_bridge_token()
        assert token_fingerprint(token) == token_fingerprint(token)

    def test_different_tokens_give_different_fingerprints(self, isolated):
        assert token_fingerprint("a" * 40) != token_fingerprint("b" * 40)
