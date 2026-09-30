"""A secret shared between the MCP server and the client within Packet Tracer. 

The HTTP bridge listens in loopback, but that does NOT protect it: a request 
'POST /queue' with 'Content-Type: text/plain' is a "simple" CORS request, as well as 
that any web page opened in the browser could queue JavaScript that PT executed with 
'new Function()'. Binding to 127.0.0.1 does not prevent the request from being send 
— only prevents reading the response, and the injection never needed to read anything. 

What does close it is a secret that the attacking website cannot guess or derive. 
That's why the token is random and persistent, not time-derived or of any public data: 
this repo is public and the attacker runs in the same machine, so any algorithm derivable 
by us is derived by it. 
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import time
from pathlib import Path

_TOKEN_FILE = "bridge_token"
_ENV_VAR = "PT_MCP_BRIDGE_TOKEN"
_MIN_LEN = 32
_VALID = re.compile(r"^[A-Za-z0-9_-]+$")

# Observable state for pt_bridge_status diagnosis: if the token was held 
# # than rotate, any already paired client is obsolete and it must be said.

_rotated = False
_ephemeral = False
_cached: str | None = None


class BridgeTokenError(RuntimeError):
    """A usable token could not be obtained."""

def token_dir() -> Path:
    """Directory of the token, by user and local to the machine. 
    
    On Windows it goes to %LOCALAPPDATA% and not to %APPDATA%: the second is synchronized 
    in Roaming profiles, and a loopback secret doesn't have to travel to a file server. 
    POSIX respects XDG_STATE_HOME. 
    """

    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        return Path(base) / "packet-tracer-mcp" if base else Path.home() / ".packet-tracer-mcp"
    xdg = os.environ.get("XDG_STATE_HOME")
    if xdg:
        return Path(xdg) / "packet-tracer-mcp"
    return Path.home() / ".local" / "state" / "packet-tracer-mcp"


def token_path() -> Path:
    return token_dir() / _TOKEN_FILE


def token_fingerprint(token: str) -> str:
    """Non-investable token footprint, to identify the bridge without filtering it."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


def _is_valid(token: str) -> bool:
    return len(token) >= _MIN_LEN and bool(_VALID.match(token))


def _read_existing(path: Path) -> str | None:

    """Read and validate the token on disk. None if it is useless. 
    
    BOM and spaces tolerated: the file is plain text and someone is going 
    to open it with the Notepad sooner or later. 
    """

    try:
        raw = path.read_text(encoding="utf-8-sig").strip()
    except (OSError, UnicodeDecodeError):
        return None
    return raw if _is_valid(raw) else None


def _write_new(path: Path) -> str | None:
    """Create the token with O_EXCL. None if another process won the race. 
    
    O_EXCL and not "write temporary + os.replace": replace is atomic but wins the last, 
    so two servers booting up at once would be left with tokens DIFFERENT. With O_EXCL 
    the one who loses reads the one who won. 
    """

    candidate = secrets.token_urlsafe(32)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return None
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(candidate)
        fh.flush()
        os.fsync(fh.fileno())
    return candidate


def get_bridge_token(refresh: bool = False) -> str:
    """Returns the bridge token, creating it the first time. 
    
    It never fails hard: if the file is corrupt it is rotated, and if the 
    directory is not writable drops to an ephemeral process token. 
    A Server that won't start is worse than one that warns that you need to re-pair. 
    """

    global _cached, _rotated, _ephemeral

    env = os.environ.get(_ENV_VAR, "").strip()
    if env:
        # Explicit override: tests, CI and multi-client scenarios. 
        #
        # It goes through the SAME gate as the file. It didn't before, so 
        # 'PT_MCP_BRIDGE_TOKEN=x' left a token of one character — guessable, y 
        # with the token guessed all the defense against the attacking website 
        # is dropped; that is, the variable designed for the tests could deactivate 
        # just what this module exists to hold. 
        # 
        # Here we fail strongly, the opposite of with the archive. It is not incoherent: 
        # a corrupt file is an accident and rotating it doesn't lose anything, but a 
        # variable misplaced is an explicit decision of the person who starts the 
        # server. To start would still be to serve with the door open and without 
        # Tell anyone.

        if not _is_valid(env):
            raise BridgeTokenError(
                f"{_ENV_VAR} It doesn't serve as a token: at least they are needed "
                f"{_MIN_LEN} characters of [A-Za-z0-9_-], and they arrived {len(env)}. "
                "Fix it, or remove the variable for the server to use the "
                "disk token."
            )
        return env

    if _cached is not None and not refresh:
        return _cached

    path = token_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError:
        _ephemeral = True
        _cached = secrets.token_urlsafe(32)
        return _cached

    for _ in range(10):
        existing = _read_existing(path)
        if existing:
            _cached = existing
            return _cached

        if path.exists():
            # Exists but is not valid (empty, truncated, hand-edited). 
            # Rotate and Alert: Any paired clients are deprecated.
            try:
                path.unlink()
                _rotated = True
            except OSError:
                break

        created = _write_new(path)
        if created:
            _cached = created
            return _cached
        # We lost the race: the winner has already written, we read again.
        time.sleep(0.05)

    _ephemeral = True
    _cached = secrets.token_urlsafe(32)
    return _cached


def token_was_rotated() -> bool:
    """True if the disk token was invalid and regenerated on this boot."""
    return _rotated


def token_is_ephemeral() -> bool:
    """True if it could not be persisted and the token dies with the process."""
    return _ephemeral


def reset_cache() -> None:
    """Cleans cached state. For tests only."""
    global _cached, _rotated, _ephemeral
    _cached = None
    _rotated = False
    _ephemeral = False
