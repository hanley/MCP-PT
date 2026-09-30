"""File transport between the MCP server and the Packet Tracer Script Engine. 

Why it exists, in addition to the HTTP bridge: 
HTTP polling lives in the extension webview (the window). If the user closes, 
the webview dies, and PT stops executing commands — even though the extension 
still installed. The Script Engine, on the other hand, runs WHENEVER PT is open 
(windowless), has setInterval and file access, but does NOT have XMLHttpRequest. 
So the channel with the Script Engine can't be HTTP: it's a File Box.

Coexistence (not replacement): HTTP is still the channel when the window is open; 
this channel takes over when it is closed. The routed (choose one by request, never both) 
lives in the adapter; here is only transportation. 

Security: The mailbox lives under %LOCALAPPDATA% with user ACLs, just like the token. 
A browser web page can't write a local file, so this channel does not have the CORS 
vector that forced HTTP authentication. Trust It is the same one that the threat model 
already assumes: the local user. 

Protocol (one file per request, atomic write tmp+rename): 
    Python ─ writes req_.js (atomic) ─► Script Engine 
    Python ◄─ read/delete res_.txt ─ write res, delete req 
    Script Engine plays alive.txt every tick (heartbeat of life)
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from .bridge_token import token_dir

# Mailbox subdirectory, under the same dir as the token.
_BRIDGE_SUBDIR = "bridge"

# The Script Engine is considered alive if it touched alive.txt does less than this.
HEARTBEAT_FRESH_S = 6.0


def bridge_dir() -> Path:
    return token_dir() / _BRIDGE_SUBDIR


def ensure_bridge_dir() -> Path:
    d = bridge_dir()
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


class FileBridge:
    """Python side of the file box. 
    
    No eigenstate except for a sequence counter; the actual state is the files on disk, 
    so that it survives process restarts. 
    """

    def __init__(self, directory: Path | None = None):
        self.dir = Path(directory) if directory else bridge_dir()
        self._seq = 0

    def _ensure(self) -> None:
        # ALWAYS create self.dir, not the default of the module: if a 
        # own directory (tests, config), creation and writing have 
        # you point to the same place.
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    # -- Script Engine Life ----------------------------------------

    def pt_alive(self) -> bool:
        """True if the Script Engine played its heartbeat recently."""

        alive = self.dir / "alive.txt"
        try:
            age = time.time() - alive.stat().st_mtime
        except OSError:
            return False
        return age < HEARTBEAT_FRESH_S

    # -- envío ----------------------------------------------------------

    def _next_name(self) -> str:
        # Monotonic sequence within the process + pid so as not to collide with each other 
        # concurrent MCP processes that share the same mailbox.
        self._seq += 1
        return f"{os.getpid()}_{self._seq:06d}"

    def _write_atomic(self, path: Path, text: str) -> None:
        # tmp + replace: the Script Engine, which lists the directory, never sees a 
        # half-written file (replace is atomic inside the volume). 
        #
        # EXACT bytes: write in binary, not write_text. On Windows the mode 
        # text translates \n -> \r\n, and an actual CR/LF within a literal string 
        # JS is SyntaxError. The command (e.g. configure IosDevice with \n between 
        # lines of CLI) must arrive at the Script Engine as generated.

        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(text.encode("utf-8"))
        os.replace(tmp, path)

    def send(self, js_code: str) -> bool:
        """Queue a fire-and-forget command. It doesn't expect results."""
        try:
            self._ensure()
            name = self._next_name()
            self._write_atomic(self.dir / f"req_{name}.js", js_code)
            return True
        except OSError:
            return False

    def send_and_wait(self, js_code: str, timeout: float = 12.0) -> str | None:
        """Queue a command and wait for its res_<name>.txt. 
        
        The Script Engine wraps the execution and writes the result; here it is 
        it polls the appearance of the response file and consumes it. 
        """
        try:
            self._ensure()
        except OSError:
            return None
        name = self._next_name()
        res_path = self.dir / f"res_{name}.txt"
        try:
            self._write_atomic(self.dir / f"req_{name}.js", js_code)
        except OSError:
            return None

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if res_path.exists():
                    body = res_path.read_text(encoding="utf-8")
                    res_path.unlink(missing_ok=True)
                    return body
            except OSError:
                pass
            time.sleep(0.1)
        # Timeout: we leave the req in case the SE processes it late, but we clean 
        # The beef did appear between the last check-up and now.
        try:
            res_path.unlink(missing_ok=True)
        except OSError:
            pass
        return None
