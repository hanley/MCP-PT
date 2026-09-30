"""HTTP bridge security tests. 

Each test corresponds to a specific vulnerability and fails if the fix is reverse. 
They do not require Packet Tracer.
"""

import hashlib
import json
import urllib.error
import urllib.request

import pytest

from src.packet_tracer_mcp.infrastructure.execution.live_bridge import (
    PTCommandBridge,
    MAX_BODY_BYTES,
)

TOKEN = "test-token-that-is-long-enough-to-be-valid-0123456789"


@pytest.fixture
def bridge():
    b = PTCommandBridge(port=0, token=TOKEN)
    b.start()
    yield b
    b.stop()


def _request(bridge, path, method="GET", body=None, headers=None, host=None):
    """Raw request to bridge. Return (status, body)."""
    url = f"http://127.0.0.1:{bridge.port}{path}"
    data = body.encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "text/plain")
    if host:
        req.add_header("Host", host)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8"), dict(e.headers)


# --- The original vulnerability -------------------------------------------


def test_drive_by_injection_is_rejected(bridge):
    """It simulates the attack exactly: a website posting JS without a token. 
    
    Content-Type text/plain makes it a "simple" CORS request, so the browser 
    sends it without preflight. Before this fix, PT ran it.
    """
    status, _, _ = _request(
        bridge,
        "/queue",
        method="POST",
        body="addDevice('pwned','2911',0,0)",
        headers={"Origin": "https://evil.example"},
    )
    assert status == 401
    # What really matters is not the code but the effect: nothing was glued.
    assert bridge._queue.empty()


def test_queue_requires_token(bridge):
    assert _request(bridge, "/queue", "POST", body="x")[0] == 401
    assert _request(bridge, "/queue?t=wrong", "POST", body="x")[0] == 401
    assert bridge._queue.empty()

    status, _, _ = _request(bridge, f"/queue?t={TOKEN}", "POST", body="ok()")
    assert status == 200
    assert bridge._queue.get_nowait() == "ok()"


def test_token_accepted_via_header(bridge):
    status, _, _ = _request(
        bridge, "/queue", "POST", body="ok()", headers={"X-PT-Token": TOKEN}
    )
    assert status == 200
    assert bridge._queue.get_nowait() == "ok()"


def test_all_endpoints_require_token(bridge):
    for path, method in [
        ("/next", "GET"),
        ("/status", "GET"),
        ("/result", "GET"),
        ("/result", "POST"),
        ("/queue", "POST"),
    ]:
        body = "x" if method == "POST" else None
        status, _, _ = _request(bridge, path, method, body=body)
        assert status == 401, f"{method} {path} did not demand token"


# --- DNS rebinding ---------------------------------------------------------


def test_foreign_host_header_rejected(bridge):
    """A DNS-rebound request arrives with a foreign host, even if it has a token."""
    status, _, _ = _request(
        bridge, f"/queue?t={TOKEN}", "POST", body="x", host="evil.example:1234"
    )
    assert status == 401
    assert bridge._queue.empty()


def test_loopback_hosts_accepted(bridge):
    for host in (f"127.0.0.1:{bridge.port}", f"localhost:{bridge.port}"):
        status, _, _ = _request(
            bridge, f"/queue?t={TOKEN}", "POST", body="x", host=host
        )
        assert status == 200, f"Host {host} should be accepted"


# --- Body Limits -----------------------------------------------------


def test_oversized_body_rejected(bridge):
    """A huge body is rejected WITHOUT reading it. 
    
    The server answers 413 and closes; as it deliberately does not drain the body, 
    The customer can see the connection cut before they can read the answer (same as nginx). 
    What is stated is the property that matters —nothing was glued—, not which of the 
    two endings fell to the client.
    """
    try:
        status, _, _ = _request(
            bridge, f"/queue?t={TOKEN}", "POST", body="A" * (MAX_BODY_BYTES + 1)
        )
        assert status == 413
    except (ConnectionError, OSError):
        pass
    assert bridge._queue.empty()


def test_malformed_content_length_is_400_not_500(bridge):
    """Non-numeric Content-Length gave ValueError → 500 with traceback."""
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", bridge.port, timeout=5)
    conn.putrequest("POST", f"/queue?t={TOKEN}")
    conn.putheader("Content-Type", "text/plain")
    conn.putheader("Content-Length", "not-a-number")
    conn.endheaders()
    resp = conn.getresponse()
    assert resp.status == 400
    conn.close()


# --- Information leakage ---------------------------------------------------


def test_denials_carry_no_cors_header(bridge):
    _, _, headers = _request(bridge, "/queue", "POST", body="x")
    assert "Access-Control-Allow-Origin" not in headers


def test_ping_is_unauthenticated_but_leaks_no_secret(bridge):
    """/ping is left open to detect port conflicts. 
    
    It returns only a non-investable footprint, never the token.
    """
    status, body, _ = _request(bridge, "/ping")
    assert status == 200
    doc = json.loads(body)
    assert doc["service"] == "pt-mcp-bridge"
    assert doc["id"] != TOKEN
    assert TOKEN not in body
    assert doc["id"] == hashlib.sha256(TOKEN.encode()).hexdigest()[:16]


# --- Routing Regression -------------------------------------------------


def test_routes_still_resolve_with_query_string(bridge):
    """Latent bug: the routes compared literal self.path. 
    
    By adding?t=... every request would fall into the 404 and the token would never be validated.
    """
    status, _, _ = _request(bridge, f"/status?t={TOKEN}")
    assert status == 200
    # Queue something first: /next makes long-poll and if not, I would wait for the timeout.
    bridge._queue.put_nowait("noop();")
    status, _, _ = _request(bridge, f"/next?t={TOKEN}")
    assert status == 200


# --- Lot and long-poll ------------------------------------------------------


def test_next_returns_the_whole_queue_in_one_response(bridge):
    """Delivering one at a time every 500 ms made 40 commands take tens of seconds."""
    for i in range(25):
        bridge._queue.put_nowait(f"cmd{i}();")

    status, body, _ = _request(bridge, f"/next?t={TOKEN}")
    assert status == 200
    assert body.split("\n") == [f"cmd{i}();" for i in range(25)]
    assert bridge._queue.empty()


def test_next_long_polls_instead_of_returning_empty(bridge):
    """No queue, /next wait; with queue, answer instantly."""
    import threading
    import time as _t

    t0 = _t.monotonic()
    threading.Timer(0.3, lambda: bridge._queue.put_nowait("late();")).start()
    status, body, _ = _request(bridge, f"/next?t={TOKEN}")
    elapsed = _t.monotonic() - t0

    assert status == 200
    assert body == "late();"
    # Arrived when the command appeared, not on the next fixed tick.
    assert 0.25 < elapsed < 2.0, f"It took {elapsed:.2f}s"


def test_batch_is_capped(bridge):
    from src.packet_tracer_mcp.infrastructure.execution.live_bridge import (
        MAX_BATCH_COMMANDS,
    )

    for i in range(MAX_BATCH_COMMANDS + 10):
        bridge._queue.put_nowait(f"c{i}();")
    _, body, _ = _request(bridge, f"/next?t={TOKEN}")
    assert len(body.split("\n")) == MAX_BATCH_COMMANDS
    assert not bridge._queue.empty()




# --- Diagnosis -----------------------------------------------------------


def test_unauthorized_attempts_are_recorded(bridge):
    """Without this, 'PT is not open' and 'PT rejected' look identical."""
    assert not bridge.saw_recent_unauthorized
    _request(bridge, "/next", "GET")
    assert bridge.saw_recent_unauthorized
    assert bridge._unauth_count == 1
    assert "/next" in bridge._unauth_paths

    status = json.loads(_request(bridge, f"/status?t={TOKEN}")[1])
    assert status["unauth_recent"] is True
    assert status["unauth_paths"] == ["/next"]


# --- Bootstrap -------------------------------------------------------------


def test_importing_the_server_does_not_open_a_socket():
    """Importing the server would open the port even if no one was using the live deploy. 
    
    It runs on a thread because the import is global and caches.
    """
    import subprocess
    import sys as _sys
    import textwrap

    code = textwrap.dedent(
        """
        import sys
        sys.path.insert(0, "src")
        from packet_tracer_mcp.infrastructure.execution import live_bridge
        started = []
        live_bridge.PTCommandBridge.start = lambda self: started.append(1)
        import packet_tracer_mcp.server  # knock out: F401
        print(len(started))
        """
    )
    out = subprocess.run(
        [_sys.executable, "-c", code], capture_output=True, text=True, timeout=60
    )
    assert out.stdout.strip() == "0", out.stderr


def test_report_result_js_carries_token_and_stays_single_line():
    """PT removes the \\n from the code, so the injected JS can't rely on them."""
    from src.packet_tracer_mcp.infrastructure.execution.live_bridge import (
        report_result_js,
    )

    js = report_result_js(54321, TOKEN)
    assert f"/result?t={TOKEN}" in js
    assert "function reportResult(d)" in js
    assert "\n" not in js
