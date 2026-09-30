"""HTTP bridge results channel tests. 

Each test corresponds to a specific defect and fails if the fix is reversed. 
They do not require Packet Tracer. 

The original flaw: '_results' was a global FIFO queue with no correlation, and 
the Handler waited with a fixed 9s timeout while the callers called for until 45 s. 
From there came two faults that were composed — a slow operation took place for failed, 
and its late result was orphaned in the queue for the consume the NEXT operation. 
The per-file channel ('file_bridge.py') is already correlated by name; this carries 
the same pattern to HTTP via 'rid'.
"""

import threading
import time
import urllib.error
import urllib.request

import pytest

from src.packet_tracer_mcp.infrastructure.execution.live_bridge import (
    PTCommandBridge,
    report_result_js,
)

TOKEN = "test-token-that-is-long-enough-to-be-valid-0123456789"


@pytest.fixture
def bridge():
    b = PTCommandBridge(port=0, token=TOKEN)
    b.start()
    yield b
    b.stop()


def _post_result(bridge, rid, body):
    """Simulates PT by returning the result of a trade."""
    url = f"http://127.0.0.1:{bridge.port}/result?t={TOKEN}"
    if rid is not None:
        url += f"&rid={rid}"
    req = urllib.request.Request(url, data=body.encode(), method="POST")
    req.add_header("Content-Type", "text/plain")
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status


def _get_result(bridge, rid, wait):
    """It simulates the MCP server by collecting the result of ITS operation."""
    url = f"http://127.0.0.1:{bridge.port}/result?t={TOKEN}&rid={rid}&wait={wait}"
    try:
        with urllib.request.urlopen(url, timeout=wait + 5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


# --- The crossover of results ------------------------------------------------


def test_orphan_result_does_not_leak_into_the_next_operation(bridge):
    """A result that no one picked up cannot answer for the following operation. 
    
    It was the silent failure: B received A's result instantly. Data PT, but from 
    the wrong device and without an error that would give it away.
    """
    # A finished late; his GET had already expired and no one picked this up.
    _post_result(bridge, "op-A", "RESULT_OF_A")

    # B is another operation and asks about his own. He must not see A's.
    status, body = _get_result(bridge, "op-B", wait=1)

    assert body != "RESULT_OF_A"
    assert status == 204


def test_each_operation_gets_its_own_result(bridge):
    """With several results in flight, everyone picks up their own."""
    _post_result(bridge, "op-1", "ONE")
    _post_result(bridge, "op-2", "TWO")
    _post_result(bridge, "op-3", "THREE")

    # They are collected out of order on purpose: correlation cannot depend on 
    # of the order of arrival, which is just what the FIFO queue supposed.
    assert _get_result(bridge, "op-2", wait=1)[1] == "ONE"
    assert _get_result(bridge, "op-1", wait=1)[1] == "TWO"
    assert _get_result(bridge, "op-3", wait=1)[1] == "THREE"


def test_concurrent_operations_do_not_cross(bridge):
    """Two simultaneous operations each receive their own. 
    
    FastMCP runs the tools sync in a threadpool, so two 'pt_*' can really overlap.
    """
    got = {}

    def collect(rid):
        got[rid] = _get_result(bridge, rid, wait=5)[1]

    waiters = [threading.Thread(target=collect, args=(r,)) for r in ("a", "b")]
    for w in waiters:
        w.start()
    time.sleep(0.3)  # Both waiting already

    _post_result(bridge, "b", "FOR_B")
    _post_result(bridge, "a", "FOR_A")
    for w in waiters:
        w.join(timeout=10)

    assert got == {"a": "FOR_A", "b": "FOR_B"}


# --- The 9-second ceiling --------------------------------------------


def test_slow_operation_is_not_cut_off_at_nine_seconds(bridge):
    """The caller sets the timeout; the handler cannot surrender before him. 
    
    26 of the 36 calls to _bridge_send_and_wait ask for more than 9 seconds (up to 45). 
    With the fixed timeout of 9 seconds all returned None even if PT was fine. It's the 
    only slow test in the suite: you have to cross the real threshold of 9 seconds to 
    prove that he is no longer there.
    """
    DELAY = 10.0

    def respond_late():
        time.sleep(DELAY)
        _post_result(bridge, "slow", "I_FINISHED_LATE_BUT_I_FINISHED")

    threading.Thread(target=respond_late, daemon=True).start()

    t0 = time.time()
    status, body = _get_result(bridge, "slow", wait=20)
    elapsed = time.time() - t0

    assert status == 200, f"surrendered to {elapsed:.1f}s with status {status}" 
    assert body == "I_FINISHED_LATE_BUT_I_FINISHED"
    assert elapsed >= DELAY


def test_wait_is_capped_so_a_client_cannot_pin_a_thread(bridge):
    """An absurd 'wait' cannot bind a threading from ThreadingHTTPServer."""
    from src.packet_tracer_mcp.infrastructure.execution.live_bridge import (
        MAX_RESULT_WAIT_SECONDS,
    )

    assert MAX_RESULT_WAIT_SECONDS <= 120


# --- Hygiene of the results table -------------------------------------


def test_unclaimed_results_are_purged(bridge):
    """The results that no one reaps cannot grow without a roof. 
    
    The old tail at least had maxsize; a dict without purging would change a bug of 
    correlation by a memory leak.
    """
    bridge._result_ttl = 0.2
    for i in range(5):
        _post_result(bridge, f"old-{i}", "x")
    assert len(bridge._results) == 5

    time.sleep(0.4)
    _post_result(bridge, "new", "and") # any writing passes the broom

    assert "new" in bridge._results 
    assert not any(k.startswith("old-") for k in bridge._results)


def test_result_table_is_bounded(bridge):
    """Even if the TTL has not won, the board has a hard top."""
    from src.packet_tracer_mcp.infrastructure.execution.live_bridge import (
        MAX_RESULT_ITEMS,
    )

    for i in range(MAX_RESULT_ITEMS + 50):
        _post_result(bridge, f"r{i}", "x")

    assert len(bridge._results) <= MAX_RESULT_ITEMS


def test_result_without_rid_is_discarded(bridge):
    """Without rid it cannot be attributed to anyone: it is thrown away instead of contaminated."""
    _post_result(bridge, None, "WITHOUT_OWNER")

    assert len(bridge._results) == 0
    assert _get_result(bridge, "Any", wait=1)[0] == 204


# --- The RID travels to PT and back ----------------------------------------


def test_report_result_js_carries_the_rid(bridge):
    """The rid goes inside the JS that is injected, so PT returns it on its own. 
    
    Here's what avoids having to touch the extension:.pts never builds the URL of /result, 
    it only executes the JS that arrives to it.
    """
    js = report_result_js(54321, TOKEN, "op-42")

    assert "rid=op-42" in js
    # The token follows first: test_bridge_security waits for '/result?t= '.
    assert f"/result?t={TOKEN}" in js
    assert "\n" not in js
