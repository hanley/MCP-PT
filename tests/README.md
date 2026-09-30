# tests/

Test suite with pytest. Run **offline**: no test needs Packet Tracer 
(bridge cases raise a `PTCommandBridge` on an ephemeral port or simulate the Script Engine in a thread). 

For the current count and breakdown by file:

```bash
python -m pytest --collect-only -q     # An expiring number is not fixed
```

## Execution

```bash
# All tests (from the root of the repo)
python -m pytest

# A specific file
python -m pytest tests/test_full_build.py -v

# A specific test
python -m pytest tests/test_full_build.py::TestFullBuild::test_basic_2_routers -v
```

## What's Covered 

- **Domain**: validation (IP, VLAN, ACL, hardening, cables, devices), planning, IP assignment, auto-fixer, estimation. 
- **Generators**: PTBuilder JS and IOS CLI, including **adversarial** injection tests (quotation marks, line breaks, `..`) in `test_injection_regressions.py`. 
- **Bridge security**: token, body limits, DNS rebinding, long-poll, and batch (`test_bridge_security.py`); file-bridge protocol (`test_file_bridge.py`). 
- **Integration**: `pt_full_build` end-to-end, diff/health-check, reconcile.