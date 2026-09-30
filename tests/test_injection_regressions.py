"""Adversarial tests: a case for vulnerability, fails if the fix is rolled back. 

Before this the suite was entirely happy-path: no test put a quotation mark, a line 
break or a '..' in any field.
"""

import json

import pytest

from src.packet_tracer_mcp.shared.utils import (
    js_escape,
    safe_name_component,
    resolve_within,
    interpret_ping,
)
from src.packet_tracer_mcp.domain.models.plans import TopologyPlan, DevicePlan
from src.packet_tracer_mcp.infrastructure.generator.ptbuilder_generator import (
    generate_ptbuilder_script,
)
from src.packet_tracer_mcp.infrastructure.execution.manual_executor import ManualExecutor
from src.packet_tracer_mcp.application.use_cases.apply_hardening import (
    build_hardening_config,
    apply_hardening_uc,
)

HOSTILE_NAMES = [
    "R'1",
    'R"1',
    "R\\1",
    "R\n1",
    "R\r1",
    "R\u20281",
    "'); alert(1); ('",
    '"); alert(1); ("',
]


# --- Escapado JS -----------------------------------------------------------


@pytest.mark.parametrize("name", HOSTILE_NAMES)
def test_js_escape_leaves_no_literal_terminator(name):
    """Neither unescaped quotation marks nor line endings, which JS does not allow in literals."""
    out = js_escape(name)
    # Any quotation marks in the result must be preceded by a backslash.
    for i, ch in enumerate(out):
        if ch in "\"'":
            assert i > 0 and out[i - 1] == "\\", f"quotation marks without escaping in {out!r}"
    for terminator in ("\n", "\r", "\u2028", "\u2029"):
        assert terminator not in out


@pytest.mark.parametrize("name", HOSTILE_NAMES)
def test_generated_ptbuilder_script_keeps_names_as_data(name):
    """A hostile name should come out as a string, not as a code. 
    
    Previously, lwAddDevice() was constructed with a crude f-string: a double 
    quotation mark closed the literal and the rest was executed in the PT Script Engine.
    """
    plan = TopologyPlan(
        name="t",
        devices=[DevicePlan(name=name, model="2911", category="router")],
        links=[],
    )
    line = generate_ptbuilder_script(plan)
    assert line.startswith("lwAddDevice(")

    # The first argument has to be a JSON literal that round-trippees the 
    # Original name: If round-trippea, it didn't escape the literal.
    arg = line[len("lwAddDevice("):].split(", ", 1)[0]
    assert json.loads(arg) == name


# --- Rutas -----------------------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    ["../../evil", "..\\..\\evil", "..", ".", "/etc/passwd", "C:/Windows/Temp"],
)
def test_project_names_cannot_escape_the_base(hostile):
    assert "/" not in safe_name_component(hostile)
    assert "\\" not in safe_name_component(hostile)
    assert safe_name_component(hostile) not in ("..", ".")


def test_resolve_within_rejects_escapes(tmp_path):
    with pytest.raises(ValueError):
        resolve_within(tmp_path, "..", "evil")
    inside = resolve_within(tmp_path, "demo")
    assert inside.parent == tmp_path.resolve()


def test_export_writes_nothing_outside_the_output_dir(tmp_path):
    """The property that matters: nothing was created outside the base."""
    outside = tmp_path / "outside"
    outside.mkdir()
    base = tmp_path / "base"

    plan = TopologyPlan(
        name="t",
        devices=[DevicePlan(name="R1", model="2911", category="router")],
        links=[],
    )
    ManualExecutor(output_dir=base).execute(plan, project_name="../outside/pwned")

    assert list(outside.iterdir()) == [], "was written outside the base directory"
    assert base.exists()


def test_device_names_cannot_escape_via_config_filename(tmp_path):
    """The device name was crudely interpolated into '{name}_config.txt'."""
    from pathlib import Path

    base = (tmp_path / "base").resolve()
    plan = TopologyPlan(
        name="t",
        devices=[DevicePlan(name="../../pwned", model="2911", category="router")],
        links=[],
    )
    result = ManualExecutor(output_dir=base).execute(plan, project_name="p")

    for path in result["files"].values():
        assert Path(path).resolve().is_relative_to(base), f"{path} was left out of {base}"


# --- Inyección de comandos IOS --------------------------------------------


def test_banner_delimiter_is_rejected():
    """'#' delimits 'motd banner'; in the text it cuts the banner and IOS executes the rest."""
    cfg = build_hardening_config(device="R1", banner_motd="Hello # enable secret pwned")
    result = apply_hardening_uc(cfg, bridge_send=lambda js: True)
    assert not result["valid"]
    assert not result["sent"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("hostname", "R1\nusername hacker privilege 15 secret x"),
        ("enable_secret", "s3cr3t\nno service password-encryption"),
        ("banner_motd", "hello\nlogging host 10.0.0.1"),
    ],
)
def test_newlines_in_hardening_fields_are_rejected(field, value):
    """Each \\n became an extra IOS command on the device."""
    cfg = build_hardening_config(device="R1", **{field: value})
    result = apply_hardening_uc(cfg, bridge_send=lambda js: True)
    assert not result["valid"], f"{field} accepted a line break"
    assert not result["sent"]


@pytest.mark.parametrize(
    "stat,expected",
    [
        # Host format (PC/Server), verified against live PT 9.0
        ("Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),", True),
        ("Packets: Sent = 4, Received = 0, Lost = 4 (100% loss),", False),
        ("Packets: Sent = 4, Received = 2, Lost = 2 (50% loss),", True),
        # IOS format (router/switch)
        ("Success rate is 100 percent (5/5)", True),
        ("Success rate is 0 percent (0/5)", False),
        ("Success rate is 80 percent (4/5)", True),
        # Trash / Empty
        ("", False),
        ("no stats here", False),
    ],
)
def test_interpret_ping(stat, expected):
    """The connectivity parser, with the two real PT formats."""
    assert interpret_ping(stat) is expected


def test_legitimate_hardening_still_works():
    """The counterweight: fixes cannot break the normal case."""
    cfg = build_hardening_config(
        device="R1", hostname="R1", banner_motd="Restricted access",
        enable_secret="cisco123",
    )
    sent = []
    result = apply_hardening_uc(cfg, bridge_send=lambda js: sent.append(js) or True)
    assert result["valid"]
    assert result["sent"]
    assert len(sent) == 1
