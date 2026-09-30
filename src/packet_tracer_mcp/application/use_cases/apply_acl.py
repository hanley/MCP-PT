"""Use case: Apply ACLs to a router in the active topology. 

Pipeline: 
1. Build optional ACLPlan + ACLBinding from user-friendly args. 
2. Statically validate (ranks, types, IPs/wildcards, unreachable rules). 
3. Verify against active PT topology (router and interface exist). 
4. Generate IOS CLI and set up payload to configureIosDevice. 
5. Returns payload ready to send via bridge (or sends it if apply=True). 

The actual application is delegated to the caller (MCP tool) to maintain 
this HTTP bridge dependency-free module.
"""

from __future__ import annotations
from typing import Callable

from ...domain.models.acls import ACLPlan, ACLEntry, ACLBinding
from ...domain.models.errors import PlanError, ErrorCode, ValidationResult
from ...domain.rules.acl_rules import validate_acl_plan, validate_acl_binding
from ...infrastructure.generator.acl_cli_generator import (
    build_configure_payload,
    build_remove_payload,
    generate_acl_cli,
    generate_acl_binding_cli,
)


def build_acl_plan(
    router: str,
    name_or_number: str,
    acl_type: str,
    entries_dicts: list[dict],
) -> ACLPlan:
    """Build an ACLPlan from dicts (typically from the LLM)."""
    entries = [ACLEntry(**e) for e in entries_dicts]
    return ACLPlan(
        router=router,
        name_or_number=str(name_or_number),
        acl_type=acl_type,
        entries=entries,
    )


def validate_against_topology(
    plan: ACLPlan,
    binding: ACLBinding | None,
    devices_in_pt: list[dict],
) -> ValidationResult:
    """Validate that router (and its interface if there is binding) exist in PT. 
    
    'devices_in_pt' is the raw output of the bridge (queryTopology()): 
    Each dict has at least {name, type, model}. Does not include interfaces 
    explicit, so the interface check is heuristic: 
    If the router model is in the catalog, we validate against your known ports.
    """
    errors: list[PlanError] = []
    warnings: list[PlanError] = []

    device = next((d for d in devices_in_pt if d.get("name") == plan.router), None)
    if device is None:
        errors.append(PlanError(
            code=ErrorCode.ACL_ROUTER_NOT_FOUND,
            device=plan.router,
            message=f"Router '{plan.router}' does not exist in the active PT topology.",
            suggestion="Call pt_query_topology to see available devices.",
        ))
        return ValidationResult(errors=errors, warnings=warnings)

    if binding is not None:
        # Verify interface against catalog (best-effort). 
        # Accepts sub-interfaces (e.g. "GigabitEthernet0/0/1.20") validating that the port 
        # base exists — PT creates sub-interfaces dynamically when configuring dot1Q.
        from ...infrastructure.catalog.devices import resolve_model
        model = resolve_model(device.get("model", ""))
        if model is not None:
            valid_ports = {p.full_name for p in model.ports}
            iface = binding.interface
            base_iface = iface.split(".", 1)[0]
            if iface not in valid_ports and base_iface not in valid_ports:
                errors.append(PlanError(
                    code=ErrorCode.ACL_INTERFACE_NOT_FOUND,
                    device=plan.router,
                    message=f"Interface '{binding.interface}' does not exist in {device.get('model')}.", 
                    suggestion=f"Available ports: {', '.join(sorted(valid_ports))} (. N sub-interfaces are valid if the base port exists)",
                ))

    return ValidationResult(errors=errors, warnings=warnings)


def apply_acl_uc(
    plan: ACLPlan,
    binding: ACLBinding | None = None,
    query_pt_topology: Callable[[], list[dict]] | None = None,
    bridge_send: Callable[[str], bool] | None = None,
    dry_run: bool = False,
) -> dict:
    """Full pipeline: validate + (optionally) apply. 
    
    Args: 
        plan: ACLPlan already built. 
        binding: optional, applies the ACL to an interface. 
        query_pt_topology: callable that returns devices_in_pt (dicts list). 
            If it is None, the verification against PT (static validation only) is omitted. 
        bridge_send: Callable that receives the full JS payload and sends it to PT. 
            If it's None or dry_run=True, nothing is sent. 
        dry_run: If True, it returns the payload but does not send it. 
    
    Returns: 
        dict con keys: valid, errors, warnings, cli_lines, js_payload, sent.
    """
    # 1. Static Plan Validation
    plan_result = validate_acl_plan(plan)
    errors = list(plan_result.errors)
    warnings = list(plan_result.warnings)

    # 2. Binding validation (if applicable)
    if binding is not None:
        binding_result = validate_acl_binding(binding, plan)
        errors.extend(binding_result.errors)
        warnings.extend(binding_result.warnings)

    # 3. Dynamic validation against PT
    if query_pt_topology is not None:
        try:
            devices_in_pt = query_pt_topology()
            topo_result = validate_against_topology(plan, binding, devices_in_pt)
            errors.extend(topo_result.errors)
            warnings.extend(topo_result.warnings)
        except Exception as exc:
            warnings.append(PlanError(
                code=ErrorCode.VALIDATION_ERROR,
                device=plan.router,
                message=f"Could not query active topology: {exc}. Static validation applied.",
            ))

    # 4. Always generate CLI (useful even if there are errors, for inspection)
    cli_lines = generate_acl_cli(plan)
    if binding is not None:
        cli_lines.extend(generate_acl_binding_cli(binding))

    full_payload = build_configure_payload(plan, binding)
    js_call = _build_js_call(plan.router, full_payload)

    sent = False
    if not errors and not dry_run and bridge_send is not None:
        sent = bool(bridge_send(js_call))

    return {
        "valid": len(errors) == 0,
        "errors": [e.to_dict() for e in errors],
        "warnings": [w.to_dict() for w in warnings],
        "cli_lines": cli_lines,
        "js_payload": js_call,
        "sent": sent,
        "dry_run": dry_run,
    }


def remove_acl_uc(
    router: str,
    name_or_number: str,
    binding_interface: str = "",
    direction: str = "in",
    bridge_send: Callable[[str], bool] | None = None,
    dry_run: bool = False,
) -> dict:
    """Constructs and sends commands to delete an applied ACL."""
    payload = build_remove_payload(router, str(name_or_number), binding_interface, direction)
    js_call = _build_js_call(router, payload)

    sent = False
    if not dry_run and bridge_send is not None:
        sent = bool(bridge_send(js_call))

    return {
        "router": router,
        "acl_id": str(name_or_number),
        "js_payload": js_call,
        "sent": sent,
        "dry_run": dry_run,
    }


def _build_js_call(router: str, ios_payload: str) -> str:
    """Wraps the IOS payload in a call configureIosDevice as a single JS line. 
    
    Important: the entire string must be in a line of JS code (without 
    actual hops in the code), but the \\n INSIDE the string do travel 
    because they're literal string escapes—they're not line breaks of source 
    code that executeCode() would strippe.
    """
    safe_router = router.replace("\\", "\\\\").replace('"', '\\"')
    safe_payload = (
        ios_payload
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )
    return f'configureIosDevice("{safe_router}", "{safe_payload}");'
