"""Static validation and counter-topology of a VLANPlan."""

from __future__ import annotations

from ..models.vlans import VLANPlan
from ..models.errors import PlanError, ErrorCode, ValidationResult

def validate_vlan_plan(plan: VLANPlan) -> ValidationResult:
    """Validates a VLANPlan without touching PT (ranges, duplicates, consistency)."""
    errors: list[PlanError] = []
    warnings: list[PlanError] = []

    seen: set[int] = set()
    for v in plan.vlans:
        if not (1 <= v.vlan_id <= 4094):
            errors.append(PlanError(
                code=ErrorCode.VLAN_INVALID_ID,
                device=plan.switch or plan.router,
                message=f"VLAN id {v.vlan_id} out of range (1-4094).", 
                suggestion="Use an id between 1 and 4094 (avoid 1002-1005 reserved).",
            ))
        if v.vlan_id in seen:
            errors.append(PlanError(
                code=ErrorCode.VLAN_DUPLICATE_ID,
                device=plan.switch or plan.router,
                message=f"VLAN id {v.vlan_id} duplicate.", 
                suggestion="Each VLAN must be declared only once.",
            ))
        seen.add(v.vlan_id)

    declared = {v.vlan_id for v in plan.vlans}
    for ap in plan.access_ports:
        if declared and ap.vlan_id not in declared:
            warnings.append(PlanError(
                code=ErrorCode.VLAN_INVALID_ID,
                device=ap.switch,
                message=f"Port {ap.port} assigned to VLAN {ap.vlan_id} not declared.", 
                suggestion="Declare the VLAN in 'vlans' or use an existing one.",
            ))

    for t in plan.trunks:
        if not (1 <= t.native_vlan <= 4094):
            errors.append(PlanError(
                code=ErrorCode.VLAN_INVALID_ID,
                device=t.switch,
                message=f"Native VLAN {t.native_vlan} out of range.", 
                suggestion="Use a valid native vlan (default 1).",
            ))

    for s in plan.subinterfaces:
        if declared and s.vlan_id not in declared:
            warnings.append(PlanError(
                code=ErrorCode.VLAN_INVALID_ID,
                device=s.router,
                message=f"Subinterface {s.parent_port}. {s.vlan_id} for undeclared VLAN.", 
                suggestion="The subinterface must correspond to a switch VLAN access.",
            ))

    return ValidationResult(errors=errors, warnings=warnings)


def validate_vlan_against_topology(
    plan: VLANPlan, devices_in_pt: list[dict]
) -> ValidationResult:
    """Validates that the switch/router (and its ports) exist in the active PT topology."""
    errors: list[PlanError] = []
    warnings: list[PlanError] = []

    by_name = {d.get("name"): d for d in devices_in_pt}

    def _ports_of(dev_name: str) -> set[str]:
        from ...infrastructure.catalog.devices import resolve_model
        dev = by_name.get(dev_name)
        if not dev:
            return set()
        model = resolve_model(dev.get("model", ""))
        if model is None:
            return set()
        return {p.full_name for p in model.ports}

    if plan.switch and plan.switch not in by_name:
        errors.append(PlanError(
            code=ErrorCode.VLAN_SWITCH_NOT_FOUND,
            device=plan.switch,
            message=f"Switch '{plan.switch}' does not exist in the active topology.", 
            suggestion="Call pt_query_topology to see the real names.",
        ))
    if plan.router and plan.router not in by_name:
        errors.append(PlanError(
            code=ErrorCode.VLAN_ROUTER_NOT_FOUND,
            device=plan.router,
            message=f"Router '{plan.router}' does not exist in the active topology.", 
            suggestion="Call pt_query_topology to see the real names.",
        ))

    # Validate trunks/access ports against the model (if the switch exists)
    if plan.switch in by_name:
        valid = _ports_of(plan.switch)
        if valid:
            for ap in plan.access_ports:
                if ap.port not in valid:
                    errors.append(PlanError(
                        code=ErrorCode.VLAN_INTERFACE_NOT_FOUND,
                        device=plan.switch,
                        message=f"Port access '{ap.port}' does not exist in {by_name[plan.switch].get('model')}.", 
                        suggestion=f"Valid ports: {', '.join(sorted(valid))}",
                    ))
            for t in plan.trunks:
                if t.port not in valid:
                    errors.append(PlanError(
                        code=ErrorCode.VLAN_TRUNK_PORT_INVALID,
                        device=plan.switch,
                        message=f"Trunk port '{t.port}' does not exist in {by_name[plan.switch].get('model')}.", 
                        suggestion=f"Valid ports: {', '.join(sorted(valid))}",
                    ))

    # Subinterfaces: The parent port must exist on the router
    if plan.router in by_name:
        valid_r = _ports_of(plan.router)
        if valid_r:
            for s in plan.subinterfaces:
                if s.parent_port not in valid_r:
                    errors.append(PlanError(
                        code=ErrorCode.VLAN_INTERFACE_NOT_FOUND,
                        device=plan.router,
                        message=f"Parent port '{s.parent_port}' does not exist in {by_name[plan.router].get('model')}.", 
                        suggestion=f"Valid ports: {', '.join(sorted(valid_r))}",
                    ))

    return ValidationResult(errors=errors, warnings=warnings)
