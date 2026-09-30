"""
Topology plan validator. 

Use domain/rules/ rules with typed errors.
"""

from __future__ import annotations
from ..models.plans import TopologyPlan
from ..models.errors import ValidationResult
from ..rules.device_rules import validate_devices
from ..rules.ip_rules import validate_ips, validate_dhcp
from ..rules.cable_rules import validate_links
from ..rules.topology_rules import (
    validate_connectivity, validate_routing, validate_wireless,
)


def validate_plan(plan: TopologyPlan) -> ValidationResult:
    """
    Validate a complete plan. 
    It returns a ValidationResult with typed errors and warnings. 
    It also updates plan.errors and plan.warnings for compatibility.
    """
    result = ValidationResult()

    # Devices
    result.errors.extend(validate_devices(plan))

    # Links and cables
    link_errors, link_warnings = validate_links(plan)
    result.errors.extend(link_errors)
    result.warnings.extend(link_warnings)

    # IPs
    result.errors.extend(validate_ips(plan))

    # DHCP
    dhcp_issues = validate_dhcp(plan)
    # DHCP gateway mismatch is warning, not error critical
    for issue in dhcp_issues:
        if issue.code.value == "DHCP_GATEWAY_MISMATCH":
            result.warnings.append(issue)
        else:
            result.errors.append(issue)

    # Graph shape: islands and incoherent routing. It goes to the end because it assumes 
    # which devices and links have already been validated one by one.
    result.errors.extend(validate_connectivity(plan))
    result.errors.extend(validate_routing(plan))
    # Warning: This is a PT limitation, not a plan error.
    result.warnings.extend(validate_wireless(plan))

    # Sync with plan.errors/warnings for compatibility
    plan.errors = result.error_messages()
    plan.warnings = result.warning_messages()

    return result
