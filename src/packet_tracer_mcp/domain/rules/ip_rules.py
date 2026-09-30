"""IP validation rules."""

from __future__ import annotations
import ipaddress
from ..models.plans import TopologyPlan
from ..models.errors import PlanError, ErrorCode


def validate_ips(plan: TopologyPlan) -> list[PlanError]:
    """Check for IP conflicts."""
    errors: list[PlanError] = []
    all_ips: dict[str, str] = {}

    for dev in plan.devices:
        for iface, ip_cidr in dev.interfaces.items():
            try:
                ip_obj = ipaddress.IPv4Interface(ip_cidr)
                ip_str = str(ip_obj.ip)
            except ValueError:
                errors.append(PlanError(
                    code=ErrorCode.INVALID_IP_ADDRESS,
                    device=dev.name,
                    message=f"Invalid IP '{ip_cidr}' in interface {iface}.", 
                    suggestion="Verify IP format. Example: 192.168.1.1/24",
                ))
                continue

            key = f"{dev.name}:{iface}"
            if ip_str in all_ips:
                errors.append(PlanError(
                    code=ErrorCode.IP_CONFLICT,
                    device=dev.name,
                    message=f"IP {ip_str} duplicated between {all_ips[ip_str]} and {key}.", 
                    suggestion="Reassign one of the conflicting IPs.",
                ))
            else:
                all_ips[ip_str] = key

    return errors


def validate_dhcp(plan: TopologyPlan) -> list[PlanError]:
    """Check DHCP pools."""
    errors: list[PlanError] = []

    for pool in plan.dhcp_pools:
        router = plan.device_by_name(pool.router)
        if router is None:
            errors.append(PlanError(
                code=ErrorCode.DHCP_ROUTER_NOT_FOUND,
                device=pool.router,
                message=f"DHCP pool '{pool.pool_name}' non-existent router reference.", 
                suggestion="Verify router name.",
            ))
            continue

        gw_found = any(
            str(ipaddress.IPv4Interface(ip).ip) == pool.gateway
            for ip in router.interfaces.values()
            if _is_valid_ip(ip)
        )
        if not gw_found:
            errors.append(PlanError(
                code=ErrorCode.DHCP_GATEWAY_MISMATCH,
                device=pool.router,
                message=f"Gateway {pool.gateway} of pool '{pool.pool_name}' not mapped to {pool.router} interface.", 
                suggestion="Assign the gateway to a router interface.",
            ))

    return errors


def _is_valid_ip(ip_cidr: str) -> bool:
    try:
        ipaddress.IPv4Interface(ip_cidr)
        return True
    except ValueError:
        return False
