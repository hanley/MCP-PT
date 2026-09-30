"""NetFlow Exporter Validation."""

from __future__ import annotations

import ipaddress

from ..models.errors import ErrorCode, PlanError, ValidationResult
from ..models.netflow import NetflowExporter

# PT implements v5 (fixed format) and v9 (template-based). Any other 
# number is accepted by the setter but does not produce a functional exporter.
VALID_VERSIONS = (5, 9)


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _has_control_chars(value: str) -> bool:
    """The name and interface travel within a JS literal. 
    
    A line break would break the single-line payload that PT demands, so it 
    is rejected here instead of escaping — just like in hardening_rules. 
    """
    return any(ch in value for ch in ("\n", "\r", " ", " "))


def validate_netflow(cfg: NetflowExporter) -> ValidationResult:
    errors: list[PlanError] = []
    warnings: list[PlanError] = []

    if not cfg.name.strip():
        errors.append(PlanError(
            code=ErrorCode.NETFLOW_INVALID_NAME, device=cfg.device,
            message="The exporter needs a name.", 
            suggestion="Pass a short name, for example 'COLLECTOR-1'.",
        ))
    elif _has_control_chars(cfg.name):
        errors.append(PlanError(
            code=ErrorCode.NETFLOW_INVALID_NAME, device=cfg.device,
            message="The exporter's name has line breaks.", 
            suggestion="Use a one-line name.",
        ))

    if cfg.destination_ip and not _is_ipv4(cfg.destination_ip):
        errors.append(PlanError(
            code=ErrorCode.NETFLOW_INVALID_DESTINATION, device=cfg.device,
            message=f"'{cfg.destination_ip}' is not a valid IPv4.", 
            suggestion="Indicate the IP of the collector, for example 192.168.0.50.",
        ))

    if not 1 <= cfg.udp_port <= 65535:
        errors.append(PlanError(
            code=ErrorCode.NETFLOW_INVALID_PORT, device=cfg.device,
            message=f"UDP port {cfg.udp_port} out of range (1-65535).", 
            suggestion="The typical port of a NetFlow collector is 2055.",
        ))

    if cfg.version not in VALID_VERSIONS:
        errors.append(PlanError(
            code=ErrorCode.NETFLOW_INVALID_VERSION, device=cfg.device,
            message=f"NetFlow version {cfg.version} not supported by PT.", 
            suggestion="Use 9 (templates, recommended) or 5 (fixed format).",
        ))

    if _has_control_chars(cfg.source_port):
        errors.append(PlanError(
            code=ErrorCode.NETFLOW_INVALID_NAME, device=cfg.device,
            message="The source interface has line breaks.", 
            suggestion="Use the exact name of the port, e.g. GigabitEthernet0/0.",
        ))

    for monitor in cfg.monitors:
        if _has_control_chars(monitor) or not monitor.strip():
            errors.append(PlanError(
                code=ErrorCode.NETFLOW_INVALID_NAME, device=cfg.device,
                message=f"Invalid monitor name: '{monitor}'.", 
                suggestion="Each monitor is a single-line name, with no gaps.",
            ))

    # Without destination the exporter is created but inert: PT reports it as not 
    # fully configured. It is valid (it can be completed later) but it is worth notifying.
    if not cfg.destination_ip:
        warnings.append(PlanError(
            code=ErrorCode.NETFLOW_INCOMPLETE, device=cfg.device,
            message="Without destination IP the exporter does not send flows.", 
            suggestion="Add destination_ip pointing to the collector.",
        ))

    return ValidationResult(errors=errors, warnings=warnings)


def validate_netflow_against_topology(
    cfg: NetflowExporter, devices_in_pt: list[dict]
) -> ValidationResult:
    errors: list[PlanError] = []

    match = next((d for d in devices_in_pt if d.get("name") == cfg.device), None)
    if match is None:
        errors.append(PlanError(
            code=ErrorCode.NETFLOW_DEVICE_NOT_FOUND, device=cfg.device,
            message=f"Device '{cfg.device}' does not exist in the active topology.", 
            suggestion="Call pt_query_topology to see the real names.",
        ))
        return ValidationResult(errors=errors)

    if cfg.source_port:
        ports = {p.get("name") for p in match.get("ports", [])}
        # If we couldn't read the ports we didn't block: fail open is better 
        # than reject a correct config for an incomplete read.
        if ports and cfg.source_port not in ports:
            errors.append(PlanError(
                code=ErrorCode.NETFLOW_PORT_NOT_FOUND, device=cfg.device,
                message=f"'{cfg.device}' does not have the port '{cfg.source_port}'.", 
                suggestion="Use pt_inspect_ports to see the exact names.",
            ))

    return ValidationResult(errors=errors)
