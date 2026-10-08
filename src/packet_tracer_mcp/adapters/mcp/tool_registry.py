"""
MCP Tools Registration. 

It defines all the tools that the LLM can invoke.
"""

from __future__ import annotations
import json
import time
import urllib.request
import urllib.parse
from pathlib import Path
from mcp.server.fastmcp import FastMCP

from ...domain.models.plans import TopologyPlan
from ...domain.models.requests import TopologyRequest
from ...domain.models.acls import ACLBinding
from ...domain.services.orchestrator import plan_from_request
from ...domain.services.validator import validate_plan
from ...domain.services.auto_fixer import fix_plan
from ...domain.services.explainer import explain_plan
from ...domain.services.estimator import estimate_from_request, estimate_from_plan
from ...application.use_cases.apply_acl import (
    build_acl_plan,
    apply_acl_uc,
    remove_acl_uc,
)
from ...application.use_cases.apply_nat import (
    build_nat_config,
    apply_nat_uc,
    remove_nat_uc,
)
from ...application.use_cases.apply_vlan import build_vlan_plan, apply_vlan_uc
from ...application.use_cases.apply_switch_security import (
    apply_stp_uc,
    apply_port_security_uc,
)
from ...domain.models.switch_security import STPConfig, PortSecurityConfig
from ...application.use_cases.apply_hardening import (
    build_hardening_config,
    apply_hardening_uc,
)
from ...application.use_cases.apply_interface_tuning import apply_interface_tuning_uc
from ...domain.models.interface_tuning import InterfaceTuning
from ...domain.services.topology_diff import diff as topology_diff, health_check
from ...domain.services.security_audit import audit_security
from ...domain.services.port_inspect import nat_mode_label, summarize_ports
from ...domain.services.packet_trace import summarize_trace, traffic_type_label
from ...domain.models.netflow import NetflowExporter
from ...domain.models.errors import ErrorCode, PlanError
from ...domain.rules.netflow_rules import (
    validate_netflow, validate_netflow_against_topology,
)
from ...infrastructure.generator.ptbuilder_generator import (
    generate_ptbuilder_script,
    generate_full_script,
    generate_executable_script,
)
from ...infrastructure.generator.cli_config_generator import (
    generate_all_configs,
    generate_pc_config,
)
from ...infrastructure.generator.acl_cli_generator import generate_acl_cli
from ...infrastructure.execution.manual_executor import ManualExecutor
from ...infrastructure.execution.deploy_executor import DeployExecutor
from ...infrastructure.execution.live_bridge import (
    PTCommandBridge, DEFAULT_PORT, report_result_js, next_rid,
)
from ...infrastructure.execution.bridge_token import (
    get_bridge_token, token_fingerprint, token_was_rotated, token_is_ephemeral,
)
from ...infrastructure.execution.file_bridge import FileBridge
from ...infrastructure.persistence.project_repository import ProjectRepository
from ...infrastructure.catalog.devices import ALL_MODELS, resolve_model, category_of_model
from ...infrastructure.catalog.cables import CABLE_TYPES, CABLE_RULES, infer_cable
from ...infrastructure.catalog.aliases import MODEL_ALIASES
from ...infrastructure.catalog.templates import list_templates
from ...infrastructure.catalog.modules import ALL_MODULES, resolve_module, ports_for_slot
from ...shared.enums import RoutingProtocol, TopologyTemplate
from ...shared.utils import (
    js_escape, safe_name_component, resolve_within, interpret_ping as _interpret_ping,
    classify_ping as _classify_ping,
)
from ...domain.services.canvas import (
    CanvasImageError, decode_pt_image, normalize_format, validate_color,
)

# Workspace options: MCP flag → (PT method, is it reversed?). 
# 
# PT exposes two of these in NEGATIVE ('setDisableAutoCabling', 
# 'setHideDevLabel') while the MCP flag says "activate/display". If the
# investment is lost, the tool does exactly the opposite of what it is 
# asks, and in silence.
WORKSPACE_SETTERS: dict[str, tuple[str, bool]] = {
    "auto_cabling":            ("setDisableAutoCabling", True),
    "show_device_labels":      ("setHideDevLabel", True),
    "external_network_access": ("setEnableExternalNetworkAccess", False),
    "show_port_labels":        ("setIsPortShown", False),
    "show_link_lights":        ("setIsLinkLightShown", False),
}

# Setters that PT declares with a second MANDATORY argument. With only one 
# answers 'Invalid arguments for IPC call "..."'. The value of the second does not 
# changes the result (tested with true and false against PT 9.0.1), but has 
# than to be.
WORKSPACE_EXTRA_ARG: dict[str, str] = {
    "setHideDevLabel": "true",
}

#--- Device Console (Ping Actual) -------------------------------------- 
# 
# 'getCommandPrompt()' ONLY exists on hosts (PC/Server/Laptop). Against a router 
# burst with 'TypeError: Property 'getCommandPrompt' of object is not a 
# function', so the ping from IOS never worked despite being documented. 
# Verified against PT 9.0.1: routers expose 'getCommandLine()' and PCs 
# expose the BOTH, so getCommandLine works for both worlds. 
# 
# The console must also be primed. A router newly deployed by the MCP will never 
# was played by console, so it's still standing on "Would you like to enter the 
# initial configuration dialog? [yes/no]:". There the 'ping' is consumed as 
# Yes/No response and never executes.
_CONSOLE_PRIME_JS = (
    "var p=String(cl.getPrompt()||'');"
    "if(p.indexOf('[yes/no]')>=0){cl.enterCommand('no');}"
    "cl.enterCommand('');"
)

# Statistics block markers, in the two PT formats.
_PING_STAT_MARKERS = "/Packets: Sent|Success rate/g"


def console_ping_arm_js(device: str, target: str) -> str:
    """JS that leaves the console usable, counts the previous blocks and triggers the ping. 
    
    Returns 'BASE: ' with how many stat blocks there were already – the console 
    It preserves history, so markers are counted instead of relying on the length.
    """
    dev = json.dumps(device)
    cmd = json.dumps("ping " + target.strip())
    return (
        f"var cl=ipc.network().getDevice({dev}).getCommandLine();"
        "if(!cl){reportResult('ERR:Device without console');}"
        "else{"
        f"{_CONSOLE_PRIME_JS}"
        "var o=String(cl.getOutput());"
        f"var m=o.match({_PING_STAT_MARKERS});"
        "var base=m?m.length:0;"
        f"cl.enterCommand({cmd});"
        "reportResult('BASE:'+base);}"
    )


def console_ping_poll_js(device: str, base: int) -> str:
    """JS polling the console until it sees a NEW stat block."""
    dev = json.dumps(device)
    return (
        f"var cl=ipc.network().getDevice({dev}).getCommandLine();"
        "if(!cl){reportResult('ERR:Device without console');}"
        "else{"
        "var o=String(cl.getOutput());"
        f"var m=o.match({_PING_STAT_MARKERS});"
        "var cur=m?m.length:0;"
        f"if(cur>{int(base)}){{"
        # raw: \d and \n belong to JS regex, they are not Python escapes.
        r"var stat=o.match(/Packets: Sent = \d+, Received = (\d+), Lost = (\d+)[^\n]*"
        r"|Success rate is (\d+) percent \((\d+)\/(\d+)\)/g);"
        "reportResult('DONE:'+(stat?stat[stat.length-1]:'without stats'));"
        "}else{reportResult('WAIT');}}"
    )


def workspace_setter_call(flag: str, value: int) -> tuple[str, str]:
    """(PT method, JS arguments) to leave 'flag' in 'value' (0 or 1)."""
    method, inverted = WORKSPACE_SETTERS[flag]
    on = "true" if (value == 1) != inverted else "false"
    extra = WORKSPACE_EXTRA_ARG.get(method)
    return method, (f"{on}, {extra}" if extra else on)


def register_tools(mcp: FastMCP) -> None:
    """Register all tools on the MCP server."""

    # ------------------------------------------------------------------
    # CONSULTATION
    # ------------------------------------------------------------------
    @mcp.tool()
    def pt_list_devices() -> str:
        """
        Lists all devices available in Packet Tracer with their ports. 
        Use this to find out which models, ports, and cables you can use.
        """
        lines = []
        for name, model in ALL_MODELS.items():
            ports = ", ".join(p.full_name for p in model.ports)
            lines.append(f"**{model.display_name}** (type: `{name}`, category: {model.category})")
            lines.append(f"  Ports: {ports}")
            lines.append("")
        lines.append("**Available aliases:**")
        for alias, target in MODEL_ALIASES.items():
            lines.append(f"  {alias} → {target}")
        return "\n".join(lines)

    @mcp.tool()
    def pt_list_templates() -> str:
        """
        List all available topology templates with their descriptions.
        """
        templates = list_templates()
        lines = []
        for t in templates:
            lines.append(f"**{t.name}** (key: `{t.key.value}`)")
            lines.append(f"  {t.description}")
            lines.append(f"  Routers: {t.min_routers}-{t.max_routers} (default: {t.default_routers})")
            lines.append(f"  PCs/LAN: {t.default_pcs_per_lan}  |  WAN: {'yes' if t.requires_wan else 'no'}")
            lines.append(f"  Routing: {t.default_routing.value}")
            lines.append(f"  Tags: {', '.join(t.tags)}")
            lines.append("")
        return "\n".join(lines)

    @mcp.tool()
    def pt_get_device_details(model_name: str) -> str:
        """
        Displays details of a specific device model. 
        
        Accepts both the exact model name (e.g. '2911', '2960-24TT') 
        as a catalog alias (e.g.: 'router', 'switch', 'firewall'). 
        
        Parameters: 
        - model_name: model name or alias
        """
        model = resolve_model(model_name)
        if not model:
            return f"Model '{model_name}' not found. Use pt_list_devices to view models."
        info = {
            "display_name": model.display_name,
            "category": model.category,
            "ports": [
                {"name": p.full_name, "speed": p.speed.value if p.speed else "N/A"}
                for p in model.ports
            ],
            "total_ports": len(model.ports),
        }
        return json.dumps(info, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # DRY-run
    # ------------------------------------------------------------------
    @mcp.tool()
    def pt_estimate_plan(
        routers: int = 2,
        pcs_per_lan: int = 3,
        laptops_per_lan: int = 0,
        switches_per_router: int = 1,
        servers: int = 0,
        access_points: int = 0,
        has_wan: bool = False,
        dhcp: bool = True,
        routing: str = "static",
    ) -> str:
        """
        Quick estimation (dry-run) without generating a complete plan. 
        Shows how many devices, links, and subnets will be created. 
        
        Parameters: 
        - routers: Number of routers (1-20) 
        - pcs_per_lan: LAN PCs 
        - laptops_per_lan: LAN Laptops (Laptop-PT) 
        - switches_per_router: Switches per router 
        - servers: Servers 
        - access_points: Access Points (AccessPoint-PT) 
        - has_wan: Include WAN 
        - dhcp: Configure DHCP 
        - routing: static, ospf, eigrp, rip, none
        """
        request = TopologyRequest(
            routers=routers,
            pcs_per_lan=pcs_per_lan,
            laptops_per_lan=laptops_per_lan,
            switches_per_router=switches_per_router,
            servers=servers,
            access_points=access_points,
            has_wan=has_wan,
            dhcp=dhcp,
            routing=RoutingProtocol(routing),
        )
        est = estimate_from_request(request)
        return json.dumps(est, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # PLANNING
    # ------------------------------------------------------------------
    @mcp.tool()
    def pt_plan_topology(
        routers: int = 2,
        pcs_per_lan: int = 3,
        laptops_per_lan: int = 0,
        switches_per_router: int = 1,
        servers: int = 0,
        access_points: int = 0,
        has_wan: bool = False,
        dhcp: bool = True,
        routing: str = "static",
        router_model: str = "2911",
        switch_model: str = "2960-24TT",
        template: str = "multi_lan",
        floating_routes: bool = False,
        ospf_process_id: int = 1,
        eigrp_as: int = 100,
        vlans: int = 0,
        dual_stack: bool = False,
        ipv6_base: str = "2001:db8::/32",
        wireless_laptops: bool = False,
    ) -> str:
        """
        Generates a complete network topology plan for Packet Tracer. 
        
        Parameters: 
        - routers: Number of routers (1-20) 
        - pcs_per_lan: PCs per LAN 
        - laptops_per_lan: Laptops per LAN (Laptop-PT) 
        - switches_per_router: Switches per router (0-4) 
        - servers: Number of servers 
        - access_points: Number of Access Points (AccessPoint-PT), one per LAN 
        - has_wan: Include WAN (Cloud) connection 
        - dhcp: Configure DHCP automatically 
        - routing: Routing protocol (static, ospf, eigrp, rip, none) 
        - router_model: Router model (1941, 2901, 2911, ISR4321) 
        - switch_model: Switch model (2960-24TT, 3560-24PS) 
        - template: Template (single_lan, multi_lan, multi_lan_wan, star, hub_spoke, 
        branch_office, router_on_a_stick, three_router_triangle, custom)
        - floating_routes: If True with routing=static, add backup paths with AD=254 
        by alternate paths (requires topology with multiple paths) 
        - ospf_process_id: OSPF process ID (1-65535, default 1) 
        - eigrp_as: AS number for EIGRP (1-65535, default 100) 
        - VLANs: Only template router_on_a_stick. 
        No. of VLANs to be distributed among the PCs (0 = default 2). 
        - dual_stack: If True, add IPv6 addressing (routers per CLI, hosts per SLAAC). 
        - ipv6_base: Base IPv6 prefix for dual-stack (default "2001:db8::/32"). 
        - wireless_laptops: If True, laptops connect via WiFi (wireless NIC + AP (LAN) 
        instead of cable. 
        
        Returns the full JSON plan.              
        """
        request = TopologyRequest(
            template=TopologyTemplate(template),
            routers=routers,
            pcs_per_lan=pcs_per_lan,
            laptops_per_lan=laptops_per_lan,
            switches_per_router=switches_per_router,
            servers=servers,
            access_points=access_points,
            has_wan=has_wan,
            dhcp=dhcp,
            routing=RoutingProtocol(routing),
            router_model=router_model,
            switch_model=switch_model,
            floating_routes=floating_routes,
            ospf_process_id=ospf_process_id,
            eigrp_as=eigrp_as,
            vlans=vlans,
            dual_stack=dual_stack,
            ipv6_base=ipv6_base,
            wireless_laptops=wireless_laptops,
        )
        plan, validation = plan_from_request(request)
        return plan.model_dump_json(indent=2)

    # ------------------------------------------------------------------
    # VALIDATION
    # ------------------------------------------------------------------
    @mcp.tool()
    def pt_validate_plan(plan_json: str) -> str:
        """
        Validates a topology plan. Returns typified errors and warnings. 
        
        Parameters: 
        - plan_json: Plan JSON (pt_plan_topology output)
        """
        try:
            raw = json.loads(plan_json)
        except json.JSONDecodeError as exc:
            return json.dumps({
                "valid": False,
                "error_count": 1,
                "warning_count": 0,
                "errors": [{"code": "INVALID_JSON", "message": f"Invalid JSON: {exc.msg}"}],
                "warnings": [],
                "summary": "❌ Invalid JSON — Failed to Parsify Plan.",
            }, indent=2, ensure_ascii=False)

        if not isinstance(raw, dict) or "devices" not in raw or not raw.get("devices"):
            return json.dumps({
                "valid": False,
                "error_count": 1,
                "warning_count": 0,
                "errors": [{
                    "code": "EMPTY_PLAN",
                    "message": "The JSON does not contain a valid plan ('devices' are missing or empty). Generate the plan with pt_plan_topology first.",
                }],
                "warnings": [],
                "summary": "❌ Empty or unstructured plan — must include at least one device.",
            }, indent=2, ensure_ascii=False)

        plan = TopologyPlan.model_validate_json(plan_json)
        result = validate_plan(plan)

        output = result.to_dict()
        if result.is_valid:
            output["summary"] = "✅ Valid plan. No errors."
        else:
            output["summary"] = f"❌ Plan with {len(result.errors)} error(es)."
        return json.dumps(output, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # AUTO-FIX
    # ------------------------------------------------------------------
    @mcp.tool()
    def pt_fix_plan(plan_json: str) -> str:
        """
        Try to fix errors in your plan automatically. 
        Fix cables, upgrade routers if ports are missing, reassign ports. 
        
        Parameters: 
        - plan_json: JSON of the plan to be corrected
        """
        plan = TopologyPlan.model_validate_json(plan_json)
        fixed_plan, fixes = fix_plan(plan)

        return json.dumps({
            "fixes_applied": fixes,
            "fixes_count": len(fixes),
            "is_valid": fixed_plan.is_valid,
            "plan": json.loads(fixed_plan.model_dump_json()),
        }, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # EXPLANATION
    # ------------------------------------------------------------------
    @mcp.tool()
    def pt_explain_plan(plan_json: str) -> str:
        """
        Explain the plan's decisions in natural language. 
        Useful for understanding why certain models, IPs, etc. were chosen. 
        
        Parameters: 
        - plan_json: Plan JSON
        """
        plan = TopologyPlan.model_validate_json(plan_json)
        explanations = explain_plan(plan)
        return "\n".join(f"• {e}" for e in explanations)

    # ------------------------------------------------------------------
    # GENERATION
    # ------------------------------------------------------------------
    @mcp.tool()
    def pt_generate_script(plan_json: str, include_configs: bool = True) -> str:
        """
        Generate the PTBuilder JavaScript script. 
        
        Parameters: 
        - plan_json: Plan JSON 
        - include_configs: If True, include CLI configs as comments
        """
        plan = TopologyPlan.model_validate_json(plan_json)
        if include_configs:
            return generate_full_script(plan)
        return generate_ptbuilder_script(plan)

    @mcp.tool()
    def pt_generate_configs(plan_json: str) -> str:
        """
        Generates CLI (IOS) configurations for all routers and switches. 
        
        Parameters: 
        - plan_json: Plan JSON
        """
        plan = TopologyPlan.model_validate_json(plan_json)
        configs = generate_all_configs(plan)

        result_parts = []
        for device_name, cli_block in configs.items():
            result_parts.append(f"=== {device_name} ===")
            result_parts.append(cli_block)
            result_parts.append("")

        pcs = [d for d in plan.devices if d.category in ("pc", "server", "laptop")]
        if pcs:
            result_parts.append("=== Host configuration ===")
            use_dhcp = bool(plan.dhcp_pools)
            for pc in pcs:
                result_parts.append(generate_pc_config(pc, use_dhcp=use_dhcp))
                result_parts.append("")

        return "\n".join(result_parts)

    # ------------------------------------------------------------------
    # FULL BUILD
    # ------------------------------------------------------------------
    @mcp.tool()
    def pt_full_build(
        routers: int = 2,
        pcs_per_lan: int = 3,
        laptops_per_lan: int = 0,
        switches_per_router: int = 1,
        servers: int = 0,
        access_points: int = 0,
        has_wan: bool = False,
        dhcp: bool = True,
        routing: str = "static",
        router_model: str = "2911",
        switch_model: str = "2960-24TT",
        template: str = "multi_lan",
        deploy: bool = True,
        floating_routes: bool = False,
        ospf_process_id: int = 1,
        eigrp_as: int = 100,
        vlans: int = 0,
        dual_stack: bool = False,
        ipv6_base: str = "2001:db8::/32",
        wireless_laptops: bool = False,
    ) -> str:
        """
        Complete pipeline: plans, validates, generates, explains, estimates, and deploys. 
        
        With deploy=True (default) the deployment depends on whether there is channel to PT: 
        - If the bridge is connected, the topology is REALLY created in Packet Tracer 
        (same path as pt_live_deploy, with verification and reconcile), 
        and the project files are also exported to disk. 
        - If there is no channel, it drops to manual mode: copy the script to the clipboard 
        and generates step-by-step instructions. 
        
        Parameters: 
        - routers: Number of routers (1-20) 
        - pcs_per_lan: LAN PCs 
        - laptops_per_lan: LAN Laptops (Laptop-PT) 
        - switches_per_router: Switches per router 
        - servers: Servers 
        - access_points: Access Points (AccessPoint-PT), one per LAN 
        - has_wan: Include WAN
        - dhcp: Configure DHCP 
        - routing: static, ospf, eigrp, rip, none 
        - router_model: 1941, 2901, 2911, ISR4321 
        - switch_model: 2960-24TT, 3560-24PS 
        - template: single_lan, multi_lan, multi_lan_wan, star, hub_spoke, 
        branch_office, router_on_a_stick, three_router_triangle, custom 
        - deploy: If True, copy script to clipboard and export files 
        - floating_routes: If True with routing=static, add backup paths with AD=254 
        - ospf_process_id: OSPF process ID (1-65535, default 1) 
        - eigrp_as: AS number for EIGRP (1-65535, default 100) 
        - VLANs: Only router_on_a_stick. No. of VLANs to be distributed among the PCs 
        (0 = default 2). 
        - dual_stack: If True, add IPv6 (routers per CLI, hosts per SLAAC). 
        - ipv6_base: Base IPv6 prefix for dual-stack (default "2001:db8::/32"). 
        - wireless_laptops: If True, laptops connect via WiFi (wireless NIC + AP).
        """
        request = TopologyRequest(
            template=TopologyTemplate(template),
            routers=routers,
            pcs_per_lan=pcs_per_lan,
            laptops_per_lan=laptops_per_lan,
            switches_per_router=switches_per_router,
            servers=servers,
            access_points=access_points,
            has_wan=has_wan,
            dhcp=dhcp,
            routing=RoutingProtocol(routing),
            router_model=router_model,
            switch_model=switch_model,
            floating_routes=floating_routes,
            ospf_process_id=ospf_process_id,
            eigrp_as=eigrp_as,
            vlans=vlans,
            dual_stack=dual_stack,
            ipv6_base=ipv6_base,
            wireless_laptops=wireless_laptops,
        )
        plan, validation = plan_from_request(request)
        explanation = explain_plan(plan)
        estimation = estimate_from_plan(plan)

        parts: list[str] = []

        #--- Summary ---        
        parts.append("=" * 60) 
        parts.append("TOPOLOGY SUMMARY") 
        parts.append("=" * 60) 
        parts.append(f"Devices: {len(plan.devices)}") 
        parts.append(f"Links: {len(plan.links)}") 
        parts.append(f"DHCP Pools: {len(plan.dhcp_pools)}") 
        parts.append(f"Static paths: {len(plan.static_routes)}") 
        parts.append(f"OSPF configs: {len(plan.ospf_configs)}") 
        parts.append(f"RIP configs: {len(plan.rip_configs)}") 
        parts.append(f"EIGRP configs: {len(plan.eigrp_configs)}") 
        parts.append("")


        # --- Validation ---
        if validation.is_valid:
            parts.append("✅ Validation: PASS")
        else:
            parts.append("❌ Validation: FAIL")
            for err in validation.errors:
                parts.append(f"  ERROR [{err.code.value}]: {err.message}")
        if validation.warnings:
            for warn in validation.warnings:
                parts.append(f"  ⚠️ [{warn.code.value}]: {warn.message}")
        parts.append("")

        # --- Explanation ---
        parts.append("=" * 60)
        parts.append("EXPLANATION")
        parts.append("=" * 60)
        for e in explanation:
            parts.append(f"• {e}")
        parts.append("")

        # --- ADDRESSING TABLE ---
        parts.append("=" * 60)
        parts.append("ADDRESSING TABLE")
        parts.append("=" * 60)
        for dev in plan.devices:
            if dev.interfaces:
                parts.append(f"{dev.name} ({dev.model}):")
                for iface, ip in dev.interfaces.items():
                    parts.append(f"  {iface}: {ip}")
                if dev.gateway:
                    parts.append(f"  Gateway: {dev.gateway}")
            elif dev.gateway:
                parts.append(f"{dev.name}: DHCP (Gateway: {dev.gateway})")
        parts.append("")

        # --- Script PTBuilder ---
        parts.append("=" * 60)
        parts.append("SCRIPT PTBUILDER")
        parts.append("=" * 60)
        parts.append(generate_full_script(plan))
        parts.append("")

        # --- Configs CLI ---
        configs = generate_all_configs(plan)
        parts.append("=" * 60)
        parts.append("CLI CONFIGURATIONS")
        parts.append("=" * 60)
        for device_name, cli_block in configs.items():
            parts.append(f"\n--- {device_name} ---")
            parts.append(cli_block)

        pcs = [d for d in plan.devices if d.category in ("pc", "server", "laptop")]
        if pcs:
            parts.append(f"\n--- Hosts ---")
            use_dhcp = bool(plan.dhcp_pools)
            for pc in pcs:
                parts.append(generate_pc_config(pc, use_dhcp=use_dhcp))

        # --- Suggested validations ---
        if plan.validations:
            parts.append("")
            parts.append("=" * 60)
            parts.append("SUGGESTED CHECKS")
            parts.append("=" * 60)
            for v in plan.validations:
                parts.append(f" {v.check_type}: {v.from_device} → {v.to_target} (expected: {v.expected})")

        # --- Deploy ---
        if deploy:
            parts.append("")
            parts.append("=" * 60)
            parts.append("DEPLOY IN PACKET TRACER")
            parts.append("=" * 60)
            project_name = f"build_{routers}r_{pcs_per_lan}pc"

            # With a live channel you have to really deploy. Before this ALWAYS 
            # went to the clipboard, so the "full" pipeline ended with 
            # the empty canvas even if the bridge was connected: the user 
            # I saw "✅ Validation: PASS" and in PT there was nothing.
            if _pick_channel() != "":
                parts.append(pt_live_deploy(plan.model_dump_json()))
                parts.append("")
                export_result = ManualExecutor(output_dir="projects").execute(
                    plan, project_name=project_name
                )
                parts.append(f"Files exported in: {export_result['project_dir']}") 
                parts.append(" CLI configs in *_config.txt files")
            else:
                deploy_exec = DeployExecutor(output_dir="projects")
                deploy_result = deploy_exec.execute(plan, project_name=project_name)
                if deploy_result["clipboard"]:
                    parts.append("SCRIPT COPIED TO CLIPBOARD") 
                    parts.append("") 
                    parts.append("Instructions:") 
                    parts.append(" 1. Open Packet Tracer") 
                    parts.append(" 2. Go to Extensions > Scripting") 
                    parts.append(" 3. Paste (Ctrl+V) and execute") 
                    parts.append("") 
                    parts.append(f"Files exported in: {deploy_result['project_dir']}") 
                    parts.append(" CLI configs in *_config.txt files") 
                else: 
                    parts.append(f"Files exported in: {deploy_result['project_dir']}") 
                    parts.append("Copy topology.js and paste it into PT > Extensions > Scripting") 
                parts.append("") 
                parts.append(deploy_result["instructions"])

        # --- Plan JSON ---
        parts.append("")
        parts.append("=" * 60)
        parts.append("JSON PLAN (for programmatic use)")
        parts.append("=" * 60)
        parts.append(plan.model_dump_json(indent=2))

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # EXPORT
    # ------------------------------------------------------------------
    @mcp.tool()
    def pt_export(
        plan_json: str,
        project_name: str = "topology",
        output_dir: str = "projects",
    ) -> str:
        """
        Export the plan to files: JS script, CLI configs, and JSON. 
        
        Parameters: 
        - plan_json: Plan JSON 
        - project_name: Project name 
        - output_dir: Output Directory
        """
        plan = TopologyPlan.model_validate_json(plan_json)
        executor = ManualExecutor(output_dir=output_dir)
        result = executor.execute(plan, project_name=project_name)

        lines = [
            f"Files exported in {result['project_dir']}:",
        ]
        for key, path in result["files"].items():
            lines.append(f"  - {key}: {path}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # DEPLOY (clipboard + instructions)
    # ------------------------------------------------------------------
    @mcp.tool()
    def pt_deploy(
        plan_json: str,
        project_name: str = "topology",
        output_dir: str = "projects",
    ) -> str:
        """
        Deploy a plan to Packet Tracer: copy the script to the clipboard of Windows, 
        exports configuration files, and generates Step-by-step instructions. 
        
        Usage: After pt_full_build or pt_plan_topology, pass the JSON plan here 
        to get everything ready for Packet Tracer. 
        
        Parameters: 
        - plan_json: Plan JSON (pt_plan_topology or pt_full_build output) 
        - project_name: Project name 
        - output_dir: Output Directory
        """
        plan = TopologyPlan.model_validate_json(plan_json)
        executor = DeployExecutor(output_dir=output_dir)
        result = executor.execute(plan, project_name=project_name)

        parts: list[str] = []

        if result["clipboard"]:
            parts.append("SCRIPT COPIED TO CLIPBOARD") 
            parts.append("Paste directly into Packet Tracer > Extensions > Scripting")
        else:
            parts.append("EXPORTED FILES (could not copy to clipboard)") 
            parts.append(f"Open {result['project_dir']}/topology.js and copy its contents")

        parts.append("")
        parts.append(f"Project: {result['project_dir']}") 
        parts.append(f"Devices: {result['devices_count']}") 
        parts.append(f"Links: {result['links_count']}")
        parts.append("")

        for key, path in result["files"].items():
            parts.append(f"  {key}: {path}")

        parts.append("")
        parts.append(result["instructions"])

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # PROJECTS
    # ------------------------------------------------------------------
    @mcp.tool()
    def pt_list_projects(output_dir: str = "projects") -> str:
        """
        List your saved projects. 
        
        Parameters: 
        - output_dir: Project Base Directory
        """
        repo = ProjectRepository(base_dir=output_dir)
        projects = repo.list_projects()
        if not projects:
            return "No projects saved."
        return json.dumps(projects, indent=2, ensure_ascii=False)

    @mcp.tool()
    def pt_load_project(project_name: str, output_dir: str = "projects") -> str:
        """
        Upload a saved project. 
        
        Parameters: 
        - project_name: Project name 
        - output_dir: Project Base Directory
        """
        repo = ProjectRepository(base_dir=output_dir)
        plan = repo.load_plan(project_name)
        return plan.model_dump_json(indent=2)

    # ------------------------------------------------------------------
    # LIVE DEPLOY (direct to Packet Tracer)
    # ------------------------------------------------------------------

    _BRIDGE_PORT = DEFAULT_PORT
    _BRIDGE_URL = f"http://127.0.0.1:{_BRIDGE_PORT}"

    # Commands per POST. Bounded so as not to approach the bridge body limit 
    # with large topologies, and so that progress is visible in PT.
    _DEPLOY_BATCH = 50

    # report_result_js() lives in live_bridge.py (one place) and spawns under 
    # lawsuit because it carries the token inside. The HTTP branch of _bridge_send_and_wait 
    # puts it before the command; through the file channel it is injected by the Script Engine. 
    
    # Internal singleton bridge — starts automatically within the MCP process
    _bridge_instance: PTCommandBridge | None = None

    def _signed(url: str) -> str:
        """Add the bridge token to the URL. 
        
        It is signed here and not on every call so that there is no path without 
        a token that someone can carelessly add later.
        """
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}t={urllib.parse.quote(get_bridge_token())}"

    def _http_get(url: str, timeout: float = 2.0):
        try:
            with urllib.request.urlopen(_signed(url), timeout=timeout) as r:
                return r.status, r.read().decode("utf-8")
        except Exception:
            return None, None

    def _http_post(url: str, body: str, timeout: float = 3.0):
        try:
            data = body.encode("utf-8")
            req = urllib.request.Request(_signed(url), data=data, method="POST")
            req.add_header("Content-Type", "text/plain")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read().decode("utf-8")
        except Exception:
            return None, None

    def _js_guard(js: str) -> str:
        """Wraps a JS command in a Script Engine-level try/catch (fire-and-forget). 
        
        Without this, an error NOT caught within runCode triggers a modal QMessageBox 
        in PT that freezes the webview and kills the bridge polling — you have to close 
        the modal to hand to reconnect. The catch is silent because this path does not 
        wait response; the path that does wait (_bridge_send_and_wait) uses its own catch 
        that report the error via reportResult() so as not to crash until timeout.
        """
        return "try{" + js + "}catch(__pterr){}"

    def _bridge_identity() -> str:
        """Who's listening at the port: 'ours' | 'foreign' | 'none'. 
        
        Before, it was enough for something to answer 200 to /ping to be considered good — 
        and from there ALL the JS payloads were sent to that process, whatever it was. 
        Now /ping returns an ID with the token footprint, so you can distinguish ours 
        from a stranger.
        """
        status, body = _http_get(f"{_BRIDGE_URL}/ping", timeout=1.0)
        if status != 200 or not body:
            return "none"
        try:
            doc = json.loads(body)
        except Exception:
            return "foreign"
        if doc.get("service") != "pt-mcp-bridge":
            return "foreign"
        if doc.get("id") != token_fingerprint(get_bridge_token()):
            return "foreign"
        return "ours"

    def _bridge_is_up() -> bool:
        return _bridge_identity() == "ours"

    def _bridge_pt_connected() -> bool:
        status, body = _http_get(f"{_BRIDGE_URL}/status", timeout=1.0)
        if status == 200 and body:
            try:
                return json.loads(body).get("connected", False)
            except Exception:
                pass
        return False

    def _ensure_bridge() -> bool:
        """
        Ensures that a bridge exists by listening in :54321. 
        If there is already one (internal or external), it does nothing. 
        If there aren't any, start an in-process one like thread daemon. 
        Returns True if the bridge is operational.
        """
        nonlocal _bridge_instance
        if _bridge_is_up():
            return True  # There is already one active in the port
        if _bridge_instance is None:
            try:
                b = PTCommandBridge()
                b.start()
                _bridge_instance = b
            except OSError:
                return False  # Port blocked by external process no-bridge
        return _bridge_is_up()

    # The bridge is booted on demand from the tools that need it. 
    # It used to get up here, when registering tools: importing the server opened a 
    # socket even if no one was going to use the live deployment, extending without 
    # reason the window in which the port is listening. 
    
    # ------------------------------------------------------------------ 
    # CHANNEL ROUTING: http (window open) or file (window closed) 
    # ------------------------------------------------------------------ 
    # They coexist. ONE channel is chosen per command, never both, so that nothing is 
    # run twice. HTTP is primary when the window is open 
    # (the tested flow); the file takes over when the Script Engine is 
    # alive but the window closed.

    _file_bridge = FileBridge()

    def _pick_channel() -> str:
        """'http' | 'file' | '' depending on which executor is available."""
        if _bridge_is_up() and _bridge_pt_connected():
            return "http"
        if _file_bridge.pt_alive():
            return "file"
        return ""

    def _channel_send(payload: str) -> bool:
        """Send fire-and-forget over the available channel."""
        ch = _pick_channel()
        if ch == "http":
            status, _ = _http_post(f"{_BRIDGE_URL}/queue", payload)
            return status == 200
        if ch == "file":
            return _file_bridge.send(payload)
        return False

    @mcp.tool()
    def pt_live_deploy(
        plan_json: str,
        command_delay: float = 0.0,
    ) -> str:
        """
        Send commands directly to Packet Tracer in real-time. 
        
        Requires open PT with the MCP Control Center extension installed. With the 
        open window HTTP is used; if you close it, the channel per file (Script Engine) 
        takes over. The bridge starts only within the MCP server. 
        
        Parameters: 
        - plan_json: Plan JSON (pt_plan_topology or pt_full_build output) 
        - command_delay: delay between BATCHES in seconds (default 0.0). 
        Commands are no longer sent one at a time: they go in batches that PT 
        executes in a single runCode, where everyone has their own try/catch. 
        Measured against PT 9.0, create 10 devices + bindings + configure IOS 
        Running takes ~100 ms and the config is applied. 
        Upload it only if you installation chokes.
        """
        if command_delay < 0.0:
            command_delay = 0.0

        # Requires a channel to PT (HTTP with open window, or file with the 
        # Live Script Engine). _check_bridge starts the HTTP and applies the patches 
        # through the right channel.
        err = _check_bridge()
        if err:
            return err

        plan = TopologyPlan.model_validate_json(plan_json)
        script = generate_executable_script(plan)
        commands = [
            line.strip() for line in script.splitlines()
            if line.strip() and not line.strip().startswith("//")
        ]

        # Send in batches: before it was a POST and a sleep(>=1s) PER COMMAND, like this 
        # that a 40-command topology took 40 seconds for no reason 
        # technique. Each command retains its own guard within the batch.
        sent = 0
        for i in range(0, len(commands), _DEPLOY_BATCH):
            chunk = commands[i:i + _DEPLOY_BATCH]
            payload = "\n".join(_js_guard(c) for c in chunk)
            if _channel_send(payload):
                sent += len(chunk)
            if command_delay:
                time.sleep(command_delay)

        dev_ok = 0
        dev_fail = []
        for dev in plan.devices:
            safe = _js_escape(dev.name)
            js = (
                "try {"
                f"  var d = ipc.network().getDevice('{safe}');"
                "  reportResult(d ? 'OK' : 'MISSING');"
                "} catch(e) { reportResult('MISSING'); }"
            )
            r = _bridge_send_and_wait(js, timeout=5.0)
            if r == "OK":
                dev_ok += 1
            else:
                dev_fail.append(dev.name)

        def _verify_link(lnk) -> str | None:
            sd = _js_escape(lnk.device_a)
            sp = _js_escape(lnk.port_a)
            js = (
                "try {"
                f"  var d = ipc.network().getDevice('{sd}');"
                f"  if (!d) {{ reportResult('DEV_MISSING'); throw 's'; }}"
                f"  var p = d.getPort('{sp}');"
                f"  if (!p) {{ reportResult('PORT_MISSING'); throw 's'; }}"
                "  reportResult(p.getLink() != null ? 'OK' : 'NO_LINK');"
                "} catch(e) { if (e !== 's') reportResult('ERROR'); }"
            )
            return _bridge_send_and_wait(js, timeout=5.0)

        link_ok = 0
        link_fail = []
        link_fail_objs = []
        for lnk in plan.links:
            r = _verify_link(lnk)
            if r == "OK":
                link_ok += 1
            else:
                link_fail.append(f"{lnk.device_a}:{lnk.port_a} <-> {lnk.device_b}:{lnk.port_b} ({r or 'timeout'})")
                link_fail_objs.append(lnk)

        # --- Reconcile (fix F16): re-queues the commands of the missing items and re-verifies. 
        # pt_live_deploy sometimes silently drops some devices (typically 
        # Laptop-PT). We reuse the commands already generated, filtering out those that reference to 
        # the failed devices/links (their name appears in quotation marks in lwAddDevice, 
        # lwAddLink and configurePcIp/configureIosDevice).
        reconciled = {"devices": [], "links": []}
        if dev_fail or link_fail_objs:
            names = set(dev_fail)
            for lnk in link_fail_objs:
                names.add(lnk.device_a)
                names.add(lnk.device_b)
            retry_cmds = [c for c in commands if any(f'"{n}"' in c for n in names)]
            for cmd in retry_cmds:
                _channel_send(_js_guard(cmd))
                time.sleep(command_delay)

            # Re-verificar dispositivos fallidos
            still_missing_dev = []
            for name in dev_fail:
                safe = _js_escape(name)
                js = (
                    "try {"
                    f"  var d = ipc.network().getDevice('{safe}');"
                    "  reportResult(d ? 'OK' : 'MISSING');"
                    "} catch(e) { reportResult('MISSING'); }"
                )
                if _bridge_send_and_wait(js, timeout=5.0) == "OK":
                    dev_ok += 1
                    reconciled["devices"].append(name)
                else:
                    still_missing_dev.append(name)
            dev_fail = still_missing_dev

            # Re-verify failed links
            still_failed_links = []
            for lnk in link_fail_objs:
                if _verify_link(lnk) == "OK":
                    link_ok += 1
                    reconciled["links"].append(f"{lnk.device_a}:{lnk.port_a}")
                else:
                    still_failed_links.append(
                        f"{lnk.device_a}:{lnk.port_a} <-> {lnk.device_b}:{lnk.port_b}"
                    )
            link_fail = still_failed_links

        report = [
            "Topology deployed in Packet Tracer!",
            f"  Commands sent: {sent}",
            f"  Devices: {dev_ok}/{len(plan.devices)} Verified",
        ]
        if reconciled["devices"] or reconciled["links"]:
            report.append(
                f" ♻ Reconciled: {len(reconciled['devices'])} device(s), "
                f"{len(reconciled['links'])} link(s) re-added after drop."
            )
        if dev_fail:
            report.append(f"  FAILED devices: {', '.join(dev_fail)}")
        report.append(f" Links: {link_ok}/{len(plan.links)} verified")
        if link_fail:
            report.append("  FAILED links:")
            for f in link_fail:
                report.append(f"    - {f}")

        return "\n".join(report)

    def _stale_client_message() -> str:
        """Message for when PT reaches the bridge but we reject it for token. 
        
        Without this, 'PT is not open' and 'PT is but its extension is old' 
        they saw exactly the same, and the symptom was 'stopped walking' without cause. 
        """
        return (
            "Packet Tracer IS reaching the bridge, but every request is being "
            "REJECTED (missing or invalid token).\n\n"
            "Why: this version requires an automatically-generated local token on "
            "every bridge request. The code running inside Packet Tracer was built "
            "by an older version and doesn't carry it. Nothing is wrong with your "
            "setup.\n\n"
            "Fix: update the MCP Control Center extension to V5.0+ from\n"
            "https://github.com/Mats2208/MCP-Packet-Tracer/releases/latest\n"
            "and reopen it. V5 reads the token from disk automatically — nothing "
            "to pair or paste. The token is stored on this machine and reused "
            "across restarts."
        )

    @mcp.tool()
    def pt_bridge_status() -> str:
        """ Check which channel Packet Tracer is connected to. 
        
        There are two: HTTP (when the MCP Control Center window is open) and 
        file (when closed but PT is still open with the extension). With Either way, 
        the deployment works. 
        """
        identity = _bridge_identity()
        if identity == "foreign":
            return (
                f"Port {_BRIDGE_PORT} is occupied by a process that is NOT this "
                "MCP server's bridge (likely a leftover MCP server from an earlier "
                "session).\n"
                "Refusing to send commands to it — they would run in whatever is "
                "listening there.\n"
                "Kill that process (or restart the MCP server) and retry."
            )

        http_up = _ensure_bridge()
        http_connected = http_up and _bridge_pt_connected()
        file_alive = _file_bridge.pt_alive()

        # Actual PT webview headers (includes Origin: pt-sm:), useful 
        # for diagnosis and to adjust CORS later.
        hdr = ""
        if _bridge_instance is not None and _bridge_instance._client_headers:
            hdr = f"\nPT client headers: {_bridge_instance._client_headers}"

        if http_connected and file_alive:
            return (
                "CONNECTED by both channels:\n" 
                f"  • HTTP (open window) — http://127.0.0.1:{_BRIDGE_PORT}\n" 
                "  • file-bridge (Script Engine, follow if you close the window)" + hdr
            )
        if http_connected:
            return (
                "CONNECTED over HTTP (MCP Control Center window open) — "
                f"http://127.0.0.1:{_BRIDGE_PORT}.\n" 
                "Note: the file-bridge has not yet reported heartbeat; if you close the "
                "Window, wait a few seconds for me to take over." + hdr
            )
        if file_alive:
            return (
                "CONNECTED by file-bridge (window is closed, but PT is still "
                "Open with the extension). The deployment works the same, a little" 
                "slower than HTTP. Open MCP Control Center if you want the channel "
                "HTTP and the Logs Panel."
            )

        # No channel.
        if _bridge_instance is not None and _bridge_instance.saw_recent_unauthorized:
            return _stale_client_message()

        warn = ""
        if token_was_rotated():
            warn = (
                "\n\nNOTE: The saved token was missing or corrupted and was "
                "regenerated. I reopened the extension for you to reread."
            )
        if token_is_ephemeral():
            warn += (
                "\n\nWARNING: The token could not be written to disk, so "
                "It changes with every reboot."
            )

        return (
            "Packet Tracer is NOT connected by any channel.\n" 
            "I opened PT with the MCP Control Center extension installed" 
            "(Extensions > MCP BUILDER). With the window open use HTTP; if the "
            "you close, the file-bridge takes over while PT is open." + warn
        )

    @mcp.tool()
    def pt_verify_connectivity(
        from_device: str,
        to_ip: str,
        count: int = 4,
        timeout_s: float = 20.0,
    ) -> str:
        """
        Run a REAL ping from a device in PT and return the result. 
        
        Unlike validations that are only printed as "verify hand", this 
        runs 'ping' on the device's console and stops the output Actual: 
        How many packets arrived. Serves to confirm that a topology Newly 
        deployed, it really has connectivity. 
        
        Works with hosts (PC/Server/Laptop, format "Packets: Sent=..") and 
        with IOS devices (router/switch, format "Success rate is N percent").

        Parameters: 
        - from_device: Name of the device originating the ping 
        - to_ip: Destination IP 
        - count: reserved; PT uses its default by type (PC 4, IOS 5). A flag 
        "-n" would break on IOS, so for now it is not forced. 
        - timeout_s: Maximum timeout (default 20s). A FAILED ping takes 
        time more than a successful one: each package waits for its own 
        timeout before declare lost (~13s measured for 4 lost packets).
        """
        err = _check_bridge()
        if err:
            return err

        # The JS lives in 'console_ping_arm_js' / 'console_ping_poll_js' (level of 
        # module) to be able to test without a bridge that does not sneak back in 
        # 'getCommandPrompt', which only exists on hosts and broke all IOS ping.
        armed = _bridge_send_and_wait(
            console_ping_arm_js(from_device, to_ip), timeout=8.0
        )
        if armed is None:
            return "No PT (timeout) response when starting the ping."
        if not armed.startswith("BASE:"):
            return f"Could not start ping: {armed}"
        base = int(armed[5:])

        poll = console_ping_poll_js(from_device, base)

        deadline = time.time() + timeout_s
        while time.time() < deadline:
            time.sleep(0.6)
            r = _bridge_send_and_wait(poll, timeout=5.0)
            if r is None:
                continue
            if r.startswith("DONE:"):
                stat = r[5:]
                verdict = {
                    "ok": "CONNECTIVITY OK",
                    # Partial loss: used to be reported as OK, so
                    # 1 out of 4 packs looked the same as 4 out of 4.
                    "partial": "PARTIAL CONNECTIVITY (packet loss)",
                    "none": "NO CONNECTIVITY",
                }[_classify_ping(stat)]
                return f"{from_device} → {to_ip}: {verdict}\n{stat}"

        return (
            f"{from_device} → {to_ip}: No result after {timeout_s:.0f}s. "
            "The ping can keep running; retry or raise timeout_s."
        )

    @mcp.tool()
    def pt_save_project(filename: str, directory: str = "") -> str:
        """
        Saves the active Packet Tracer topology as a .pkt file. 

        Closes the loop: previously, the MCP built the topology, but saving it
        required manually pressing Ctrl+S. 

        Parameters:
        - filename: file name (.pkt is added if missing)
        - directory: destination folder. Empty = PT save folder.
        """
        err = _check_bridge()
        if err:
            return err

        name = safe_name_component(filename.strip(), "topology")
        if not name.lower().endswith(".pkt"):
            name += ".pkt"

        js = (
            "var aw=ipc.appWindow();"
            f"var dir={json.dumps(directory.strip())};"
            "if(!dir){dir='/home/analyst/Downloads';}"
            "dir=String(dir).replace(/\\\\/g,'/').replace(/\\/+$/,'');"
            f"var full=dir+'/'+{json.dumps(name)};"
            "aw.fileSaveAsNoPrompt(full,false);"
            "var fm=ipc.systemFileManager();"
            "reportResult(fm.fileExists(full)?('OK:'+full+'|'+fm.getFileSize(full)):('ERR: File was not created: '+full));"
        )
        result = _bridge_send_and_wait(js, timeout=20.0)
        if result is None:
            return "No PT (timeout) response when saving."
        if result.startswith("OK:"):
            path_str, _, size = result[3:].rpartition("|")
            return f"Project saved in {path_str} ({size} bytes)."
        return f"PT error saving: {result}"

    @mcp.tool()
    def pt_open_project(path: str) -> str:
        """
        Open a.pkt file in Packet Tracer. 
        
        ATTENTION: Replaces the currently open topology. If you have changes 
        without Save, store them first with pt_save_project. 
        
        Parameters: 
        - path: full path to the.pkt file
        """
        err = _check_bridge()
        if err:
            return err

        target = path.strip().replace("\\", "/")
        if not target.lower().endswith(".pkt"):
            return "The file must end in .pkt"

        js = (
            "var fm=ipc.systemFileManager();"
            f"var p={json.dumps(target)};"
            "if(!fm.fileExists(p)){reportResult('ERR: does not exist '+p);}"
            "else{ipc.appWindow().fileOpen(p);"
            "reportResult('OK:'+ipc.network().getDeviceCount());}"
        )
        result = _bridge_send_and_wait(js, timeout=30.0)
        if result is None:
            return "No PT (timeout) response when opening."
        if result.startswith("OK:"):
            return f"Open project: {target} ({result[3:]} devices)."
        return f"PT error when opening: {result}"

    # ------------------------------------------------------------------
    # Helpers for bidirectional tools (send command → wait for result)
    # ------------------------------------------------------------------

    # Unique timeout message, so as not to repeat four almost identical variants.
    _TIMEOUT_MSG = (
        "No response from PT (timeout). Check pt_bridge_status — PT must be open "
        "with the MCP Control Center extension."
    )

    # Defined in shared/utils.py: when living within this closure there was no 
    # way to test it, and it's just the kind of function to test.
    _js_escape = js_escape

    def _bridge_send_and_wait(js_call: str, timeout: float = 10.0) -> str | None:
        """Send JS and wait for the result, through the available channel. 
        
        The js_call is wrapped in try/catch: an error not caught is reported as 
        'PT_ERROR:...' via reportResult instead of opening a modal that kills the bridge. 
        
        HTTP and file differ in how reportResult arrives, so the wrapper Different Weapon 
        Per Channel: 
        - HTTP: report_result_js defines a reportResult that XHR does to /result. 
        - file: The Script Engine injects a local reportResult that captures the value 
        and writes it to the res; here the "raw" JS is sent with its try/catch. 
        """
        ch = _pick_channel()
        guarded = (
            "try{" + js_call + "}catch(__pterr){reportResult('PT_ERROR: '+__pterr);}"
        )
        if ch == "http":
            # The rid correlates this operation with ITS result. Travel within 
            # of the injected JS, so PT returns it by itself and the extension does not 
            # entire. Without it, a result that came late was kept by the 
            # Next operation.
            rid = next_rid()
            wrapped = (
                report_result_js(_BRIDGE_PORT, get_bridge_token(), rid) + ";" + guarded
            )
            status_post, _ = _http_post(f"{_BRIDGE_URL}/queue", wrapped)
            if status_post != 200:
                return None
            # The 'wait' goes to the server: the one who knows how long the operation takes is 
            # who asks for it. The socket timeout goes above for you to win 
            # the server and a 204 means "didn't arrive", not "I hung up".
            status_get, body = _http_get(
                f"{_BRIDGE_URL}/result?rid={rid}&wait={timeout}",
                timeout=timeout + 5.0,
            )
            return body if status_get == 200 else None
        if ch == "file":
            return _file_bridge.send_and_wait(guarded, timeout=timeout)
        return None

    def _check_bridge() -> str | None:
        """Verify that there is a channel to PT (HTTP or file). Error message or None. 
        
        The helpers of the script engine (lwAddDevice, etc.) are defined by the extension 
        (installMcpHelpers in V5), so there's nothing to inject per channel. 
        """
        ch = _pick_channel()
        if ch in ("http", "file"):
            return None
        # No live channel: start the HTTP in case the window is about to open.
        _ensure_bridge()
        if _bridge_instance is not None and _bridge_instance.saw_recent_unauthorized:
            return _stale_client_message()
        return (
            "Packet Tracer is not connected by any channel.\n" 
            "I opened the MCP Control Center extension in PT (Extensions > MCP BUILDER). "
            "With the window open use HTTP; if you close it, the channel per file "
            "take over while PT is still open."
        )

    # ------------------------------------------------------------------
    # QUERY / INTERACT with existing topology in PT
    # ------------------------------------------------------------------

    @mcp.tool()
    def pt_query_topology() -> str:
        """
        Query current devices in Packet Tracer.
        Returns name, model, and port/IP info for each device in the active topology.
        Requires bridge connected (use pt_bridge_status to verify).
        """
        err = _check_bridge()
        if err:
            return err

        js = (
            "try {"
            "  var net = ipc.network();"
            "  var n = net.getDeviceCount();"
            "  var lc = net.getLinkCount();"
            "  var parts = [];"
            "  for (var i = 0; i < n; i++) {"
            "    var d = net.getDeviceAt(i);"
            "    var pc = d.getPortCount();"
            "    var portNames = [];"
            "    for (var j = 0; j < pc; j++) {"
            "      var p = d.getPortAt(j);"
            "      try {"
            "        var ip = p.getIpAddress();"
            "        if (ip && ip !== '0.0.0.0') {"
            "          portNames.push(p.getName() + '=' + ip + '/' + p.getSubnetMask());"
            "        } else {"
            "          portNames.push(p.getName());"
            "        }"
            "      } catch(pe) { portNames.push(p.getName()); }"
            "    }"
            "    parts.push(d.getName() + '|' + d.getModel() + '|' + portNames.join(','));"
            "  }"
            "  reportResult('DEVICES:' + n + '|LINKS:' + lc + '\\n' + parts.join('\\n'));"
            "} catch(e) { reportResult('ERROR:' + e); }"
        )
        result = _bridge_send_and_wait(js, timeout=10.0)
        if result is None:
            return _TIMEOUT_MSG
        if result.startswith("ERROR:"):
            return f"PT error: {result}"

        lines_raw = result.split("\n")
        header = lines_raw[0] if lines_raw else ""
        device_lines = lines_raw[1:] if len(lines_raw) > 1 else []

        output = [header, ""]
        for line in device_lines:
            if not line.strip():
                continue
            parts = line.split("|", 2)
            name = parts[0] if len(parts) > 0 else "?"
            model = parts[1] if len(parts) > 1 else "?"
            ports = parts[2] if len(parts) > 2 else ""
            port_info = f"  ({ports})" if ports else ""
            output.append(f"  {name:20} [{model}]{port_info}")
        return "\n".join(output)

    @mcp.tool()
    def pt_export_topology() -> str:
        """
        Export a detailed snapshot of the full topology currently in Packet Tracer.
        Returns JSON with devices (name, model, x/y position, interfaces with IPs)
        and links (endpoints, ports, cable type). This gives a complete picture of
        what is deployed so the LLM can reason about the topology.
        """
        err = _check_bridge()
        if err:
            return err

        js = (
            "try {"
            "  var net = ipc.network();"
            "  var devCount = net.getDeviceCount();"
            "  var linkCount = net.getLinkCount();"
            "  var devices = [];"
            "  for (var i = 0; i < devCount; i++) {"
            "    var d = net.getDeviceAt(i);"
            "    var ports = [];"
            "    var pc = d.getPortCount();"
            "    for (var j = 0; j < pc; j++) {"
            "      var p = d.getPortAt(j);"
            "      var pInfo = p.getName();"
            "      try {"
            "        var ip = p.getIpAddress();"
            "        var mask = p.getSubnetMask();"
            "        if (ip && ip !== '0.0.0.0') pInfo += ':' + ip + '/' + mask;"
            "      } catch(e) {}"
            "      var hasLink = (p.getLink() != null) ? '1' : '0';"
            "      pInfo += ':' + hasLink;"
            "      ports.push(pInfo);"
            "    }"
            "    var x = 0; var y = 0;"
            "    try { x = d.getXCoordinate(); y = d.getYCoordinate(); } catch(e) {}"
            "    devices.push(d.getName() + '|' + d.getModel() + '|' + x + '|' + y + '|' + ports.join(','));"
            "  }"
            "  var links = [];"
            "  for (var k = 0; k < linkCount; k++) {"
            "    var l = net.getLinkAt(k);"
            "    var cls = l.getClassName();"
            "    try {"
            "      if (cls === 'Antenna') {"
            "        var ap = l.getPort().getOwnerDevice().getName();"
            "        var apPort = l.getPort().getName();"
            "        links.push(ap + ':' + apPort + '|[wireless-signal]');"
            "      } else {"
            "        var p1 = l.getPort1();"
            "        var p2 = l.getPort2();"
            "        var d1 = p1.getOwnerDevice().getName();"
            "        var d2 = p2.getOwnerDevice().getName();"
            "        links.push(d1 + ':' + p1.getName() + '|' + d2 + ':' + p2.getName());"
            "      }"
            "    } catch(le) { links.push('UNKNOWN:' + cls); }"
            "  }"
            "  reportResult('TOPO|' + devCount + '|' + linkCount + '\\n' + devices.join('\\n') + '\\nLINKS\\n' + links.join('\\n'));"
            "} catch(e) { reportResult('ERROR:' + e); }"
        )
        result = _bridge_send_and_wait(js, timeout=15.0)
        if result is None:
            return _TIMEOUT_MSG
        if result.startswith("ERROR:"):
            return f"PT error: {result}"

        lines = result.split("\n")
        header = lines[0] if lines else ""
        header_parts = header.split("|")
        dev_count = header_parts[1] if len(header_parts) > 1 else "?"
        link_count = header_parts[2] if len(header_parts) > 2 else "?"

        output = [f"=== Topology Export: {dev_count} devices, {link_count} links ===", ""]
        in_links = False
        for line in lines[1:]:
            if not line.strip():
                continue
            if line == "LINKS":
                output.append("")
                output.append("--- Links ---")
                in_links = True
                continue
            if in_links:
                parts = line.split("|")
                if len(parts) == 2:
                    if parts[1] == "[wireless-signal]":
                        output.append(f"  {parts[0]}  )))  [wireless signal]")
                    else:
                        output.append(f"  {parts[0]}  <-->  {parts[1]}")
                else:
                    output.append(f"  {line}")
            else:
                parts = line.split("|")
                name = parts[0] if len(parts) > 0 else "?"
                model = parts[1] if len(parts) > 1 else "?"
                x = parts[2] if len(parts) > 2 else "?"
                y = parts[3] if len(parts) > 3 else "?"
                ports_raw = parts[4] if len(parts) > 4 else ""

                output.append(f"  {name} [{model}] @ ({x}, {y})")
                if ports_raw:
                    for pstr in ports_raw.split(","):
                        pparts = pstr.split(":")
                        pname = pparts[0]
                        ip_info = ""
                        linked = ""
                        if len(pparts) >= 3:
                            if pparts[1] and "/" in pparts[1]:
                                ip_info = f" IP={pparts[1]}"
                            linked = " [linked]" if pparts[-1] == "1" else ""
                        elif len(pparts) == 2:
                            linked = " [linked]" if pparts[1] == "1" else ""
                        if ip_info or linked:
                            output.append(f"    {pname}{ip_info}{linked}")

        return "\n".join(output)

    @mcp.tool()
    def pt_delete_device(device_name: str) -> str:
        """
        Delete a device from the active topology in Packet Tracer.
        Uses getLogicalWorkspace().removeDevice() and verifies the device is gone.

        Parameters:
        - device_name: exact device name (e.g. "R1", "PC3", "Laptop-WAN")
        """
        err = _check_bridge()
        if err:
            return err

        safe_name = _js_escape(device_name)
        js = (
            "try {"
            f'  var dev = ipc.network().getDevice("{safe_name}");'
            "  if (!dev) { reportResult('ERROR:Device not found'); }"
            "  else {"
            "    var lw = ipc.appWindow().getActiveWorkspace().getLogicalWorkspace();"
            "    if (typeof lw.removeDevice !== 'function') {"
            "      reportResult('ERROR:removeDevice API not available in this PT build');"
            "    } else {"
            "      lw.removeDevice(dev.getName());"
            f'      var still = ipc.network().getDevice("{safe_name}");'
            "      reportResult(still ? 'ERROR:device still present after removeDevice' : 'OK:deleted');"
            "    }"
            "  }"
            "} catch(e) { reportResult('ERROR:' + e); }"
        )
        result = _bridge_send_and_wait(js, timeout=8.0)
        if result is None:
            return f"No response from PT. Device '{device_name}' may not exist."
        if result.startswith("ERROR:"):
            return f"Error: {result[6:]}"
        return f"Device '{device_name}' deleted from the topology."

    @mcp.tool()
    def pt_rename_device(old_name: str, new_name: str) -> str:
        """
        Rename a device in the active Packet Tracer topology.

        Parameters:
        - old_name: current device name
        - new_name: new name to assign
        """
        err = _check_bridge()
        if err:
            return err

        if not new_name.strip():
            return "Error: new_name cannot be empty."
        if old_name == new_name:
            return f"Device '{old_name}' It's already called that — no change."

        safe_old = _js_escape(old_name)
        safe_new = _js_escape(new_name)
        js = (
            "try {"
            f'  var dev = ipc.network().getDevice("{safe_old}");'
            "  if (!dev) { reportResult('ERROR:Device not found'); }"
            # PT lets you put a repeated name without complaining, and there getDevice() 
            # can only return one of the two: the other remains on the canvas 
            # but unreachable by name, and any tool that references it 
            # Work silently on the wrong one.
            f'  else if (ipc.network().getDevice("{safe_new}")) {{'
            f"    reportResult('ERROR:DUPLICATE'); }}"
            "  else {"
            f'    dev.setName("{safe_new}");'
            f'    reportResult("OK:renamed to {safe_new}");'
            "  }"
            "} catch(e) { reportResult('ERROR:' + e); }"
        )
        result = _bridge_send_and_wait(js, timeout=8.0)
        if result is None:
            return "No response from PT."
        if result == "ERROR:DUPLICATE":
            return (
                f"Error: A device named '{new_name}' already exists. "
                "Two devices with the same name make PT solve" 
                "always the same and the other is unreachable by name — "
                "Choose another or rename the one who occupies it first."
            )
        if result.startswith("ERROR:"):
            return f"Error: {result[6:]}"
        return f"Device renamed: '{old_name}' → '{new_name}'"

    @mcp.tool()
    def pt_move_device(device_name: str, x: int, y: int) -> str:
        """
        Move a device to new coordinates on the Packet Tracer canvas.

        Parameters:
        - device_name: device name
        - x: X coordinate (logical view, e.g. 100-800)
        - y: Y coordinate (logical view, e.g. 100-600)
        """
        err = _check_bridge()
        if err:
            return err

        safe_name = _js_escape(device_name)
        js = (
            "try {"
            f'  var dev = ipc.network().getDevice("{safe_name}");'
            "  if (!dev) { reportResult('ERROR:Device not found'); }"
            "  else {"
            f"    dev.moveToLocation({int(x)}, {int(y)});"
            f'    reportResult("OK:moved to {int(x)},{int(y)}");'
            "  }"
            "} catch(e) { reportResult('ERROR:' + e); }"
        )
        result = _bridge_send_and_wait(js, timeout=8.0)
        if result is None:
            return "No response from PT."
        if result.startswith("ERROR:"):
            return f"Error: {result[6:]}"
        return f"Device '{device_name}' moved to ({x}, {y})."

    @mcp.tool()
    def pt_delete_link(device_name: str, interface_name: str) -> str:
        """
        Delete the link connected to a specific interface on a device in PT.

        Parameters:
        - device_name: device name (e.g. "R1")
        - interface_name: interface name (e.g. "GigabitEthernet0/0", "FastEthernet0/1")
        """
        err = _check_bridge()
        if err:
            return err

        safe_dev = _js_escape(device_name)
        safe_iface = _js_escape(interface_name)
        js = (
            "try {"
            f'  var dev = ipc.network().getDevice("{safe_dev}");'
            "  if (!dev) { reportResult('ERROR:Device not found'); }"
            "  else {"
            f'    var port = dev.getPort("{safe_iface}");'
            "    if (!port) { reportResult('ERROR:Interface not found'); }"
            "    else if (port.getLink() == null) {"
            "      reportResult('ERROR:No link on this interface');"
            "    } else {"
            "      port.deleteLink();"
            f'      reportResult("OK:link removed from {safe_iface}");'
            "    }"
            "  }"
            "} catch(e) { reportResult('ERROR:' + e); }"
        )
        result = _bridge_send_and_wait(js, timeout=8.0)
        if result is None:
            return "No response from PT."
        if result.startswith("ERROR:"):
            return f"Error: {result[6:]}"
        return f"Link on {device_name}/{interface_name} deleted."

    # ------------------------------------------------------------------
    # VALIDATED BUILDERS — pt_add_device, pt_add_link (MEJORA-01)
    # ------------------------------------------------------------------

    _CABLE_ALIASES: dict[str, str] = {
        "crossover": "cross",
        "cross-over": "cross",
        "copper-crossover": "cross",
        "copper-straight": "straight",
        "straight-through": "straight",
        "rollover": "roll",
        "dce": "serial",
        "serial-dce": "serial",
    }

    @mcp.tool()
    def pt_add_device(
        name: str,
        model: str,
        x: int = 200,
        y: int = 200,
    ) -> str:
        """
        Add a single device to Packet Tracer with validation.
        Checks: name not empty, model exists in catalog, no duplicate name.

        Parameters:
        - name: device name (e.g. "R1", "SW-Core", "PC-Admin")
        - model: PT model type (e.g. "2911", "2960-24TT", "PC-PT", "Server-PT")
        - x: X coordinate on canvas (default 200)
        - y: Y coordinate on canvas (default 200)
        """
        if not name or not name.strip():
            return "ERROR: Device name cannot be empty."

        device_model = resolve_model(model)
        if device_model is None:
            return (
                f"ERROR: Model '{model}' not found in catalog.\n"
                f"Use pt_list_devices to see available models."
            )

        err = _check_bridge()
        if err:
            return err

        safe_name = _js_escape(name.strip())
        js = (
            "try {"
            "  var net = ipc.network();"
            "  var n = net.getDeviceCount();"
            "  for (var i = 0; i < n; i++) {"
            "    if (net.getDeviceAt(i).getName() === '" + safe_name + "') {"
            "      reportResult('ERROR:DUPLICATE:Device \\'" + safe_name + "\\' already exists');"
            "      throw 'dup';"
            "    }"
            "  }"
            f'  addDevice("{safe_name}", "{_js_escape(device_model.pt_type)}", {int(x)}, {int(y)});'
            "  var check = ipc.network().getDevice('" + safe_name + "');"
            "  if (check) {"
            "    reportResult('OK:' + check.getName() + '|' + check.getModel());"
            "  } else {"
            "    reportResult('ERROR:Device was not created (unknown reason)');"
            "  }"
            "} catch(e) { if (e !== 'dup') reportResult('ERROR:' + e); }"
        )
        result = _bridge_send_and_wait(js, timeout=10.0)
        if result is None:
            return _TIMEOUT_MSG
        if result.startswith("ERROR:DUPLICATE:"):
            return result[6:]
        if result.startswith("ERROR:"):
            return f"PT error: {result[6:]}"
        return f"Device '{name}' ({device_model.pt_type}) created at ({x}, {y})."

    @mcp.tool()
    def pt_add_link(
        device1: str,
        port1: str,
        device2: str,
        port2: str,
        cable_type: str = "",
    ) -> str:
        """
        Create a link between two devices in Packet Tracer with full validation.
        Checks: both devices exist, both ports exist, ports are free, cable type is valid.
        If cable_type is omitted, it is inferred from the device categories.

        Parameters:
        - device1: first device name
        - port1: port on device1 (e.g. "GigabitEthernet0/0", "FastEthernet0/1")
        - device2: second device name
        - port2: port on device2
        - cable_type: cable type (straight, cross, serial, fiber, console, roll, auto, etc.)
                      Common aliases accepted: "crossover"→"cross", "rollover"→"roll"
        """
        if cable_type:
            resolved_cable = _CABLE_ALIASES.get(cable_type.lower(), cable_type.lower())
            if resolved_cable not in CABLE_TYPES:
                valid = ", ".join(sorted(CABLE_TYPES.keys()))
                return (
                    f"ERROR: Cable type '{cable_type}' is not valid.\n"
                    f"Valid types: {valid}\n"
                    f"Common aliases: crossover→cross, rollover→roll"
                )
        else:
            resolved_cable = ""

        err = _check_bridge()
        if err:
            return err

        sd1 = _js_escape(device1)
        sp1 = _js_escape(port1)
        sd2 = _js_escape(device2)
        sp2 = _js_escape(port2)

        js = (
            "try {"
            f"  var d1 = ipc.network().getDevice('{sd1}');"
            f"  var d2 = ipc.network().getDevice('{sd2}');"
            f"  if (!d1) {{ reportResult('ERROR:Device \\'{sd1}\\' not found'); throw 'stop'; }}"
            f"  if (!d2) {{ reportResult('ERROR:Device \\'{sd2}\\' not found'); throw 'stop'; }}"
            f"  var p1 = d1.getPort('{sp1}');"
            f"  var p2 = d2.getPort('{sp2}');"
            f"  if (!p1) {{ reportResult('ERROR:Port \\'{sp1}\\' not found on \\'{sd1}\\''); throw 'stop'; }}"
            f"  if (!p2) {{ reportResult('ERROR:Port \\'{sp2}\\' not found on \\'{sd2}\\''); throw 'stop'; }}"
            "  if (p1.getLink() != null) {"
            f"    reportResult('ERROR:Port \\'{sp1}\\' on \\'{sd1}\\' already has a link'); throw 'stop';"
            "  }"
            "  if (p2.getLink() != null) {"
            f"    reportResult('ERROR:Port \\'{sp2}\\' on \\'{sd2}\\' already has a link'); throw 'stop';"
            "  }"
            # getModel() and NOT getClassName(): The PT class does not distinguish a 
            # switch on a router (a 3560 says "Router" because it's multi-layered, and 
            # a 2960 says "CiscoDevice"), so no "switch" category 
            # never reached CABLE_RULES and a switch router↔came out crossed.
            "  reportResult('PRE_OK:' + d1.getModel() + '|' + d2.getModel());"
            "} catch(e) { if (e !== 'stop') reportResult('ERROR:' + e); }"
        )
        pre_result = _bridge_send_and_wait(js, timeout=10.0)
        if pre_result is None:
            return _TIMEOUT_MSG
        if pre_result.startswith("ERROR:"):
            return pre_result
        if not pre_result.startswith("PRE_OK:"):
            return f"Unexpected response: {pre_result}"

        if not resolved_cable:
            parts = pre_result[7:].split("|")
            model1 = parts[0].strip() if len(parts) > 0 else ""
            model2 = parts[1].strip() if len(parts) > 1 else ""
            resolved_cable = infer_cable(
                category_of_model(model1), category_of_model(model2)
            )

        js_link = (
            "try {"
            f'  addLink("{sd1}", "{sp1}", "{sd2}", "{sp2}", "{resolved_cable}");'
            f"  var pCheck = ipc.network().getDevice('{sd1}').getPort('{sp1}');"
            "  if (pCheck && pCheck.getLink() != null) {"
            "    reportResult('OK:link created');"
            "  } else {"
            f"    reportResult('ERROR:addLink returned but link not found on {sp1}');"
            "  }"
            "} catch(e) { reportResult('ERROR:' + e); }"
        )
        link_result = _bridge_send_and_wait(js_link, timeout=10.0)
        if link_result is None:
            return "No response after addLink (timeout)."
        if link_result.startswith("ERROR:"):
            return f"Link creation failed: {link_result[6:]}"
        return f"Link created: {device1}/{port1} <--[{resolved_cable}]--> {device2}/{port2}"

    # ------------------------------------------------------------------
    # RAW JS EXECUTION
    # ------------------------------------------------------------------

    @mcp.tool()
    def pt_set_port(
        device: str,
        interface: str,
        bandwidth: int = 0,
        bandwidth_auto: int = -1,
        full_duplex: int = -1,
        duplex_auto: int = -1,
        description: str = "",
        mac_address: str = "",
        power: int = -1,
        zone_member: str = "",
        proxy_arp: int = -1,
        ike: int = -1,
    ) -> str:
        """
        Configures low-level attributes of a port on a live device in PT. 
        
        Only applies attributes that are explicitly passed (parameters with defaults 
        sentinel). Useful for settings that the CLI does not easily expose or that 
        you want to apply them without entering 'configure terminal'.

        Parameters: 
        - device: name of the device in PT (e.g.: "R1") 
        - interface: name of the interface (e.g. "GigabitEthernet0/0") 
        - Bandwidth: Bandwidth in kbps (>0 to apply; 0 = do not change) 
        - bandwidth_auto: 1 activates BW's auto-negotiate, 0 deactivates it, -1 does not change 
        - full_duplex: 1 full duplex, 0 half duplex, -1 unchanged 
        - duplex_auto: 1 activates duplex auto-deal, 0 disables, -1 does not change 
        - description: descriptive text (empty = does not change) 
        - mac_address: MAC in "AABB. CCDD.EEFF" format (empty = unchanged) 
        - Power: 1 turns on port, 0 turns it off, -1 doesn't change
        - zone_member: Name of the port's security zone, for Zone-Based 
        Firewall (empty = unchanged). Router interfaces only. 
        - proxy_arp: 1 activates ARP Proxy, 0 disables it, -1 does not change. 
        Turn it off is usual hardening: with ARP Proxy the router responds to 
        ARPs that do not are yours and filters information from the topology. 
        - ike: 1 enables IKE on the interface (IPsec VPN), 0 disables it, -1 does not change.

        Returns which attributes were applied (those that had method available in 
        port API). If any 'setXxx' does not exist in the device model, it is silently 
        ignored and only what did hit is reported.
        """
        err = _check_bridge()
        if err:
            return err

        parts = [
            'var d=ipc.network().getDevice(' + json.dumps(device) + ');',
            'if(!d){reportResult(JSON.stringify({success:false,error:"device not found: ' + _js_escape(device) + '"}));return;}',
            'var p=d.getPort(' + json.dumps(interface) + ');',
            'if(!p){reportResult(JSON.stringify({success:false,error:"port not found: ' + _js_escape(interface) + '"}));return;}',
            'var applied=[];',
        ]

        if bandwidth and bandwidth > 0:
            parts.append(
                f'if(typeof p.setBandwidth==="function"){{p.setBandwidth({int(bandwidth)});applied.push("bandwidth={int(bandwidth)}");}}'
            )
        if bandwidth_auto in (0, 1):
            v = "true" if bandwidth_auto == 1 else "false"
            parts.append(
                f'if(typeof p.setBandwidthAutoNegotiate==="function"){{p.setBandwidthAutoNegotiate({v});applied.push("bandwidth_auto={v}");}}'
            )
        if full_duplex in (0, 1):
            v = "true" if full_duplex == 1 else "false"
            parts.append(
                f'if(typeof p.setFullDuplex==="function"){{p.setFullDuplex({v});applied.push("full_duplex={v}");}}'
            )
        if duplex_auto in (0, 1):
            v = "true" if duplex_auto == 1 else "false"
            parts.append(
                f'if(typeof p.setDuplexAutoNegotiate==="function"){{p.setDuplexAutoNegotiate({v});applied.push("duplex_auto={v}");}}'
            )
        if description:
            parts.append(
                f'if(typeof p.setDescription==="function"){{p.setDescription({json.dumps(description)});applied.push("description");}}'
            )
        if mac_address:
            parts.append(
                f'if(typeof p.setMacAddress==="function"){{p.setMacAddress({json.dumps(mac_address)});applied.push("mac");}}'
            )
        if power in (0, 1):
            v = "true" if power == 1 else "false"
            parts.append(
                f'if(typeof p.setPower==="function"){{p.setPower({v});applied.push("power={v}");}}'
            )

        # Zone-Based Firewall / ARP / IKE Proxy – only exist on ports of 
        # router, so the typeof is not too defensive — on a switch or a 
        # host these setters are not there and calling them would open a modal.
        if zone_member:
            parts.append(
                f'if(typeof p.setZoneMemberName==="function"){{p.setZoneMemberName({json.dumps(zone_member)});applied.push("zone_member");}}'
            )
        if proxy_arp in (0, 1):
            v = "true" if proxy_arp == 1 else "false"
            parts.append(
                f'if(typeof p.setProxyArpEnabled==="function"){{p.setProxyArpEnabled({v});applied.push("proxy_arp={v}");}}'
            )
        if ike in (0, 1):
            v = "true" if ike == 1 else "false"
            parts.append(
                f'if(typeof p.setIkeEnabled==="function"){{p.setIkeEnabled({v});applied.push("ike={v}");}}'
            )

        parts.append('reportResult(JSON.stringify({success:true,applied:applied}));')

        # IIFE for early returns to work in the PT Script Engine.
        js = '(function(){' + ''.join(parts) + '})()'

        result = _bridge_send_and_wait(js, timeout=8.0)
        if result is None:
            return "No response from PT."
        try:
            data = json.loads(result)
            if data.get("success"):
                applied = data.get("applied", [])
                if not applied:
                    return (
                        f"Nothing was applied in {device}/{interface}: "
                        "No attributes were passed or no setXxx is available on this model."
                    )
                return f"Applied in {device}/{interface}: " + ", ".join(applied)
            return f"Error: {data.get('error', 'unknown')}"
        except Exception:
            return f"Unexpected response: {result}"

    @mcp.tool()
    def pt_send_raw(js_code: str, wait_result: bool = False) -> str:
        """
        Send arbitrary JavaScript to Packet Tracer via bridge.
        Useful for exploring the IPC API or running custom commands.

        If wait_result=True, reportResult() is auto-injected into scope.
        Just call reportResult(data) in your code — no need to define it.
        Examples:
          pt_send_raw("reportResult(getDevices('router'))", wait_result=True)
          pt_send_raw("addDevice('TestR','2911',500,300)")

        Parameters:
        - js_code: JavaScript to execute in PT's Script Engine
        - wait_result: if True, waits for a response via reportResult()
        """
        err = _check_bridge()
        if err:
            return err

        if wait_result:
            result = _bridge_send_and_wait(js_code, timeout=10.0)
            if result is None:
                return "No response (timeout). Make sure the code calls reportResult(...)."
            return result
        else:
            if _channel_send(_js_guard(js_code)):
                return "Command sent to PT."
            return "Error sending command to the bridge."

    # ------------------------------------------------------------------
    # MODULES — Install Expansion Modules on Living Devices
    # ------------------------------------------------------------------

    @mcp.tool()
    def pt_list_modules(
        router_model: str = "",
        category: str = "",
    ) -> str:
        """
        List of available expansion modules from the PT catalog. 
        
        Unfiltered: returns ALL modules. Useful for discovering names 
        before calling pt_add_module. 
        
        Parameters: 
        - router_model: If specified (e.g., "2911", "ISR4321"), 
        it filters to modules compatible with that router. Includes generic 
        modules (without list compatible_with) and those that list that model. 
        - category: filter by category (e.g.: "router_hwic", "router_nm", 
        "router_nim", "router_wic"). Void = all. 
        
        Returns JSON with: name, description, category, ports_added, compatible_with.
        """
        rm = (router_model or "").strip()
        cat = (category or "").strip().lower()

        items = []
        for mod in ALL_MODULES.values():
            if cat and mod.category.lower() != cat:
                continue
            if rm and mod.compatible_with and rm not in mod.compatible_with:
                continue
            items.append({
                "name": mod.name,
                "description": mod.description,
                "category": mod.category,
                "module_type": mod.module_type,
                "ports_added": list(mod.ports_added),
                "compatible_with": list(mod.compatible_with) if mod.compatible_with else "any",
            })

        items.sort(key=lambda x: (x["category"], x["name"]))
        return json.dumps({
            "count": len(items),
            "filter": {"router_model": rm or None, "category": cat or None},
            "modules": items,
        }, indent=2, ensure_ascii=False)

    @mcp.tool()
    def pt_add_module(
        device_name: str,
        slot: str,
        module_name: str,
        dry_run: bool = False,
    ) -> str:
        """
        Installs an expansion module on a device in the active topology. 
        
        The runtime patch already injected into PT shuts down the device, 
        installs the module and turn it back on (with skipBoot). You do 
        NOT need to turn off by hand.

        Parameters: 
        - device_name: exact name of the device in PT (e.g.: "R1"). 
        Use pt_query_topology to list valid names. 
        - slot: Identifier of the slot as STRING. The format depends on 
        the Device slot type: 
        * HWIC at 2911/2901 → "0/0".." 0/3" · in 1941 ONLY "0/0" and "0/1" 
        (verified against PT 9.0.1: 1941 has 2 slots, not 4) 
        (chassis-slot/hwic-subslot) 
        * NM in 2811/2620XM/Router-PT → "1" 
        * NIM in ISR4321/4331 → "0/1", "0/2" (chassis/subslot — NOT "0"/"1") 
        * Cloud-PT/Server-PT/PCs → "0", "1",... depending on the available 
        slot If you pass an integer it is also accepted and converted to string. 
        - module_name: exact name of the module, e.g. "HWIC-2T", "NM-4A/S", 
        "NIM-2T", "HWIC-1GE-SFP". Use pt_list_modules to discover them. 
        - dry_run: If True, it validates and returns the JS payload without sending it.

        Example: Adding 2 serial ports to R1 in HWIC slot 0: 
        pt_add_module(device_name="R1", slot="0/0", module_name="HWIC-2T")
        """
        # Convert slot to string (accepts int for compatibility) and validate non-empty
        if isinstance(slot, bool) or slot is None:
            return f"Error: invalid slot (received: {slot!r})."
        slot_s = str(slot).strip()
        if not slot_s:
            return "Error: slot cannot be empty."

        # Validate Module Name
        spec = resolve_module(module_name)
        if not spec:
            return (
                f"Error: module '{module_name}' not found in the catalog.\n" 
                f"Call pt_list_modules to see valid names."
            )

        # Build JS payload
        safe_name = _js_escape(device_name)
        safe_module = _js_escape(spec.name)
        safe_slot = _js_escape(slot_s)
        # The ports have the slot in the name, so you have to calculate them 
        # for THIS slot: the catalog lists them for the first one in the family.
        slot_ports = ports_for_slot(spec, slot_s)
        ports_added = ", ".join(slot_ports) if slot_ports else "(No Ports)"

        if dry_run:
            return json.dumps({
                "summary": f"[dry_run] Payload generated to install {spec.name} in {device_name} slot {slot_s}.",
                "device": device_name,
                "slot": slot_s,
                "module": spec.name,
                "description": spec.description,
                "ports_added": slot_ports,
                "compatible_with": list(spec.compatible_with) if spec.compatible_with else "any",
                "js_payload": f'addModule("{safe_name}", "{safe_slot}", "{safe_module}")',
                "sent": False,
                "dry_run": True,
            }, indent=2, ensure_ascii=False)

        # Check Bridge + PT
        err = _check_bridge()
        if err:
            return err

        # Verify that the device exists and validate compatibility
        devices = _query_pt_devices()
        if devices:
            target = next((d for d in devices if d.get("name") == device_name), None)
            if target is None:
                names = sorted({d.get("name", "") for d in devices if d.get("name")})
                return (
                    f"Error: device '{device_name}' does not exist in PT.\n" 
                    f"Current devices: {', '.join(names) or '(none)'}"
                )
            if spec.compatible_with:
                target_model = target.get("model", "") or ""
                if target_model and target_model not in spec.compatible_with:
                    return (
                        f"Error: module '{spec.name}' is not compatible with model '{target_model}'.\n" 
                        f"Compatible with: {', '.join(spec.compatible_with)}"
                    )

        # Send to bridge — the patch runtime handles the power cycle automatically. 
        # We wait for a response to confirm success (installation takes a few seconds).
        js = (
            f'var __ok = addModule("{safe_name}", "{safe_slot}", "{safe_module}"); '
            f'return JSON.stringify({{success: __ok === true, returned: __ok}});'
        )
        result = _bridge_send_and_wait(js, timeout=15.0)

        if result is None:
            return (
                f"No response from PT (timeout). Possible causes:\n" 
                f" - The module is still being installed (power cycle may take time)\n" 
                f" - The module name does not exist in PT\n's allModuleTypes" 
                f" - The slot '{slot_s}' is already occupied or does not exist\n" 
                f"Manually check with pt_query_topology."
            )

        try:
            data = json.loads(result)
            success = bool(data.get("success"))
        except Exception:
            return f"Unexpected response from PT: {result}"

        if success:
            return (
                f"Module installed in {device_name}.\n" 
                f" Slot: {slot_s}\n" 
                f" Module: {spec.name} — {spec.description}\n" 
                f" Added ports: {ports_added}\n" 
                f" PT turned the device off/on automatically."
            )
        return (
            f"PT rejected the installation of '{spec.name}' in {device_name} slot '{slot_s}'.\n" 
            f"Usual causes:\n" 
            f" - Slot occupied by another module\n" 
            f" - Module incompatible with the device model\n" 
            f" - Slot out of range or incorrect format (HWIC: '0/0', NM: '1', NIM: '0/1')"
        )

    @mcp.tool()
    def pt_install_modules_batch(
        modules: list[dict],
        dry_run: bool = False,
    ) -> str:
        """
        Install N modules in a single JS runCode — power-off → addModule×N → power-on. 
        
        Useful when multiple serial modules (HWIC-2T, NIM-2T, etc.) need to be put 
        into the multiple routers at once. PREFER this tool over multiple calls to 
        pt_add_module: Each individual power-cycle can pause the PT script engine > 5s 
        and kill the bridge bootstrap polling.

        Parameters: 
        - modules: list of dicts with {device, slot, module}. Example for RTR-4 with
        4 serial ports on a 2911 (which does NOT accept NM-4A/S): 
            [ 
                {"device": "RTR-4", "slot": "0/0", "module": "HWIC-2T"}, 
                {"device": "RTR-4", "slot": "0/1", "module": "HWIC-2T"} 
            ] 
          → generates Serial0/0/0..0/0/1, Serial0/1/0..0/1/1. 
        - dry_run: If True, it validates and returns the JS payload without sending it.

        Slot rules (string): 
            HWIC at 2911/2901 → "0/0".." 0/3" · in 1941 ONLY "0/0" and "0/1" 
            NIM in ISR4321/4331 → "0/1", "0/2" (chassis/subslot — NOT "0"/"1") 
            NM en 2811/Router-PT → "1" Cloud-PT / hosts → "0".." 7" 
            
        Return JSON with summary, status per module, and js_payload.
        """
        if not isinstance(modules, list) or not modules:
            return json.dumps({"error": "modules should be non-empty list of {device, slot, module}."})

        # Validate each entry against the catalog
        validated = []
        errors = []
        for idx, entry in enumerate(modules):
            if not isinstance(entry, dict):
                errors.append(f"[{idx}] is not dict")
                continue
            dev = entry.get("device")
            slot = entry.get("slot")
            mod = entry.get("module")
            if not dev or not isinstance(dev, str):
                errors.append(f"[{idx}] device required (str)")
                continue
            if slot is None or isinstance(slot, bool):
                errors.append(f"[{idx}] slot required")
                continue
            slot_s = str(slot).strip()
            if not slot_s:
                errors.append(f"[{idx}] empty slot")
                continue
            if not mod or not isinstance(mod, str):
                errors.append(f"[{idx}] module required (str)")
                continue
            spec = resolve_module(mod)
            if not spec:
                errors.append(f"[{idx}] module '{mod}' does not exist (uses pt_list_modules)")
                continue
            validated.append({
                "device": dev, "slot": slot_s,
                "module": spec.name,
                # Per slot, not from the catalog: two HWIC-2T in "0/0" and "0/1" give 
                # different ports, and before both were reported as 0/0.
                "ports_added": ports_for_slot(spec, slot_s),
                "compatible_with": list(spec.compatible_with) if spec.compatible_with else None,
            })

        if errors:
            return json.dumps({
                "error": "Validation failed",
                "details": errors,
            }, indent=2, ensure_ascii=False)

        # Build a single JS one-liner: power-off of unique devices → addModule × N → power-on
        unique_devs = []
        seen = set()
        for v in validated:
            if v["device"] not in seen:
                seen.add(v["device"])
                unique_devs.append(v["device"])

        # JS literal arrays for devices and modules
        devs_js = "[" + ",".join(f'"{_js_escape(d)}"' for d in unique_devs) + "]"
        mods_js = "[" + ",".join(
            f'["{_js_escape(v["device"])}","{_js_escape(v["slot"])}","{_js_escape(v["module"])}"]'
            for v in validated
        ) + "]"

        js = (
            f"var DEVS={devs_js};var MODS={mods_js};"
            "var saved=[];"
            "for(var i=0;i<DEVS.length;i++){"
            "var d=ipc.network().getDevice(DEVS[i]);"
            "if(!d)continue;"
            "var hp=typeof d.getPower===\"function\";"
            "var was=hp?d.getPower():false;"
            "if(hp&&was)d.setPower(false);"
            "saved.push({n:DEVS[i],hp:hp,was:was});"
            "}"
            # addModule returns false when the slot does not exist in that model 
            # (a 1941 doesn't have HWIC 0/2) and PT doesn't pitch – misses silently. Without 
            # look at the return, the tool reported ports that were never created.
            "var res=[];"
            "for(var j=0;j<MODS.length;j++){"
            "var m=MODS[j];var dd=ipc.network().getDevice(m[0]);"
            "if(!dd){res.push(m[0]+'|'+m[1]+'|nodev');continue;}"
            "var ok=false;"
            "try{ok=dd.addModule(m[1],allModuleTypes[m[2]],m[2]);}catch(e){ok=false;}"
            "res.push(m[0]+'|'+m[1]+'|'+(ok?'ok':'fail'));"
            "}"
            # Reported BEFORE power-on purpose: turning on is what 
            # delays, and waiting for it was the reason this was fire-and-forget.
            "reportResult(res.join(';'));"
            "for(var k=0;k<saved.length;k++){"
            "var s=saved[k];if(!s.hp||!s.was)continue;"
            "var dx=ipc.network().getDevice(s.n);if(!dx)continue;"
            "dx.setPower(true);"
            "if(typeof dx.skipBoot===\"function\")dx.skipBoot();"
            "}"
        )

        summary = {
            "total_modules": len(validated),
            "devices_affected": unique_devs,
            "modules": validated,
            "js_payload": js,
            "dry_run": dry_run,
            "sent": False,
        }

        if dry_run:
            summary["summary"] = f"[dry_run] {len(validated)} module(s) in {len(unique_devs)} device(s)."
            return json.dumps(summary, indent=2, ensure_ascii=False)

        err = _check_bridge()
        if err:
            return err

        # Verify existing devices + validate module compatibility
        pt_devices = _query_pt_devices()
        if pt_devices:
            by_name = {d.get("name"): d for d in pt_devices}
            for v in validated:
                if v["device"] not in by_name:
                    return f"Error: device '{v['device']}' does not exist in PT."
                if v["compatible_with"]:
                    target_model = by_name[v["device"]].get("model", "") or ""
                    if target_model and target_model not in v["compatible_with"]:
                        return (
                            f"Error: module '{v['module']}' incompatible with model "
                            f"'{target_model}' (device '{v['device']}').\n" 
                            f"Compatible with: {', '.join(v['compatible_with'])}"
                        )

        # The result is expected: the JS reports before powering on, so the 
        # Power-On—what used to force Fire-and-Forget—no longer counts.
        raw = _bridge_send_and_wait(js, timeout=20.0)
        if raw is None:
            summary["sent"] = True
            summary["verified"] = False
            summary["summary"] = (
                f"Batch sent ({len(validated)} module(s)) but PT did not commit in time.\n" 
                "Check with pt_query_topology which ones were installed."
            )
            return json.dumps(summary, indent=2, ensure_ascii=False)

        # "R1|0/0|ok; R1|0/2|fail" — a non-existent slot for the model returns 
        # false without launching, so without this ghost ports were reported.
        status: dict[tuple[str, str], str] = {}
        for chunk in raw.split(";"):
            parts = chunk.split("|")
            if len(parts) == 3:
                status[(parts[0], parts[1])] = parts[2]

        failed = []
        for v in validated:
            state = status.get((v["device"], v["slot"]), "unknown")
            v["installed"] = state == "ok"
            if state != "ok":
                v["ports_added"] = []
                failed.append(f"{v['device']} slot {v['slot']} ({v['module']})")

        summary["sent"] = True
        summary["verified"] = True
        summary["installed_count"] = sum(1 for v in validated if v.get("installed"))
        if failed:
            summary["failed"] = failed
            summary["summary"] = (
                f"{summary['installed_count']}/{len(validated)} installed module(s). "
                f"PT rejected: {', '.join(failed)}.\n" 
                "That slot doesn't exist in that model — check pt_list_modules and the "
                "Correct slot for the router family."
            )
            return json.dumps(summary, indent=2, ensure_ascii=False)

        summary["summary"] = (
            f"Batch sent: {len(validated)} module(s) in {len(unique_devs)} device(s).\n" 
            f"PT is shutting down, installing, and relighting in one step. "
            f"Check with pt_query_topology or by querying getPorts() on each router."
        )
        return json.dumps(summary, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # ACL — apply and remove Access Control Lists via bridge
    # ------------------------------------------------------------------

    # JS that reads the active topology and returns it as structured JSON. 
    # Replaces the old 'queryTopology()' that was NEVER defined/injected (the so-called 
    # always returned PT_ERROR → empty list → the compatibility pre-validations of 
    # modules and ACL/NAT against PT were silently disabled). JSON.stringify 
    # is available on the PT Script Engine (live verified). isPortUp()/getLink() 
    # feed the health-check and diff. Each port is saved with its name as it is 
    # (includes "Gig0/0.10" sub-interfaces if they exist).
    _LIVE_DEVICES_JS = (
        "var net=ipc.network();var n=net.getDeviceCount();var arr=[];"
        "for(var i=0;i<n;i++){"
        "var d=net.getDeviceAt(i);var pc=d.getPortCount();var ports=[];"
        "for(var j=0;j<pc;j++){"
        "var p=d.getPortAt(j);var ip='';var mask='';var up=false;var linked=false;"
        "try{ip=p.getIpAddress()||'';}catch(pe){}"
        "try{mask=p.getSubnetMask()||'';}catch(pe){}"
        "try{up=(typeof p.isPortUp==='function')?p.isPortUp():false;}catch(pe){}"
        "try{linked=(p.getLink()!=null);}catch(pe){}"
        "ports.push({name:p.getName(),ip:ip,mask:mask,up:up,linked:linked});"
        "}"
        "arr.push({name:d.getName(),model:d.getModel(),ports:ports});"
        "}"
        "reportResult(JSON.stringify({devices:arr,links:net.getLinkCount()}));"
    )

    def _live_devices() -> list[dict]:
        """Reads the active PT topology as a structured list of devices. 
        
        Cada elemento: {name, model, ports:[{name, ip, mask, up, linked}]}. 
        Single source of truth for pre-checks (compat modules, ACL/NAT), 
        pt_diff and pt_health_check. Returns [] if the bridge is unresponsive or PT fails.
        """
        result = _bridge_send_and_wait(_LIVE_DEVICES_JS, timeout=10.0)
        if not result or result.startswith("PT_ERROR") or result.startswith("ERROR"):
            return []
        try:
            data = json.loads(result)
            return data.get("devices", []) or []
        except Exception:
            return []

    def _query_pt_devices() -> list[dict]:
        """Alias compat de _live_devices (name used by module/ACL/NAT pre-checks)."""
        return _live_devices()

    def _bridge_send_payload(js_call: str) -> bool:
        """Sends a JS payload fire-and-forget over the available channel (HTTP or file)."""
        return _channel_send(_js_guard(js_call))

    @mcp.tool()
    def pt_apply_acl(
        router: str,
        name_or_number: str,
        acl_type: str,
        entries: list[dict],
        binding_interface: str = "",
        binding_direction: str = "in",
        dry_run: bool = False,
    ) -> str:
        """
        Applies an Access Control List (ACL) to a router in the active PT topology. 
        
        Pipeline: builds plan → validates static (ranges, types, IPs/wildcards, 
        unreachable rules) → verifies router/interface against PT via bridge → 
        generates IOS CLI → sent via configureIosDevice.

        Parameters: 
        - router: name of the device in PT (e.g., "CORE-R1"). Call 
        pt_query_topology if you're not sure of the exact names. 
        - name_or_number: IOS identifier of the ACL. 
        * 1-99 or 1300-1999 → standard 
        * 100-199 or 2000-2699 → extended 
        * any alphanumeric string → named ACL 
        - acl_type: "standard" or "extended". Standard only filters by source. 
        Extended allows source + destination + protocol + ports.
        - entries: list of rules. Each rule is a dict with: 
        * action: "permit" | "deny" (required) 
        * protocol: "ip" | "icmp" | "tcp" | "udp" |... (default "ip") 
        * Source: "any" | "host A.B.C.D" | "A.B.C.D wildcard" (required) 
        * destination: same as source (solo extended) 
        * source_port_op/source_port: e.g. "EQ"/80 (TCP/UDP, optional) 
        * dest_port_op/dest_port/dest_port_end: Same (optional) 
        * icmp_type: "echo" | "echo-reply" |... (ICMP only) 
        * tcp_flags: ["established"] | ["syn"] (TCP only, optional) 
        * log: bool (optional) 
        * Remark: Optional comment
        - binding_interface: If specified, applies the ACL to that interface 
        (e.g., "GigabitEthernet0/0"). If empty, only the unapplied ACL is defined. 
        - binding_direction: "in" or "out" (default "in"). Only applies if 
        binding_interface is defined. 
        - dry_run: if True, it does NOT send anything to the bridge — it only validates 
        and returns the CLI/JS payload for inspection.

        Example: Ping from 192.168.1.0/24 to 192.168.0.0/24 in CORE-R1: 
          pt_apply_acl(
              router="CORE-R1",
              name_or_number="101",
              acl_type="extended",
              entries=[
                  {"action": "deny", "protocol": "icmp",
                   "source": "192.168.1.0 0.0.0.255",
                   "destination": "192.168.0.0 0.0.0.255",
                   "icmp_type": "echo"},
                  {"action": "permit", "protocol": "ip",
                   "source": "any", "destination": "any"},
              ],
              binding_interface="GigabitEthernet0/0",
              binding_direction="in",
          )
        """
        plan = build_acl_plan(router, name_or_number, acl_type, entries)
        binding = None
        if binding_interface:
            binding = ACLBinding(
                router=router,
                interface=binding_interface,
                acl_id=str(name_or_number),
                direction=binding_direction,
            )

        # Only query PT if the bridge is connected (dynamic validation)
        bridge_ok = _pick_channel() != ""
        query_fn = _query_pt_devices if bridge_ok else None
        send_fn = _bridge_send_payload if bridge_ok and not dry_run else None

        result = apply_acl_uc(
            plan=plan,
            binding=binding,
            query_pt_topology=query_fn,
            bridge_send=send_fn,
            dry_run=dry_run,
        )

        # Friendly summary
        summary_lines = []
        if result["valid"]:
            summary_lines.append(f" ✅ ACL '{plan.name_or_number}' valid ({len(plan.entries)} rules).")
        else:
            summary_lines.append(f" ❌ ACL '{plan.name_or_number}' has {len(result['errors'])} error(es).")

        if dry_run:
            summary_lines.append("Mode dry_run — NOT sent to the bridge.")
        elif result["sent"]:
            summary_lines.append(f" 📤 Applied to '{router}' via bridge (configureIosDevice).")
            if binding:
                summary_lines.append(f"   Binding: {binding.interface} {binding.direction}")
        elif result["valid"] and not bridge_ok:
            summary_lines.append(" ⚠ Bridge not connected — payload generated but NOT sent.")
        elif result["valid"] and not result["sent"]:
            summary_lines.append(" ⚠ Bridge OK but send failed.")

        return json.dumps({
            "summary": "\n".join(summary_lines),
            "valid": result["valid"],
            "errors": result["errors"],
            "warnings": result["warnings"],
            "cli_lines": result["cli_lines"],
            "js_payload": result["js_payload"],
            "sent": result["sent"],
            "dry_run": result["dry_run"],
        }, indent=2, ensure_ascii=False)

    @mcp.tool()
    def pt_apply_acl_object(
        router: str,
        name_or_number: str,
        acl_type: str,
        entries: list[dict],
        binding_interface: str = "",
        binding_direction: str = "in",
        replace_existing: bool = True,
        dry_run: bool = False,
    ) -> str:
        """
        Apply an ACL using the PT Object API (AclProcess.addAcl/addStatement) 
        instead of CLI via configureIosDevice. 
        
        Same input as pt_apply_acl. It's faster (no CLI parsing) and less 
        prone to throwing bridge-breaking modal popups if a line goes wrong. 
        
        Limitation: Binding only works on physical ports in the catalog (e.g. 
        GigabitEthernet0/0). For sub-interfaces (G0/0/1.20) use pt_apply_acl (CLI), 
        since port.setAclInID only applies to the base port and not to the sub-interface. 
        
        Pipeline: Validate plan → generate statements (without "access-list NAME" prefix) 
        → run addAcl + addStatement one by one + optional binding.
        """
        plan = build_acl_plan(router, name_or_number, acl_type, entries)
        binding = None
        if binding_interface:
            binding = ACLBinding(
                router=router,
                interface=binding_interface,
                acl_id=str(name_or_number),
                direction=binding_direction,
            )

        bridge_ok = _pick_channel() != ""

        # Static + Topological Validation
        query_fn = _query_pt_devices if bridge_ok else None
        result = apply_acl_uc(
            plan=plan,
            binding=binding,
            query_pt_topology=query_fn,
            bridge_send=None, # we don't ship by CLI — we build our own JS 
            dry_run=True, # validate without sending
        )

        if not result["valid"]:
            return json.dumps({
                "summary": f" ❌ ACL '{plan.name_or_number}' has {len(result['errors'])} error(es).",
                "valid": False,
                "errors": result["errors"],
                "warnings": result["warnings"],
                "sent": False,
                "dry_run": dry_run,
                "backend": "objects",
            }, indent=2, ensure_ascii=False)

        # Convert CLI lines to statements (without the "access-list NAME" prefix)
        cli_lines = generate_acl_cli(plan)
        prefix = f"access-list {plan.name_or_number} "
        statements = [ln[len(prefix):] for ln in cli_lines if ln.startswith(prefix)]

        # Build JS for AclProcess.addAcl + addStatement
        name_js = json.dumps(str(plan.name_or_number))
        router_js = json.dumps(router)
        stmts_js = "[" + ",".join(json.dumps(s) for s in statements) + "]"

        js_lines = [
            f"var d=ipc.network().getDevice({router_js});",
            'if(!d){reportResult(JSON.stringify({success:false,error:"router not found"}));return;}',
            'var ap=d.getProcess("AclProcess");',
            'if(!ap){reportResult(JSON.stringify({success:false,error:"AclProcess not available"}));return;}',
        ]
        if replace_existing:
            js_lines.append(f"try{{ap.removeAcl({name_js});}}catch(e){{}}")
        js_lines.extend([
            f"ap.addAcl({name_js});",
            f"var acl=ap.getAcl({name_js});",
            'if(!acl){reportResult(JSON.stringify({success:false,error:"addAcl failed"}));return;}',
            f"var stmts={stmts_js};",
            'var added=0;for(var i=0;i<stmts.length;i++){if(acl.addStatement(stmts[i]))added++;}',
        ])

        bound = "none"
        if binding:
            iface_js = json.dumps(binding.interface)
            setter = "setAclInID" if binding.direction == "in" else "setAclOutID"
            js_lines.extend([
                f"var p=d.getPort({iface_js});",
                f'if(p){{p.{setter}({name_js});}}',
            ])
            bound = f"{binding.interface} {binding.direction}"

        js_lines.append(
            'reportResult(JSON.stringify({success:true,added:added,cmdCount:acl.getCommandCount()}));'
        )

        js = "(function(){" + "".join(js_lines) + "})()"

        payload = {
            "summary": "",
            "valid": True,
            "errors": [],
            "warnings": result["warnings"],
            "cli_lines": cli_lines,
            "statements": statements,
            "js_payload": js,
            "binding": bound,
            "sent": False,
            "dry_run": dry_run,
            "backend": "objects",
        }

        if dry_run:
            payload["summary"] = (
                f"[dry_run] ACL '{plan.name_or_number}' lista: "
                f"{len(statements)} statement(s) + binding={bound}. JS NO enviado."
            )
            return json.dumps(payload, indent=2, ensure_ascii=False)

        if not bridge_ok:
            payload["summary"] = "⚠ Bridge not connected—payload generated but NOT sent."
            return json.dumps(payload, indent=2, ensure_ascii=False)

        response = _bridge_send_and_wait(js, timeout=10.0)
        if response is None:
            payload["summary"] = "No response from PT."
            return json.dumps(payload, indent=2, ensure_ascii=False)

        try:
            r = json.loads(response)
            if r.get("success"):
                payload["sent"] = True
                payload["added"] = r.get("added")
                payload["cmd_count"] = r.get("cmdCount")
                payload["summary"] = (
                    f" 📤 ACL '{plan.name_or_number}' applied on '{router}' via AclProcess "
                    f"({r.get('added')}/{len(statements)} statements). Binding={bound}."
                )
            else:
                payload["summary"] = f"Error PT: {r.get('error', 'unknown')}"
        except Exception:
            payload["summary"] = f"Unexpected response: {response}"

        return json.dumps(payload, indent=2, ensure_ascii=False)

    @mcp.tool()
    def pt_remove_acl_object(
        router: str,
        name_or_number: str,
        binding_interface: str = "",
        binding_direction: str = "in",
        dry_run: bool = False,
    ) -> str:
        """
        Delete an ACL using the Object API (AclProcess.removeAcl + Port.setAclInID=""). 
        
        Alternative to pt_remove_acl (CLI). If binding_interface specified, 
        first cleans the AclInID/AclOutID of the port and then removes the ACL. 
        
        Parameters: 
        - router: name of the device in PT 
        - name_or_number: identifier of the ACL to be removed 
        - binding_interface: optional, interface where the binding was 
        - binding_direction: "in" or "out" (only if binding_interface) 
        - dry_run: If True, it returns payload without sending it
        """
        bridge_ok = _pick_channel() != ""

        name_js = json.dumps(str(name_or_number))
        router_js = json.dumps(router)

        js_lines = [
            f"var d=ipc.network().getDevice({router_js});",
            'if(!d){reportResult(JSON.stringify({success:false,error:"router not found"}));return;}',
            'var ap=d.getProcess("AclProcess");',
            'if(!ap){reportResult(JSON.stringify({success:false,error:"AclProcess not available"}));return;}',
        ]

        bound_label = "none"
        if binding_interface:
            iface_js = json.dumps(binding_interface)
            setter = "setAclInID" if binding_direction == "in" else "setAclOutID"
            js_lines.extend([
                f"var p=d.getPort({iface_js});",
                f'if(p){{p.{setter}("");}}',
            ])
            bound_label = f"{binding_interface} {binding_direction}"

        js_lines.extend([
            f"var removed=ap.removeAcl({name_js});",
            'reportResult(JSON.stringify({success:true,removed:removed}));',
        ])

        js = "(function(){" + "".join(js_lines) + "})()"

        payload = {
            "summary": "",
            "router": router,
            "acl_id": str(name_or_number),
            "binding": bound_label,
            "js_payload": js,
            "sent": False,
            "dry_run": dry_run,
            "backend": "objects",
        }

        if dry_run:
            payload["summary"] = (
                f"[dry_run] payload generated to remove ACL '{name_or_number}' "
                f"en '{router}' (binding={bound_label}). NOT sent."
            )
            return json.dumps(payload, indent=2, ensure_ascii=False)

        if not bridge_ok:
            payload["summary"] = "⚠ Bridge not connected—payload generated but NOT sent."
            return json.dumps(payload, indent=2, ensure_ascii=False)

        response = _bridge_send_and_wait(js, timeout=10.0)
        if response is None:
            payload["summary"] = "No response from PT."
            return json.dumps(payload, indent=2, ensure_ascii=False)

        try:
            r = json.loads(response)
            if r.get("success"):
                payload["sent"] = True
                payload["removed"] = r.get("removed")
                payload["summary"] = (
                    f" 📤 ACL '{name_or_number}' removed in '{router}' via AclProcess "
                    f"(removed={r.get('removed')}, binding={bound_label})."
                )
            else:
                payload["summary"] = f"Error PT: {r.get('error', 'unknown')}"
        except Exception:
            payload["summary"] = f"Unexpected response: {response}"

        return json.dumps(payload, indent=2, ensure_ascii=False)

    @mcp.tool()
    def pt_remove_acl(
        router: str,
        name_or_number: str,
        binding_interface: str = "",
        binding_direction: str = "in",
        dry_run: bool = False,
    ) -> str:
        """
        Removes an ACL applied to a router. 
        
        If binding_interface is specified, first remove the binding from the 
        interface (no ip access-group...) and then deletes the entire ACL 
        (no access-list...). 
        
        Parameters: 
        - router: name of the device in PT 
        - name_or_number: identifier of the ACL to be removed 
        - binding_interface: optional, interface where it was applied 
        - binding_direction: "in" or "out" (only if binding_interface) 
        - dry_run: If True, it returns payload without sending it
        """
        bridge_ok = _pick_channel() != ""
        send_fn = _bridge_send_payload if bridge_ok and not dry_run else None

        result = remove_acl_uc(
            router=router,
            name_or_number=name_or_number,
            binding_interface=binding_interface,
            direction=binding_direction,
            bridge_send=send_fn,
            dry_run=dry_run,
        )

        summary = []
        if dry_run:
            summary.append(f"Mode dry_run — payload generated to remove ACL '{name_or_number}' in '{router}'.") 
        elif result["sent"]: 
            summary.append(f" 📤 ACL '{name_or_number}' removed in '{router}' via bridge.") 
        elif not bridge_ok: 
            summary.append(" ⚠ Bridge not connected — payload generated but NOT sent.") 
        else: 
            summary.append("⚠ Submission failed.")

        return json.dumps({
            "summary": "\n".join(summary),
            "router": result["router"],
            "acl_id": result["acl_id"],
            "js_payload": result["js_payload"],
            "sent": result["sent"],
            "dry_run": result["dry_run"],
        }, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # NAT/PAT — apply and remove address translation via bridge
    # ------------------------------------------------------------------

    @mcp.tool()
    def pt_apply_nat(
        router: str,
        mode: str,
        inside_interface: str,
        outside_interface: str,
        static_mappings: list[dict] | None = None,
        inside_networks: list[str] | None = None,
        acl_number: str = "1",
        pool_name: str = "NAT-POOL",
        pool_start: str = "",
        pool_end: str = "",
        pool_netmask: str = "",
        use_interface_overload: bool = False,
        dry_run: bool = False,
    ) -> str:
        """
        Applies NAT or PAT to a router in the active Packet Tracer topology. 
        
        ── WHEN TO USE EACH MODE ────────────────────────────────────────────── 
        
        mode="static" — Static NAT (1 to 1, permanent) 
        Each private IP is ALWAYS mapped to the same public IP. 
        Use when an internal server (web, FTP, mail) should be reachable 
        from the Internet with a known fixed public IP. 
        Requires: static_mappings = [{"inside_local": "...", "inside_global": "..."}]

        mode="dynamic" — Dynamic NAT (public IP pool) 
        The router assigns IPs from the pool on demand. 
        When the host closes session, the public IP returns to the pool for another host. 
        Use when you have MORE public IPs than overload justifies but LESS than 
        simultaneous internal hosts, and IP tracking matters. 
        Requires: inside_networks + pool_start/end/netmask

        mode="pat" — PAT/NAT Overload (many-to-one with ports) 
        Multiple internal hosts share ONE single public IP. 
        The Router Differentiates connections using unique port numbers. 
        It's the mode that almost all home and business routers use. 
        Use when you have 1 public ISP IP and N internal hosts. 
        Sub-modes: 
            use_interface_overload=True → uses outside_interface IP directly 
            use_interface_overload=False → uses a pool (typically 1 IP) 
        Requires: inside_networks (+ pool if use_interface_overload=False)

        ── PARAMETERS ──────────────────────────────────────────────────────── 
        
        - router: name of the device in PT (e.g., "R1"). Call 
        pt_query_topology if you don't know the exact name. 
        - mode: "static" | "dynamic" | "pat" 
        - inside_interface: interface connected to the private LAN (e.g. "GigabitEthernet0/0") 
        - outside_interface: WAN/Internet-connected interface (e.g. "GigabitEthernet0/1") 
        - static_mappings: only mode="static". Dict list: 
        [{"inside_local": "192.168.1.10", "inside_global": "200.1.1.5"}] 
        - inside_networks: dynamic/pat modes. Internal networks to be translated 
        into "Network Wildcard" format (e.g.: ["192.168.1.0 0.0.0.255"]). 
        They are generated as an inline access-list.
        - acl_number: ACL number or name to identify inside hosts (default "1") 
        - pool_name: NAT pool name (default "NAT-POOL") 
        - pool_start / pool_end: first and last public pool IPs 
        - pool_netmask: Pool mask (mask format, e.g. "255.255.255.0") 
        - use_interface_overload: PAT only. If True, use outside_interface IP 
        instead of a pool. Typical when the ISP allocates 1 IP to the WAN. 
        - dry_run: If True, validate and generate the payload without sending it to the bridge.

        Example PAT with interface overload (most common case):
          pt_apply_nat(
              router="R1",
              mode="pat",
              inside_interface="GigabitEthernet0/0",
              outside_interface="GigabitEthernet0/1",
              inside_networks=["192.168.1.0 0.0.0.255"],
              use_interface_overload=True,
          )
        """
        config = build_nat_config(
            router=router,
            mode=mode,
            inside_interface=inside_interface,
            outside_interface=outside_interface,
            static_mappings=static_mappings,
            inside_networks=inside_networks,
            acl_number=acl_number,
            pool_name=pool_name,
            pool_start=pool_start,
            pool_end=pool_end,
            pool_netmask=pool_netmask,
            use_interface_overload=use_interface_overload,
        )

        bridge_ok = _pick_channel() != ""
        query_fn = _query_pt_devices if bridge_ok else None
        send_fn = _bridge_send_payload if bridge_ok and not dry_run else None

        result = apply_nat_uc(
            config=config,
            query_pt_topology=query_fn,
            bridge_send=send_fn,
            dry_run=dry_run,
        )

        summary_lines = []
        mode_label = {"static": "NAT Static", "dynamic": "NAT Dynamic", "pat": "PAT/Overload"}.get(mode, mode) 
        if result["valid"]: 
            summary_lines.append(f" ✅ {mode_label} valid for router '{router}'.") 
        else: 
            summary_lines.append(f" ❌ {mode_label}: {len(result['errors'])} error(es).")

        if dry_run: 
            summary_lines.append("Mode dry_run — NOT sent to the bridge.") 
        elif result["sent"]: 
            summary_lines.append(f" 📤 Applied on '{router}' via bridge (configureIosDevice).") 
        elif result["valid"] and not bridge_ok: 
            summary_lines.append(" ⚠ Bridge not connected — payload generated but NOT sent.") 
        elif result["valid"] and not result["sent"]: 
            summary_lines.append(" ⚠ Bridge OK but send failed.")

        return json.dumps({
            "summary": "\n".join(summary_lines),
            "mode": mode,
            "valid": result["valid"],
            "errors": result["errors"],
            "warnings": result["warnings"],
            "cli_lines": result["cli_lines"],
            "js_payload": result["js_payload"],
            "sent": result["sent"],
            "dry_run": result["dry_run"],
        }, indent=2, ensure_ascii=False)

    @mcp.tool()
    def pt_remove_nat(
        router: str,
        mode: str,
        inside_interface: str,
        outside_interface: str,
        acl_number: str = "1",
        pool_name: str = "",
        static_mappings: list[dict] | None = None,
        dry_run: bool = False,
    ) -> str:
        """
        Removes the NAT/PAT configuration from a router. 
        
        Remove ip nat inside/outside marks from interfaces and remove 
        the associated translations, pool and access-list. 
        
        Parameters: 
        - router: name of the device in PT 
        - mode: "static" | "dynamic" | "pat" 
        - inside_interface: Interface marked as IP Nat Inside 
        - outside_interface: interface marked as IP Nat Outside 
        - acl_number: number/name of the access-list used (default "1") 
        - pool_name: name of the NAT pool to be removed (dynamic/pat with pool only) 
        - static_mappings: only mode="static". List of dicts with inside_local/inside_global 
        To generate the commands "No IP Nat Inside Source Static..." 
        - dry_run: If True, it returns payload without sending it
        """
        bridge_ok = _pick_channel() != ""
        send_fn = _bridge_send_payload if bridge_ok and not dry_run else None

        result = remove_nat_uc(
            router=router,
            mode=mode,
            inside_interface=inside_interface,
            outside_interface=outside_interface,
            acl_number=acl_number,
            pool_name=pool_name,
            static_mappings=static_mappings,
            bridge_send=send_fn,
            dry_run=dry_run,
        )

        summary = []
        if dry_run: 
            summary.append(f"Mode dry_run — payload generated to remove NAT '{mode}' in '{router}'.") 
        elif result["sent"]: 
            summary.append(f" 📤 NAT '{mode}' removed in '{router}' via bridge.") 
        elif not bridge_ok: 
            summary.append(" ⚠ Bridge not connected — payload generated but NOT sent.") 
        else: 
            summary.append("⚠ Submission failed.")

        return json.dumps({
            "summary": "\n".join(summary),
            "router": result["router"],
            "mode": result["mode"],
            "js_payload": result["js_payload"],
            "sent": result["sent"],
            "dry_run": result["dry_run"],
        }, indent=2, ensure_ascii=False)

    @mcp.tool()
    def pt_apply_vlan(
        switch: str = "",
        router: str = "",
        vlans: list[dict] | None = None,
        access_ports: list[dict] | None = None,
        trunks: list[dict] | None = None,
        subinterfaces: list[dict] | None = None,
        dry_run: bool = False,
    ) -> str:
        """
        Apply VLANs/trunks/inter-VLAN routing to an active PT topology. 
        
        Configure the switch (definition of VLANs, access ports, trunks) and 
        optionally the router (.1q subinterfaces for inter-VLAN routing / router-on-a-stick). 
        All via IOS CLI (configureIosDevice). Use pt_query_topology for actual names/ports.

        Parameters: 
        - switch: name of the switch in PT (e.g. "SW1"). 
        - router: name of the router (only if you do inter-VLAN routing with subinterfaces). 
        - vlans: list of {vlan_id:int, name:str?}. Ex: [{"vlan_id":10,"name":"SALES"}]. 
        - access_ports: list of {switch, port, vlan_id}. 
        Ex [{"switch":"SW1","port":"FastEthernet0/1","vlan_id":10}]. 
        - trunks: list of {switch, port, allowed_vlans:[..]?, native_vlan:int?, encapsulation:str?}. 
        On 2960 (dot1q-only) 'switchport trunk encapsulation' is NOT emitted; on 3560 it is. 
        - Subinterfaces: List of {router, parent_port, vlan_id, ip_cidr}. 
        Ex [{"router":"R1","parent_port":"GigabitEthernet0/0","vlan_id":10,"ip_cidr":"192.168.10.1/24"}]. 
        - dry_run: If True, it only validates and returns the unsent CLI/payload.

        Example router-on-a-stick (2 VLANs):
          pt_apply_vlan(
            switch="SW1", router="R1",
            vlans=[{"vlan_id":10,"name":"V10"},{"vlan_id":20,"name":"V20"}],
            access_ports=[{"switch":"SW1","port":"FastEthernet0/1","vlan_id":10},
                          {"switch":"SW1","port":"FastEthernet0/2","vlan_id":20}],
            trunks=[{"switch":"SW1","port":"GigabitEthernet0/1"}],
            subinterfaces=[{"router":"R1","parent_port":"GigabitEthernet0/0","vlan_id":10,"ip_cidr":"192.168.10.1/24"},
                           {"router":"R1","parent_port":"GigabitEthernet0/0","vlan_id":20,"ip_cidr":"192.168.20.1/24"}],
            dry_run=True)
        """
        plan = build_vlan_plan(
            switch=switch, router=router, vlans=vlans,
            access_ports=access_ports, trunks=trunks, subinterfaces=subinterfaces,
        )

        bridge_ok = _pick_channel() != ""
        query_fn = _query_pt_devices if bridge_ok else None
        send_fn = _bridge_send_payload if bridge_ok and not dry_run else None

        result = apply_vlan_uc(
            plan=plan,
            query_pt_topology=query_fn,
            bridge_send=send_fn,
            dry_run=dry_run,
        )

        summary = []
        if result["valid"]: 
            summary.append(f" ✅ valid VLAN config ({len(plan.vlans)} VLAN(s)).") 
        else: 
            summary.append(f" ❌ VLAN: {len(result['errors'])} error(es).") 
        if dry_run: 
            summary.append("Mode dry_run — NOT sent to the bridge.") 
        elif result["sent"]: 
            summary.append(" 📤 Applied via bridge (configureIosDevice).") 
        elif result["valid"] and not bridge_ok: 
            summary.append(" ⚠ Bridge not connected — payload generated but NOT sent.")

        return json.dumps({
            "summary": "\n".join(summary),
            "valid": result["valid"],
            "errors": result["errors"],
            "warnings": result["warnings"],
            "cli_lines": result["cli_lines"],
            "js_payload": result["js_payload"],
            "sent": result["sent"],
            "dry_run": result["dry_run"],
        }, indent=2, ensure_ascii=False)

    def _switch_security_response(result: dict, label: str, bridge_ok: bool, dry_run: bool) -> str:
        summary = []
        summary.append(f" ✅ {label} valid." if result["valid"] 
                       else f" ❌ {label}: {len(result['errors'])} error(es).")
        if dry_run: 
            summary.append("Mode dry_run — NOT sent to the bridge.") 
        elif result["sent"]: 
            summary.append(" 📤 Applied via bridge (configureIosDevice).") 
        elif result["valid"] and not bridge_ok: 
            summary.append(" ⚠ Bridge not connected — payload generated but NOT sent.")
        return json.dumps({
            "summary": "\n".join(summary),
            "valid": result["valid"],
            "errors": result["errors"],
            "warnings": result["warnings"],
            "cli_lines": result["cli_lines"],
            "js_payload": result["js_payload"],
            "sent": result["sent"],
            "dry_run": result["dry_run"],
        }, indent=2, ensure_ascii=False)

    @mcp.tool()
    def pt_apply_stp(
        switch: str,
        mode: str = "rapid-pvst",
        root_primary_vlans: list[int] | None = None,
        priority: dict | None = None,
        portfast_ports: list[str] | None = None,
        bpduguard_ports: list[str] | None = None,
        dry_run: bool = False,
    ) -> str:
        """
        Configures Spanning-Tree on a switch in the active topology. 
        
        Parameters: 
        - switch: name of the switch in PT (e.g. "SW1"). 
        - mode: "rapid-pvst" (default) or "pvst". 
        - root_primary_vlans: list of VLANs where this switch is root primary 
        (generates 'spanning-tree vlan N root primary'). 
        - priority: dict {vlan_id: priority}. The priority must be 0-61440 and a multiple of 4096. 
        - portfast_ports: access ports with 'spanning-tree portfast'. 
        - bpduguard_ports: ports with 'spanning-tree bpduguard enable'. 
        - dry_run: If True, it only validates and returns the CLI/payload. 
        
        Example: SW1 root of VLAN 10 + portfast in Fa0/1:
          pt_apply_stp(switch="SW1", root_primary_vlans=[10],
                       portfast_ports=["FastEthernet0/1"], dry_run=True)
        """
        cfg = STPConfig(
            switch=switch, mode=mode,
            root_primary_vlans=root_primary_vlans or [],
            priority={int(k): int(v) for k, v in (priority or {}).items()},
            portfast_ports=portfast_ports or [],
            bpduguard_ports=bpduguard_ports or [],
        )
        bridge_ok = _pick_channel() != ""
        result = apply_stp_uc(
            cfg,
            query_pt_topology=_query_pt_devices if bridge_ok else None,
            bridge_send=_bridge_send_payload if bridge_ok and not dry_run else None,
            dry_run=dry_run,
        )
        return _switch_security_response(result, "STP", bridge_ok, dry_run)

    @mcp.tool()
    def pt_apply_port_security(
        switch: str,
        port: str,
        max_mac: int = 1,
        violation: str = "shutdown",
        sticky: bool = True,
        static_macs: list[str] | None = None,
        dry_run: bool = False,
    ) -> str:
        """
        Configures port-security on an access port on a switch. 
        
        Parameters: 
        - switch: name of the switch in PT. 
        - port: access port (e.g. "FastEthernet0/1"). 
        - max_mac: maximum MACs allowed (default 1). 
        - violation: "shutdown" (default) | "restrict" | "protect". 
        - sticky: if True, learn sticky MACs ('mac-address sticky'). 
        - static_macs: Static MACs in IOS format aaaa.bbbb.cccc. 
        - dry_run: If True, it only validates and returns the CLI/payload. 
        
        Example: max 2 sticky MACs in Fa0/1 of SW1:
          pt_apply_port_security(switch="SW1", port="FastEthernet0/1", max_mac=2, dry_run=True)
        """
        cfg = PortSecurityConfig(
            switch=switch, port=port, max_mac=max_mac,
            violation=violation, sticky=sticky, static_macs=static_macs or [],
        )
        bridge_ok = _pick_channel() != ""
        result = apply_port_security_uc(
            cfg,
            query_pt_topology=_query_pt_devices if bridge_ok else None,
            bridge_send=_bridge_send_payload if bridge_ok and not dry_run else None,
            dry_run=dry_run,
        )
        return _switch_security_response(result, "Port-security", bridge_ok, dry_run)

    @mcp.tool()
    def pt_apply_hardening(
        device: str,
        hostname: str = "",
        banner_motd: str = "",
        enable_secret: str = "",
        users: list[dict] | None = None,
        ssh: dict | None = None,
        service_password_encryption: bool = True,
        dry_run: bool = False,
    ) -> str:
        """
        Hardens an active topology router/switch. 
        
        Applies via CLI: hostname, banner MOTD, enable secret, local users, SSH 
        (domain-name + RSA keys + 'ip ssh version'), service password-encryption, 
        and Restrict VTY lines to SSH with local login. 
        
        Parameters: 
        - device: name of the device in PT. 
        - hostname: new hostname (optional). 
        - banner_motd: MOTD banner text (without the '#' character). 
        - enable_secret: Enable password (encrypted). 
        - users: list of {username, secret, privilege?}. Required for local SSH/login. 
        - ssh: dict {domain?, modulus?, version?, enable?} to enable SSH. 
        Requires at least one user. modulus<768 generates warning. 
        - service_password_encryption: apply 'service password-encryption' (default True). 
        - dry_run: If True, it only validates and returns the CLI/payload. 
        
        Example: full hardening of R1 with SSH:
          pt_apply_hardening(device="R1", hostname="R1", enable_secret="cisco123",
            users=[{"username":"admin","secret":"adminpass","privilege":15}],
            ssh={"domain":"lab.local","modulus":1024}, dry_run=True)
        """
        cfg = build_hardening_config(
            device=device, hostname=hostname, banner_motd=banner_motd,
            enable_secret=enable_secret, users=users, ssh=ssh,
            service_password_encryption=service_password_encryption,
        )
        bridge_ok = _pick_channel() != ""
        result = apply_hardening_uc(
            cfg,
            query_pt_topology=_query_pt_devices if bridge_ok else None,
            bridge_send=_bridge_send_payload if bridge_ok and not dry_run else None,
            dry_run=dry_run,
        )
        return _switch_security_response(result, "Hardening", bridge_ok, dry_run)

    @mcp.tool()
    def pt_apply_interface_tuning(
        router: str,
        interface: str,
        clock_rate: int | None = None,
        bandwidth: int | None = None,
        ospf_cost: int | None = None,
        ospf_priority: int | None = None,
        ospf_hello_interval: int | None = None,
        ospf_dead_interval: int | None = None,
        ospf_auth_key: str | None = None,
        ospf_md5_key_id: int | None = None,
        ospf_md5_key: str | None = None,
        delay: int | None = None,
        dry_run: bool = False,
    ) -> str:
        """
        Sets parameters of a router interface in the active topology. 
        
        Parameters (all optional except router/interface): 
        - router: name of the router in PT. 
        - interface: interface to be adjusted (e.g. "Serial0/0/0", "GigabitEthernet0/0"). 
        - clock_rate: ONLY on Serial interfaces (DCE end). Ex. 64000, 2000000. 
        Applying clock_rate to a non-serial interface is a validation error. 
        - bandwidth: bandwidth in kbps ('bandwidth N'). 
        - ospf_cost / ospf_priority: OSPF knobs per interface. 
        - ospf_hello_interval / ospf_dead_interval: OSPF timers. 
        They have to coincide with those of the neighbor or the adjacency does not form; 
        the convention IOS is dead = 4 x hello, and dead <= hello is rejected. 
        - ospf_md5_key + ospf_md5_key_id: OSPF message-digest authentication (recommended). 
        The id must match the neighbor's id. 
        - ospf_auth_key: OSPF authentication in plain text. It works, but the A password 
        travels readable over the network — a warning is issued. 
        - delay: delay of the interface (affects EIGRP metric), in tens of microseconds. 
        - dry_run: If True, it only validates and returns the CLI/payload. 
        
        Example: authenticate OSPF with MD5 between R1 and its neighbor:
          pt_apply_interface_tuning(router="R1", interface="GigabitEthernet0/0",
                                    ospf_md5_key_id=1, ospf_md5_key="s3cr3t")
        """
        cfg = InterfaceTuning(
            router=router, interface=interface, clock_rate=clock_rate,
            bandwidth=bandwidth, ospf_cost=ospf_cost, ospf_priority=ospf_priority,
            ospf_hello_interval=ospf_hello_interval,
            ospf_dead_interval=ospf_dead_interval, ospf_auth_key=ospf_auth_key,
            ospf_md5_key_id=ospf_md5_key_id, ospf_md5_key=ospf_md5_key,
            delay=delay,
        )
        bridge_ok = _pick_channel() != ""
        result = apply_interface_tuning_uc(
            cfg,
            query_pt_topology=_query_pt_devices if bridge_ok else None,
            bridge_send=_bridge_send_payload if bridge_ok and not dry_run else None,
            dry_run=dry_run,
        )
        return _switch_security_response(result, "Interface tuning", bridge_ok, dry_run)

    @mcp.tool()
    def pt_diff(plan_json: str) -> str:
        """
        Compare a plan (pt_plan_topology JSON) against the PT VIVA topology. 
        
        Reports: plan devices missing in PT, extra devices in PT, and IP discrepancies 
        by interface. Useful for reconciling after a deployment. Requires connected bridge.
        """
        try:
            plan = TopologyPlan.model_validate_json(plan_json)
        except Exception as exc:
            return json.dumps({"error": f"plan_json invalid: {exc}"}, ensure_ascii=False)
        err = _check_bridge()
        if err:
            return err
        live = _live_devices()
        result = topology_diff(plan, live)
        result["summary"] = (
            "✅ Plan and PT in sync."
            if result["in_sync"]
            else f" ⚠ {len(result['missing_devices'])} missing(s), "
                 f"{len(result['extra_devices'])} extra(s), "
                 f"{len(result['ip_mismatches'])} IP mismatch(es)."
        )
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp.tool()
    def pt_health_check() -> str:
        """
        Health sweep of the VIVA topology of PT. 
        
        Reports: Links down (wired but not up), wired ports without IP 
        (possible DHCP not completed), and duplicate IPs. Requires connected bridge.
        """
        err = _check_bridge()
        if err:
            return err
        live = _live_devices()
        result = health_check(live)
        result["summary"] = (
            "✅ Healthy topology."
            if result["healthy"]
            else f" ⚠ {len(result['down_links'])} link(s) down, "
                 f"{len(result['duplicate_ips'])} Duplicate IP(s)."
        )
        return json.dumps(result, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # SECURITY AUDIT — actual read posture of living devices
    # ------------------------------------------------------------------

    # Sort each credential by its prefix and return ONLY the tag of the 
    # algorithm. The hash never crosses the bridge: it would end up in the context of the LLM 
    # and in the MCP client logs, and the tag reaches for auditing. 
    # Verified against PT 9.0.0.0810: 'enable secret'/'username X secret' dan 
    # "$1$...", and 'username X password' con service-password-encryption da hex 
    # type-7 (reversible with public set-top boxes).
    _AUDIT_ALGO_JS = (
        "function __algo(s){"
        "  if(!s) return null;"
        "  s = String(s);"
        "  if(s.indexOf('$1$')===0) return 'md5';"
        "  if(s.indexOf('$8$')===0) return 'pbkdf2';"
        "  if(s.indexOf('$9$')===0) return 'scrypt';"
        "  if(/^[0-9A-Fa-f]{4,}$/.test(s)) return 'type7';"
        "  return 'plaintext';"
        "}"
    )

    _SECURITY_AUDIT_JS = (
        "try {"
        + _AUDIT_ALGO_JS +
        "  var __net = ipc.network();"
        "  var __out = [];"
        "  var __n = __net.getDeviceCount();"
        "  for (var __i = 0; __i < __n; __i++) {"
        "    try {"
        "      var __d = __net.getDeviceAt(__i);"
        # Hosts (PC/Server/Laptop) do not expose IOS configuration: call 
        # these getters there launch and open a modal that freezes the bridge.
        "      if (!__d || typeof __d.getEnableSecret !== 'function') continue;"
        "      var __users = [];"
        "      try {"
        "        var __uc = __d.getUserPassCount();"
        "        for (var __j = 0; __j < __uc; __j++) {"
        # getUserEntryAt throws 'out of bound' instead of returning null, so 
        # Each read goes with its own guard.
        "          try {"
        "            var __u = String(__d.getUserEntryAt(__j));"
        "            __users.push({ name: __u, algo: __algo(__d.getUserPass(__u)) });"
        "          } catch (__ue) {}"
        "        }"
        "      } catch (__uce) {}"
        "      var __sec = __d.getEnableSecret();"
        "      var __pwd = __d.getEnablePassword();"
        "      __out.push({"
        "        name: __d.getName(),"
        "        model: (typeof __d.getModel === 'function') ? __d.getModel() : '',"
        "        hostname: (typeof __d.getHostName === 'function') ? __d.getHostName() : '',"
        "        enable_secret_set: !!__sec,"
        "        enable_secret_algo: __algo(__sec),"
        "        enable_password_set: !!__pwd,"
        "        service_password_encryption: (typeof __d.getServicePasswordEncryption === 'function')"
        "          ? !!__d.getServicePasswordEncryption() : false,"
        "        banner_set: (typeof __d.getBannerMotd === 'function')"
        "          ? !!__d.getBannerMotd() : false,"
        "        users: __users,"
        "        config_register: (typeof __d.getConfigRegister === 'function')"
        "          ? __d.getConfigRegister() : null"
        "      });"
        "    } catch (__pe) {}"
        "  }"
        "  reportResult(JSON.stringify({ devices: __out }));"
        "} catch (__e) { reportResult('ERROR:' + __e); }"
    )

    @mcp.tool()
    def pt_audit_security(device: str = "") -> str:
        """
        Audits the REAL security posture of live devices in PT. 
        
        Does not read the plan: reads the effective configuration of each router/switch in 
        the canvas and reports findings with severity (high/medium/low). Detects 
        Enable Secret absent, credentials saved reversibly (type 7), 
        'service password-encryption' off, missing users locals, missing MOTD banner, 
        and config-register in 0x2142 (which discards the startup-config in the next reboot). 
        
        Passwords and hashes NEVER leave the device – it's just transmitted the label of 
        the algorithm with which they are stored. 
        
        Hosts (PC/Server/Laptop) are ignored: they have no IOS configuration. 
        
        Parameters: 
        - device: if indicated, audits only that device; empty = all. 
        
        Example: Audit the entire topology:
          pt_audit_security()
        """
        err = _check_bridge()
        if err:
            return err

        raw = _bridge_send_and_wait(_SECURITY_AUDIT_JS, timeout=12.0)
        if raw is None:
            return _TIMEOUT_MSG
        if raw.startswith("ERROR:"):
            return f"PT error: {raw}"

        try:
            devices = json.loads(raw).get("devices", [])
        except Exception as exc:
            return f"PT illegible response: {exc}"

        wanted = device.strip()
        if wanted:
            devices = [d for d in devices if d.get("name") == wanted]
            if not devices:
                return (
                    f"'{wanted}' does not exist in the active topology or does not have "
                    "IOS configuration (PCs and servers do not have it)." 
                    "Use pt_query_topology to see the real names."
                )

        result = audit_security(devices)
        counts = result["counts"]
        if not devices:
            result["summary"] = "There are no devices with IOS configuration on the canvas."
        elif result["secure"]:
            result["summary"] = (
                f" ✅ {result['devices_audited']} audited device(s), "
                f"No high or medium findings ({counts['low']} low(s))."
            )
        else:
            result["summary"] = (
                f" ⚠ {counts['high']} high find(s), {counts['medium']} medium(s), "
                f"{counts['low']} low(s) in {result['devices_audited']} device(s)."
            )
        return json.dumps(result, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # PORT INSPECTION — read physical and logical state of the device
    # ------------------------------------------------------------------

    def _inspect_ports_js(device: str) -> str:
        """Reader per port. Empty 'device' = all. 
        
        Each getter goes after a typeof: the surface of Port changes by model 
        (a PC-PT does not have getNatMode or getAclInID) and a call to a non-existent 
        method launches and opens a modal that freezes the bridge.
        """
        want = json.dumps(device.strip())
        return (
            "try {"
            f"  var __want = {want};"
            "  var __net = ipc.network();"
            "  var __out = [];"
            "  var __n = __net.getDeviceCount();"
            "  for (var __i = 0; __i < __n; __i++) {"
            "    try {"
            "      var __d = __net.getDeviceAt(__i);"
            "      if (!__d) continue;"
            "      var __dn = __d.getName();"
            "      if (__want && __dn !== __want) continue;"
            "      var __ports = [];"
            "      var __pc = __d.getPortCount();"
            "      for (var __j = 0; __j < __pc; __j++) {"
            "        try {"
            "          var __p = __d.getPortAt(__j);"
            "          if (!__p) continue;"
            "          __ports.push({"
            "            name: __p.getName(),"
            "            up: !!__p.isPortUp(),"
            "            protocol_up: (typeof __p.isProtocolUp === 'function') ? !!__p.isProtocolUp() : null,"
            "            linked: !!__p.getLink(),"
            "            ip: __p.getIpAddress(),"
            "            mask: __p.getSubnetMask(),"
            "            mac: (typeof __p.getMacAddress === 'function') ? __p.getMacAddress() : null,"
            "            description: (typeof __p.getDescription === 'function') ? __p.getDescription() : '',"
            "            duplex_full: (typeof __p.isFullDuplex === 'function') ? !!__p.isFullDuplex() : null,"
            "            bandwidth_kbps: (typeof __p.getBandwidth === 'function') ? __p.getBandwidth() : null,"
            "            mtu: (typeof __p.getMtu === 'function') ? __p.getMtu() : null,"
            "            delay: (typeof __p.getDelay === 'function') ? __p.getDelay() : null,"
            "            cdp: (typeof __p.isCdpEnable === 'function') ? !!__p.isCdpEnable() : null,"
            "            dhcp_client: (typeof __p.isDhcpClientOn === 'function') ? !!__p.isDhcpClientOn() : null,"
            "            wireless: (typeof __p.isWirelessPort === 'function') ? !!__p.isWirelessPort() : null,"
            "            nat_mode_raw: (typeof __p.getNatMode === 'function') ? __p.getNatMode() : null,"
            "            acl_in: (typeof __p.getAclInID === 'function') ? __p.getAclInID() : '',"
            "            acl_out: (typeof __p.getAclOutID === 'function') ? __p.getAclOutID() : ''"
            "          });"
            "        } catch (__pe) {}"
            "      }"
            "      __out.push({"
            "        name: __dn,"
            "        model: (typeof __d.getModel === 'function') ? __d.getModel() : '',"
            "        ports: __ports"
            "      });"
            "    } catch (__de) {}"
            "  }"
            "  reportResult(JSON.stringify({ devices: __out }));"
            "} catch (__e) { reportResult('ERROR:' + __e); }"
        )

    @mcp.tool()
    def pt_inspect_ports(device: str = "", only_linked: bool = False) -> str:
        """
        Actual status of each port of a live device in PT. 
        
        Reads from device, not plan: line/protocol status, MAC, IP/mask, duplex, 
        bandwidth, MTU, delay, CDP, DHCP client, NAT mode, and ACLs applied. 
        Marks anomalies (cable placed with the down port, line up with Down protocol). 
        
        It is the DETAIL view of a device; for the sweep of the entire Topology 
        (Down Links, Duplicate IPs) Use pt_health_check. 
        
        Parameters: 
        - device: name of the device; empty = all (verbose in large topologies). 
        - only_linked: If True, returns only wired ports attached. 
        
        Example: See why you don't lift an R1 link:
          pt_inspect_ports(device="R1", only_linked=True)
        """
        err = _check_bridge()
        if err:
            return err

        raw = _bridge_send_and_wait(_inspect_ports_js(device), timeout=15.0)
        if raw is None:
            return _TIMEOUT_MSG
        if raw.startswith("ERROR:"):
            return f"PT error: {raw}"
        try:
            devices = json.loads(raw).get("devices", [])
        except Exception as exc:
            return f"PT illegible response: {exc}"

        wanted = device.strip()
        if wanted and not devices:
            return (
                f"'{wanted}' does not exist in the active topology. "
                "Use pt_query_topology to see the real names."
            )

        for dev in devices:
            ports = dev.get("ports", [])
            if only_linked:
                ports = [p for p in ports if p.get("linked")]
            for port in ports:
                port["nat_mode"] = nat_mode_label(port.pop("nat_mode_raw", None))
            dev["ports"] = ports

        result = summarize_ports(devices)
        result["devices"] = devices
        anomalies = result["anomalies"]
        result["summary"] = (
            f" ✅ {result['ports_up']}/{result['ports_total']} port(s) up, "
            f"{result['ports_linked']} wiring(s), no anomalies." 
            if not anomalies 
            else f" ⚠ {len(anomalies)} anomaly(s) in {result['ports_total']} port(s)."
        )
        return json.dumps(result, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # VLANs — read from the VlanManager of the switch, not the plan
    # ------------------------------------------------------------------

    @mcp.tool()
    def pt_read_vlans(switch: str) -> str:
        """
        Reads the REAL VLAN database of a switch in PT. 
        
        It returns each VLAN with its number, name and if it is one 
        of the ones that PT brings (1, 1002-1005). It serves to confirm 
        that a pt_apply_vlan was applied, or to discover what is in a topology 
        that you did not assemble. 
        
        Parameters: 
        - switch: name of the switch in PT. 
        
        Example: pt_read_vlans(switch="SW1")
        """
        err = _check_bridge()
        if err:
            return err

        name = json.dumps(switch.strip())
        js = (
            "try {"
            f"  var __d = ipc.network().getDevice({name});"
            "  if (!__d) { reportResult(JSON.stringify({ found: false })); } else {"
            "    var __vm = (typeof __d.getProcess === 'function') ? __d.getProcess('VlanManager') : null;"
            "    if (!__vm) { reportResult(JSON.stringify({ found: true, supported: false })); } else {"
            "      var __vs = [];"
            "      var __n = __vm.getVlanCount();"
            "      for (var __i = 0; __i < __n; __i++) {"
            "        try {"
            "          var __v = __vm.getVlanAt(__i);"
            "          if (!__v) continue;"
            "          __vs.push({"
            "            number: __v.getVlanNumber(),"
            "            name: __v.getName(),"
            "            is_default: !!__v.isDefault()"
            "          });"
            "        } catch (__ve) {}"
            "      }"
            "      reportResult(JSON.stringify({"
            "        found: true, supported: true,"
            "        max_vlans: __vm.getMaxVlans(),"
            "        vlan_interfaces: __vm.getVlanIntCount(),"
            "        vlans: __vs"
            "      }));"
            "    }"
            "  }"
            "} catch (__e) { reportResult('ERROR:' + __e); }"
        )

        raw = _bridge_send_and_wait(js, timeout=10.0)
        if raw is None:
            return _TIMEOUT_MSG
        if raw.startswith("ERROR:"):
            return f"PT error: {raw}"
        try:
            data = json.loads(raw)
        except Exception as exc:
            return f"PT illegible response: {exc}"

        if not data.get("found"):
            return (
                f"'{switch}' does not exist in the active topology. "
                "Use pt_query_topology to see the real names."
            )
        if not data.get("supported"):
            return (
                f"'{switch}' does not expose VlanManager: it is not a switch or the model is not "
                "Handle VLANs. Use pt_get_device_details to see what it is."
            )

        vlans = data.get("vlans", [])
        custom = [v for v in vlans if not v.get("is_default")]
        data["summary"] = (
            f"{len(vlans)} VLAN(s): {len(custom)} own(s), "
            f"{len(vlans) - len(custom)} from the factory. "
            f"Model maximum: {data.get('max_vlans')}."
        )
        return json.dumps(data, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # ON/OFF devices
    # ------------------------------------------------------------------

    @mcp.tool()
    def pt_device_power(device: str, on: bool = True) -> str:
        """
        Turn a device on or off in PT, with verification reading. 
        
        Useful for simulating a equipment drop and seeing how the routing reacts, 
        or to restart a router and reread its startup-config. 
        
        It works on all models, including PCs. Hosts don't have IOS boot, 
        so when you turn them on 'booting' it returns null; on a router o Switch 
        skips boot so as not to wait for full boot. 
        
        Parameters: 
        - device: name of the device in PT. 
        - on: True turns on (default), False turns off. 
        
        Example: simulate the fall of R2:
          pt_device_power(device="R2", on=False)
        """
        err = _check_bridge()
        if err:
            return err

        name = json.dumps(device.strip())
        want = "true" if on else "false"
        js = (
            "try {"
            f"  var __d = ipc.network().getDevice({name});"
            "  if (!__d) { reportResult(JSON.stringify({ found: false })); }"
            "  else if (typeof __d.setPower !== 'function' || typeof __d.getPower !== 'function') {"
            "    reportResult(JSON.stringify({ found: true, supported: false }));"
            "  } else {"
            "    var __before = !!__d.getPower();"
            f"    __d.setPower({want});"
            f"    if ({want} && typeof __d.skipBoot === 'function') {{ __d.skipBoot(); }}"
            "    reportResult(JSON.stringify({"
            "      found: true, supported: true,"
            "      before: __before, after: !!__d.getPower(),"
            "      booting: (typeof __d.isBooting === 'function') ? !!__d.isBooting() : null"
            "    }));"
            "  }"
            "} catch (__e) { reportResult('ERROR:' + __e); }"
        )

        raw = _bridge_send_and_wait(js, timeout=15.0)
        if raw is None:
            return _TIMEOUT_MSG
        if raw.startswith("ERROR:"):
            return f"PT error: {raw}"
        try:
            data = json.loads(raw)
        except Exception as exc:
            return f"PT illegible response: {exc}"

        if not data.get("found"):
            return (
                f"'{device}' does not exist in the active topology. "
                "Use pt_query_topology to see the real names."
            )
        if not data.get("supported"):
            # No model without setPower/getPower was observed in PT 9.0.0.0810 
            # (not even PCs), but the surface area varies by build and a 
            # Absent method launches and opens a modal that freezes the bridge.
            return f"'{device}' does not expose power control in this PT build."

        verb = "on" if on else "off"
        if data["after"] == on:
            data["summary"] = (
                f"✅ '{device}' {verb}."
                if data["before"] != on
                else f"'{device}' was already {verb}; no change."
            )
        else:
            data["summary"] = (
                f" ⚠ Asked for {verb} but PT reports power={data['after']}. "
                "The model may not support change."
            )
        return json.dumps(data, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # SIMULATION — mode, step-by-step, and read the event list
    # ------------------------------------------------------------------

    @mcp.tool()
    def pt_simulation_mode(on: bool = True) -> str:
        """
        Switch PT between Realtime mode and Simulation mode. 
        
        In Simulation mode, packets do NOT advance on their own: 
        they are glued in the event list and you have to move them 
        with pt_simulation_step. That's what Allows you to read the 
        journey package by package with pt_read_packet_trace. 
        
        Parameters: 
        - on: True goes to Simulation (default), False goes back to Realtime. 
        
        Example: pt_simulation_mode(on=True)
        """
        err = _check_bridge()
        if err:
            return err

        want = "true" if on else "false"
        js = (
            "try {"
            "  var __s = ipc.simulation();"
            "  var __before = !!__s.isSimulationMode();"
            f"  __s.setSimulationMode({want});"
            "  reportResult(JSON.stringify({"
            "    before: __before, after: !!__s.isSimulationMode(),"
            "    frames: __s.getFrameInstanceCount(), sim_time: __s.getCurrentSimTime()"
            "  }));"
            "} catch (__e) { reportResult('ERROR:' + __e); }"
        )
        raw = _bridge_send_and_wait(js, timeout=10.0)
        if raw is None:
            return _TIMEOUT_MSG
        if raw.startswith("ERROR:"):
            return f"PT error: {raw}"
        try:
            data = json.loads(raw)
        except Exception as exc:
            return f"PT illegible response: {exc}"

        mode = "Simulation" if data["after"] else "Realtime"
        data["summary"] = (
            f"Mode {mode}. {data['frames']} frame(s) in the event list."
            if data["before"] != data["after"]
            else f"It was already in {mode}; no changes."
        )
        return json.dumps(data, indent=2, ensure_ascii=False)

    @mcp.tool()
    def pt_simulation_step(action: str = "forward", times: int = 1) -> str:
        """
        Fast-forward, rewind, or restart the simulation step-by-step. 
        
        Requires Simulation mode (pt_simulation_mode(on=True)). Each step 
        moves the packets an event; after moving forward, read the result 
        with pt_read_packet_trace. 
        
        Parameters: 
        - action: "forward" (default) | "back" | "reset". 
        - Times: How many steps to take (1-100, ignored in "reset"). 
        
        Example: Advance 5 events:
          pt_simulation_step(action="forward", times=5)
        """
        err = _check_bridge()
        if err:
            return err

        act = action.strip().lower()
        if act not in ("forward", "back", "reset"):
            return json.dumps(
                {"error": f"action invalid: '{action}'. Use forward, back or reset."},
                ensure_ascii=False,
            )
        steps = max(1, min(int(times), 100))

        call = {"forward": "__s.forward();", "back": "__s.backward();",
                "reset": "__s.resetSimulation();"}[act]
        loop = call if act == "reset" else f"for (var __i = 0; __i < {steps}; __i++) {{ {call} }}"
        js = (
            "try {"
            "  var __s = ipc.simulation();"
            "  if (!__s.isSimulationMode()) {"
            "    reportResult(JSON.stringify({ simulation_mode: false }));"
            "  } else {"
            "    var __b = __s.getFrameInstanceCount();"
            f"   {loop}"
            "    reportResult(JSON.stringify({"
            "      simulation_mode: true, frames_before: __b,"
            "      frames_after: __s.getFrameInstanceCount(),"
            "      sim_time: __s.getCurrentSimTime(),"
            "      current_index: __s.getCurrentFrameInstanceIndex()"
            "    }));"
            "  }"
            "} catch (__e) { reportResult('ERROR:' + __e); }"
        )
        raw = _bridge_send_and_wait(js, timeout=15.0)
        if raw is None:
            return _TIMEOUT_MSG
        if raw.startswith("ERROR:"):
            return f"PT error: {raw}"
        try:
            data = json.loads(raw)
        except Exception as exc:
            return f"PT illegible response: {exc}"

        if not data.get("simulation_mode"):
            return (
                "PT is in Realtime mode, so there's nothing to advance. "
                "Call pt_simulation_mode(on=True) first."
            )
        data["action"] = act
        data["steps"] = 1 if act == "reset" else steps
        data["summary"] = (
            f"{act} x{data['steps']} — {data['frames_after']} frame(s) in the event list "
            f"(formerly {data['frames_before']})."
        )
        return json.dumps(data, indent=2, ensure_ascii=False)

    @mcp.tool()
    def pt_read_packet_trace(
        limit: int = 20,
        device: str = "",
        include_decisions: bool = True,
    ) -> str:
        """
        Read the simulation event list: what each package did and WHY. 
        
        In addition to the route (device, input/output port, origin, destination, 
        traffic type, and outcome) returns the log of decisions that PT generates 
        per OSI layer — the same text as the "PDU Details" panel of your GUI. 
        That's where you see the real cause of a ping that doesn't work, for example. 
        example: "The next-hop IP address is not in the ARP table."

        Parameters: 
        - limit: maximum frames to return (1-200, default 20). 
        - device: if indicated, only the frames that passed through that device. 
        - include_decisions: If False, skip the log per layer (shorter response). 
        
        Example: See why a ping drops:
          pt_read_packet_trace(limit=10)
        """
        err = _check_bridge()
        if err:
            return err

        lim = max(1, min(int(limit), 200))
        want = json.dumps(device.strip())
        dec = "true" if include_decisions else "false"
        js = (
            "try {"
            "  var __s = ipc.simulation();"
            f"  var __lim = {lim}; var __want = {want}; var __wd = {dec};"
            "  var __n = __s.getFrameInstanceCount();"
            "  var __out = [];"
            "  for (var __i = 0; __i < __n && __out.length < __lim; __i++) {"
            "    try {"
            "      var __f = __s.getFrameInstanceAt(__i);"
            "      if (!__f) continue;"
            "      var __dev = __f.getDevice();"
            "      var __dn = __dev ? __dev.getName() : '';"
            "      if (__want && __dn !== __want) continue;"
            "      var __prev = __f.getPreviousDevice();"
            "      var __ip = __f.getInPort();"
            "      var __op = null;"
            # getOutPort(0) throws when getOutPortCount() is 0 (frame in buffer, 
            # still no output port chosen).
            "      try {"
            "        if (__f.getOutPortCount() > 0) {"
            "          var __o = __f.getOutPort(0); __op = __o ? __o.getName() : null;"
            "        }"
            "      } catch (__oe) {}"
            "      var __dl = [];"
            "      if (__wd) {"
            # No getDecisionCount(); flowchart node count matches 
            # with the decision count (verified: 6/6 and 3/3 in a real ping).
            "        var __dc = __f.getFlowChartNodeCount();"
            "        for (var __j = 0; __j < __dc; __j++) {"
            "          try {"
            # getFrameDecsionAt: The typo is from PT, not ours.
            "            var __d = __f.getFrameDecsionAt(__j);"
            "            if (!__d) continue;"
            "            __dl.push({ layer: __d.osiLayer, inbound: !!__d.osiIn,"
            "                        description: __d.description });"
            "          } catch (__de) {}"
            "        }"
            "      }"
            "      __out.push({"
            "        index: __i, device: __dn,"
            "        previous_device: __prev ? __prev.getName() : null,"
            "        in_port: __ip ? __ip.getName() : null, out_port: __op,"
            "        source: __f.getSourceString(), destination: __f.getDestinationString(),"
            "        traffic_type_raw: __f.getUserTrafficType(),"
            "        sim_time: __f.getStartSimTime(), transit_time: __f.getTransitTime(),"
            "        sent: !!__f.isFrameSent(), accepted: !!__f.isFrameAccepted(),"
            "        dropped: !!__f.isFrameDropped(), buffered: !!__f.isFrameBuffered(),"
            "        in_transit: !!__f.isFrameOnTransit(),"
            "        collided_at_device: !!__f.isFrameCollidedAtDevice(),"
            "        collided_on_link: !!__f.isFrameCollidedOnLink(),"
            "        not_forwarded: !!__f.isFrameNotForwarded(),"
            "        unexpected: !!__f.isFrameUnexpected(),"
            "        decisions: __dl"
            "      });"
            "    } catch (__pe) {}"
            "  }"
            "  reportResult(JSON.stringify({"
            "    total: __n, simulation_mode: !!__s.isSimulationMode(), frames: __out"
            "  }));"
            "} catch (__e) { reportResult('ERROR:' + __e); }"
        )

        raw = _bridge_send_and_wait(js, timeout=20.0)
        if raw is None:
            return _TIMEOUT_MSG
        if raw.startswith("ERROR:"):
            return f"PT error: {raw}"
        try:
            data = json.loads(raw)
        except Exception as exc:
            return f"PT illegible response: {exc}"

        frames = data.get("frames", [])
        for frame in frames:
            frame["traffic_type"] = traffic_type_label(frame.pop("traffic_type_raw", None))

        result = summarize_trace(frames)
        result["total_in_event_list"] = data.get("total", 0)
        result["simulation_mode"] = data.get("simulation_mode", False)
        result["trace"] = frames

        if not data.get("simulation_mode"):
            result["summary"] = (
                "PT is in Realtime mode: the event list is not holding packages." 
                "Call pt_simulation_mode(on=True) and generate traffic."
            )
        elif not frames:
            result["summary"] = (
                "Active Simulation mode but without frames. Generate traffic" 
                "(e.g. pt_verify_connectivity) and read again."
            )
        elif result["clean"]:
            result["summary"] = (
                f"{result['frames']} frame(s) read, none discarded."
            )
        else:
            reasons = "; ".join(f["reason"] for f in result["failures"][:3] if f["reason"])
            result["summary"] = (
                f" ⚠ {len(result['failures'])} frame(s) did not reach their destination. {reasons}"
            )
        return json.dumps(result, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # CANVAS — capture and annotations
    # ------------------------------------------------------------------

    @mcp.tool()
    def pt_screenshot(
        filename: str = "topology",
        fmt: str = "PNG",
        output_dir: str = "projects",
    ) -> str:
        """
        Capture the PT logical canvas and save it as an image. 
        
        Returns the file PATH, not the image: a capture weighs tens of 
        thousands of bytes and pouring it into the answer would fill the 
        context without no one can see it. 
        
        PNG compresses a diagram much better than JPG (measured: 33 KB against 
        105 KB of the same canvas), so it's the default. 
        
        Parameters: 
        - filename: name of the file, without extension. It is sanitized. 
        - fmt: PNG (default) | JPG | JPEG | BMP. 
        - output_dir: destination folder, relating to the root of the project. 
        
        Example: pt_screenshot(filename="lab-ospf")
        """
        err = _check_bridge()
        if err:
            return err

        try:
            image_fmt = normalize_format(fmt)
        except CanvasImageError as exc:
            return json.dumps({"error": str(exc)}, ensure_ascii=False)

        js = (
            "try {"
            "  var __lw = ipc.appWindow().getActiveWorkspace().getLogicalWorkspace();"
            f"  reportResult(String(__lw.getWorkspaceImage({json.dumps(image_fmt)})));"
            "} catch (__e) { reportResult('ERROR:' + __e); }"
        )
        # Generoso a propósito: la imagen viaja como texto y son cientos de KB.
        raw = _bridge_send_and_wait(js, timeout=45.0)
        if raw is None:
            return (
                "No response from PT when capturing. On very large canvases the "
                "Image can exceed the limit of bridge; try fmt='PNG'."
            )
        if raw.startswith("ERROR:"):
            return f"PT error: {raw}"

        try:
            blob = decode_pt_image(raw, image_fmt)
        except CanvasImageError as exc:
            return f"Could not decode image: {exc}"

        safe = safe_name_component(filename, fallback="topology")
        ext = "jpg" if image_fmt in ("JPG", "JPEG") else image_fmt.lower()
        try:
            base = Path(safe_name_component(output_dir, fallback="projects"))
            base.mkdir(parents=True, exist_ok=True)
            target = resolve_within(base, f"{safe}.{ext}")
            target.write_bytes(blob)
        except (OSError, ValueError) as exc:
            return f"Could not write image: {exc}"

        return json.dumps({
            "path": str(target),
            "format": image_fmt,
            "bytes": len(blob),
            "summary": f" ✅ Capture saved in {target} ({len(blob):,} bytes).",
        }, indent=2, ensure_ascii=False)

    @mcp.tool()
    def pt_add_note(x: int, y: int, text: str) -> str:
        """
        Write a text note on the PT canvas. 
        
        It is used to document the topology in the diagram itself: labeling a subnet, 
        mark an OSPF area, name a trunk. Returns the id of the note, with which it 
        can be deleted later. 
        
        The coordinates are the same as the logical canvas used by pt_add_device 
        and pt_move_device: routers ~y=100, switches ~y=250, hosts ~y=400. 
        
        The font size is NOT configurable: PT sets it and uses that parameter for 
        the stacking order, which the tool calculates itself. 
        
        Parameters: 
        - x, y: position on the canvas. 
        - text: content of the note. 
        
        Example: pt_add_note(x=300, y=100, text="LAN 192.168.0.0/24")
        """
        err = _check_bridge()
        if err:
            return err
        if not text.strip():
            return json.dumps({"error": "The note is empty."}, ensure_ascii=False)

        # The third argument of addNote is the Z-ORDER, not the font size: 
        # PT exposes getIncNoteZOrder() just to get the following. It is 
        # checked by passing 12 and 14 — the notes come out the same size.
        js = (
            "try {"
            "  var __lw = ipc.appWindow().getActiveWorkspace().getLogicalWorkspace();"
            "  var __z = (typeof __lw.getIncNoteZOrder === 'function')"
            "    ? __lw.getIncNoteZOrder() : 0;"
            f"  reportResult(String(__lw.addNote({int(x)}, {int(y)}, __z, "
            f"{json.dumps(text)})));"
            "} catch (__e) { reportResult('ERROR:' + __e); }"
        )
        raw = _bridge_send_and_wait(js, timeout=10.0)
        if raw is None:
            return _TIMEOUT_MSG
        if raw.startswith("ERROR:"):
            return f"PT error: {raw}"
        return json.dumps({
            "id": raw.strip(),
            "summary": f"✅ Note added on ({x},{y}).",
        }, indent=2, ensure_ascii=False)

    @mcp.tool()
    def pt_clear_annotations(kind: str = "all") -> str:
        """
        Delete annotations from the canvas: text notes and drawings. 
        
        DO NOT touch devices or links, only the graphic elements. 
        
        PT leaves orphaned note ids that it never releases—no text and that 
        are refuses to erase. They are not a mistake: the canvas is visually 
        clean the same, and they are reported separately as 'stale_ids'. 
        
        Parameters: 
        - kind: "all" (default) deletes notes and drawings; "notes" only notes. 
        
        Example: pt_clear_annotations()
        """
        err = _check_bridge()
        if err:
            return err

        what = kind.strip().lower()
        if what not in ("all", "notes"):
            return json.dumps(
                {"error": f"kind invalid: '{kind}'. Use 'all' or 'notes'."},
                ensure_ascii=False,
            )
        # getCanvasItemIds does NOT include the notes: they are distinct sets. Sweep 
        # only one left notes on the screen and on top of that reported remaining=0, which 
        # is worse than not deleting — the user thinks it was clean.
        getters = ["getCanvasNoteIds"] if what == "notes" else [
            "getCanvasNoteIds", "getCanvasItemIds",
        ]
        js_getters = ", ".join(json.dumps(g) for g in getters)
        js = (
            "try {"
            "  var __lw = ipc.appWindow().getActiveWorkspace().getLogicalWorkspace();"
            f"  var __gs = [{js_getters}];"
            "  var __n = 0;"
            "  for (var __k = 0; __k < __gs.length; __k++) {"
            "    var __ids = null;"
            "    try { __ids = __lw[__gs[__k]](); } catch (__ge) { continue; }"
            "    if (!__ids) continue;"
            "    for (var __i = 0; __i < __ids.length; __i++) {"
            "      try { if (__lw.removeCanvasItem(__ids[__i])) __n++; } catch (__re) {}"
            "    }"
            "  }"
            # PT leaves orphaned note IDs: no text and with removeCanvasItem 
            # returning false. Counting them as "remaining" would make it seem that the 
            # cleanup failed when the canvas was empty, so they separate.            
            "  var __left = 0, __stale = 0;"
            "  for (var __m = 0; __m < __gs.length; __m++) {"
            "    var __rest = null;"
            "    try { __rest = __lw[__gs[__m]]() || []; } catch (__le) { continue; }"
            "    for (var __q = 0; __q < __rest.length; __q++) {"
            "      var __has = true;"
            "      try {"
            "        if (typeof __lw.getCanvasNoteText === 'function') {"
            "          __has = String(__lw.getCanvasNoteText(__rest[__q]) || '') !== '';"
            "        }"
            "      } catch (__te) {}"
            "      if (__has) { __left++; } else { __stale++; }"
            "    }"
            "  }"
            "  reportResult(JSON.stringify({ removed: __n, remaining: __left,"
            "    stale_ids: __stale }));"
            "} catch (__e) { reportResult('ERROR:' + __e); }"
        )
        raw = _bridge_send_and_wait(js, timeout=20.0)
        if raw is None:
            return _TIMEOUT_MSG
        if raw.startswith("ERROR:"):
            return f"PT error: {raw}"
        try:
            data = json.loads(raw)
        except Exception as exc:
            return f"Respuesta ilegible de PT: {exc}"
        data["kind"] = what
        stale = data.get("stale_ids", 0)
        # Orphaned ids are not a bug: PT never releases them and the canvas 
        # It is still visually clean. They are mentioned without alarm. 
        note = f" ({stale} orphan id(s) that PT does not release)." if stale else "."
        data["summary"] = (
            f" ✅ {data['removed']} annotation(s) deleted{note}" 
            if data.get("removed") 
            else f"There were no annotations to delete{note}"
        )
        return json.dumps(data, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # BACKUP y METADATA del proyecto
    # ------------------------------------------------------------------

    # La startup-config vuelve con las líneas separadas por COMAS, no por
    # saltos. Reconstruirla es lo que la vuelve pegable en una CLI.
    _MAX_BACKUP_XML = 200_000

    @mcp.tool()
    def pt_backup_config(device: str, include_xml: bool = False) -> str:
        """
        Supports the boot configuration of a PT device. 
        
        Returns the actual startup-config (the one that the team rereads when rebooting), 
        plus its serial number, config-register, boot and uptime images. It is used to 
        store a known state before touching something, or to Compare two teams. 
        
        Parameters: 
        - device: name of the router or switch in PT. 
        - include_xml: If True, add the full device dump to XML (topology + config + modules). 
        There are tens of thousands of characters: Useful for filing, heavy for reading. 
        
        Example: pt_backup_config(device="R1")
        """
        err = _check_bridge()
        if err:
            return err

        dev = json.dumps(device.strip())
        want_xml = "true" if include_xml else "false"
        js = (
            "try {"
            f"  var __d = ipc.network().getDevice({dev});"
            "  if (!__d) { reportResult(JSON.stringify({ found: false })); }"
            "  else if (typeof __d.getStartupFile !== 'function') {"
            "    reportResult(JSON.stringify({ found: true, supported: false }));"
            "  } else {"
            "    var __out = { found: true, supported: true,"
            "      startup: String(__d.getStartupFile() || ''),"
            "      model: (typeof __d.getModel === 'function') ? __d.getModel() : '',"
            "      hostname: (typeof __d.getHostName === 'function') ? __d.getHostName() : '',"
            "      serial: (typeof __d.getSerialNumber === 'function') ? __d.getSerialNumber() : '',"
            "      config_register: (typeof __d.getConfigRegister === 'function')"
            "        ? __d.getConfigRegister() : null,"
            "      uptime: (typeof __d.getUpTime === 'function') ? __d.getUpTime() : null,"
            "      boot_systems: (typeof __d.getBootSystems === 'function')"
            "        ? String(__d.getBootSystems() || '') : '' };"
            f"    if ({want_xml} && typeof __d.serializeToXml === 'function') {{"
            f"      __out.xml = String(__d.serializeToXml() || '').substring(0, {_MAX_BACKUP_XML});"
            "    }"
            "    reportResult(JSON.stringify(__out));"
            "  }"
            "} catch (__e) { reportResult('ERROR:' + __e); }"
        )

        raw = _bridge_send_and_wait(js, timeout=20.0)
        if raw is None:
            return _TIMEOUT_MSG
        if raw.startswith("ERROR:"):
            return f"PT error: {raw}"
        try:
            data = json.loads(raw)
        except Exception as exc:
            return f"PT illegible response: {exc}"

        if not data.get("found"):
            return (
                f"'{device}' does not exist in the active topology. "
                "Use pt_query_topology to see the real names."
            )
        if not data.get("supported"):
            return f"'{device}' does not have startup-config (PT hosts do not)."

        startup = data.pop("startup", "")
        lines = [ln for ln in startup.split(",") if ln != ""]
        data["startup_config"] = "\n".join(lines)
        data["startup_lines"] = len(lines)
        if not lines:
            data["summary"] = (
                f"'{device}' has no startup-config saved. "
                "Run 'write memory' on the computer before backing up."
            )
        else:
            data["summary"] = (
                f"{len(lines)} startup-config line(s) of '{device}' "
                f"({data.get('model')}, serial {data.get('serial')})."
            )
        return json.dumps(data, indent=2, ensure_ascii=False)

    @mcp.tool()
    def pt_project_metadata(description: str = "") -> str:
        """
        Reads (and optionally writes) the metadata of the project open in PT. 
        
        Returns the saved file, the version of PT that wrote it, and the 
        description of the project, along with the count of devices and links. 
        Useful to know what you are working with before modifying something. 
        
        Parameters: 
        - description: if indicated, REPLACES the project description. 
        Empty = read-only. 
        
        Example: pt_project_metadata()
        """
        err = _check_bridge()
        if err:
            return err

        new_desc = description.strip()
        setter = (
            f"  if (typeof __f.setNetworkDescription === 'function') "
            f"{{ __f.setNetworkDescription({json.dumps(new_desc)}); }}"
            if new_desc else ""
        )
        js = (
            "try {"
            "  var __a = ipc.appWindow();"
            "  var __f = __a.getActiveFile();"
            "  if (!__f) { reportResult(JSON.stringify({ found: false })); } else {"
            + setter +
            "    var __n = ipc.network();"
            "    reportResult(JSON.stringify({"
            "      found: true,"
            "      saved_filename: String(__f.getSavedFilename() || ''),"
            "      pt_version: String(__f.getVersion() || ''),"
            "      description: String(__f.getNetworkDescription() || ''),"
            "      devices: __n.getDeviceCount(), links: __n.getLinkCount()"
            "    }));"
            "  }"
            "} catch (__e) { reportResult('ERROR:' + __e); }"
        )

        raw = _bridge_send_and_wait(js, timeout=10.0)
        if raw is None:
            return _TIMEOUT_MSG
        if raw.startswith("ERROR:"):
            return f"PT error: {raw}"
        try:
            data = json.loads(raw)
        except Exception as exc:
            return f"PT illegible response: {exc}"

        if not data.get("found"):
            return "PT does not have any active network files."

        data["updated_description"] = bool(new_desc)
        saved = data.get("saved_filename") or ""
        data["summary"] = (
            f"{data['devices']} device(s), {data['links']} link(s). "
            + (f"File: {saved}." if saved 
               else "Project NO saving — use pt_save_project to persist.") 
               + ("Updated description." if new_desc else "")
        )
        return json.dumps(data, indent=2, ensure_ascii=False)

    @mcp.tool()
    def pt_workspace_options(
        auto_cabling: int = -1,
        external_network_access: int = -1,
        show_port_labels: int = -1,
        show_link_lights: int = -1,
        show_device_labels: int = -1,
    ) -> str:
        """
        Reads and adjusts PT workspace settings that affect how it behaves. 
        
        No arguments is read-only. Flags are tri-state: 1 active, 
        0 deactivates, -1 (default) does not touch. 
        
        Parameters: 
        - auto_cabling: PT's auto-wiring chooses the cable and port for you. 
        Turn it off before building topologies by script if you want control 
        exact which port is used. 
        - external_network_access: Allows PT to reach the REAL network of the 
        machine. Off by default; turning it on takes traffic out of the simulator. 
        - show_port_labels/show_link_lights/show_device_labels: What You See 
        In the canvas. It matters for a screenshot to be readable. 
        
        Example: turning off auto-cabling before a scripted deploy:
          pt_workspace_options(auto_cabling=0)
        """
        err = _check_bridge()
        if err:
            return err

        def _opt_set(method: str, args: str) -> str:
            """An isolated setter: if PT rejects him, he falls alone and reports. 
            
            Everyone goes in their own try/catch on purpose. Before, everyone went 
            under it, so a setter that failed—'setHideDevLabel' with the wrong 
            arity—aborted the whole round and returned a mistake raw, but the previous 
            ones had ALREADY been applied: the user saw "failed" with half of the changes 
            put in. 
            """
            return (
                f"    try {{ if (typeof __o.{method} === 'function')"
                f" {{ __o.{method}({args}); __applied.push('{method}'); }}"
                f" else {{ __failed.push('{method}: no existe'); }} }}"
                f" catch (__se) {{ __failed.push('{method}: ' + __se); }}"
            )

        # Polarity and arity live in WORKSPACE_SETTERS / 
        # WORKSPACE_EXTRA_ARG (module level) to be able to test them without PT.
        sets: list[str] = []
        for flag, value in (
            ("auto_cabling", auto_cabling),
            ("show_device_labels", show_device_labels),
            ("external_network_access", external_network_access),
            ("show_port_labels", show_port_labels),
            ("show_link_lights", show_link_lights),
        ):
            if value in (0, 1):
                sets.append(_opt_set(*workspace_setter_call(flag, value)))

        js = (
            "try {"
            "  var __o = ipc.options();"
            "  var __applied = []; var __failed = [];"
            + "".join(sets) +
            "  reportResult(JSON.stringify({"
            "    applied: __applied, failed: __failed,"
            "    auto_cabling: !__o.isAutoCablingDisabled(),"
            "    external_network_access: !!__o.isExternalNetworkAccessEnabled(),"
            "    show_port_labels: !!__o.isPortShown(),"
            "    show_link_lights: !!__o.isLinkLightsShown(),"
            "    show_device_labels: !__o.isHideDevLabel(),"
            "    using_metric: !!__o.isUsingMetric(),"
            "    language: String(__o.getCurrentLanguage() || ''),"
            "    config_path: String(__o.getConfigFilePath() || '')"
            "  }));"
            "} catch (__e) { reportResult('ERROR:' + __e); }"
        )

        raw = _bridge_send_and_wait(js, timeout=10.0)
        if raw is None:
            return _TIMEOUT_MSG
        if raw.startswith("ERROR:"):
            return f"PT error: {raw}"
        try:
            data = json.loads(raw)
        except Exception as exc:
            return f"PT illegible response: {exc}"

        # What PT really accepted, not what was tried: counting the attempts 
        # gave "5 options changed" even though one had been rejected.
        applied = data.get("applied") or []
        failed = data.get("failed") or []
        data["changed"] = len(applied)
        notes = []
        if not data["auto_cabling"]:
            notes.append("auto-cabling OFF (ports are chosen by you)")
        if data["external_network_access"]:
            notes.append("⚠ REAL network access enabled")
        if failed:
            notes.append(f" ⚠ {len(failed)} option(s) rejected by PT: {'; '.join(failed)}")
        data["summary"] = (
            f"{len(applied)} option(s) changed. "if sets else "Read only. "
        ) + ("; ". join(notes) if notes else "Default settings.")
        return json.dumps(data, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # NETFLOW — is configured by native API, not CLI
    # ------------------------------------------------------------------

    @mcp.tool()
    def pt_apply_netflow(
        device: str,
        name: str,
        destination_ip: str = "",
        udp_port: int = 2055,
        version: int = 9,
        source_port: str = "",
        monitors: list[str] | None = None,
        remove: bool = False,
        dry_run: bool = False,
    ) -> str:
        """
        Configures a NetFlow exporter on a PT appliance. 
        
        Unlike the rest of the advanced features, NetFlow does NOT go by CLI: 
        it is it is directly configured and reread to verify that it was applied. 
        Yes the name already exists, it is reconfigured instead of duplicated. 
        
        Parameters: 
        - device: router where the exporter lives. 
        - name: name of the exporter (e.g. "COLLECTOR-1"). 
        - destination_ip: IP of the collector. Without this, the exporter is inert. 
        - udp_port: UDP port of the collector (default 2055). 
        - Version: 9 (templates, recommended) or 5 (fixed format). 
        - source_port: source interface; empty = PT chooses it. 
        - monitors: names of monitors to be associated. 
        - remove: if True, delete the 'name' exporter instead of creating it. 
        - dry_run: If True, it only validates and returns the payload without 
        touching PT. 
        
        Example: Export to a collector on 192.168.0.50:
          pt_apply_netflow(device="R1", name="COLLECTOR-1", destination_ip="192.168.0.50")
        """
        cfg = NetflowExporter(
            device=device, name=name, destination_ip=destination_ip.strip(),
            udp_port=udp_port, version=version, source_port=source_port.strip(),
            monitors=monitors or [],
        )

        res = validate_netflow(cfg)
        errors = list(res.errors)
        warnings = list(res.warnings)

        bridge_ok = _pick_channel() != ""
        if bridge_ok:
            try:
                topo = validate_netflow_against_topology(cfg, _live_devices())
                errors.extend(topo.errors)
                warnings.extend(topo.warnings)
            except Exception as exc:  # pragma: no cover
                warnings.append(PlanError(
                    code=ErrorCode.VALIDATION_ERROR, device=cfg.device,
                    message=f"Could not be validated against PT: {exc}", 
                    suggestion="Check the bridge with pt_bridge_status.",
                ))

        dev = json.dumps(cfg.device)
        exporter = json.dumps(cfg.name)
        if remove:
            body = (
                f"    __m.removeNFExporter({exporter});"
                "    reportResult(JSON.stringify({ found: true, supported: true,"
                "      removed: true, exporters: __m.getNFExporterCount() }));"
            )
        else:
            sets = [f"      __e.setExporterVersion({int(cfg.version)});"]
            if cfg.destination_ip:
                sets.append(f"      __e.setDestinationAddr({json.dumps(cfg.destination_ip)});")
            sets.append(f"      __e.setDestinationUdpPort({int(cfg.udp_port)});")
            if cfg.source_port:
                sets.append(f"      __e.setSrcPort({json.dumps(cfg.source_port)});")
            for monitor in cfg.monitors:
                sets.append(f"      __e.addMonitor({json.dumps(monitor)});")
            body = (
                f"    var __e = __m.getNFExporterByName({exporter});"
                "    var __created = false;"
                f"    if (!__e) {{ __e = __m.createNFExporter({exporter}); __created = true; }}"
                f"    if (!__e) {{ reportResult(JSON.stringify({{ found: true, supported: true,"
                "      error: 'no se pudo crear el exportador' })); } else {"
                + "".join(sets) +
                "      reportResult(JSON.stringify({ found: true, supported: true,"
                "        created: __created, name: __e.getExporterName(),"
                "        version: __e.getExporterVersion(),"
                "        destination: String(__e.getDestinationAddr()),"
                "        udp_port: __e.getDestinationUdpPort(),"
                "        fully_configured: !!__e.isFullyConfigured(),"
                "        exporters: __m.getNFExporterCount() }));"
                "    }"
            )

        js = (
            "try {"
            f"  var __d = ipc.network().getDevice({dev});"
            "  if (!__d) { reportResult(JSON.stringify({ found: false })); }"
            "  else if (typeof __d.getNetflowExporterManager !== 'function') {"
            "    reportResult(JSON.stringify({ found: true, supported: false }));"
            "  } else {"
            "    var __m = __d.getNetflowExporterManager();"
            + body +
            "  }"
            "} catch (__e2) { reportResult('ERROR:' + __e2); }"
        )

        payload = {
            "valid": not errors,
            "errors": [e.to_dict() for e in errors],
            "warnings": [w.to_dict() for w in warnings],
            "js_payload": js,
            "dry_run": dry_run,
            "sent": False,
        }

        if errors:
            payload["summary"] = f" ❌ NetFlow: {len(errors)} error(s); nothing was sent."
            return json.dumps(payload, indent=2, ensure_ascii=False)
        if dry_run:
            payload["summary"] = "✅ NetFlow valid. Mode dry_run — NOT sent to the bridge."
            return json.dumps(payload, indent=2, ensure_ascii=False)

        err = _check_bridge()
        if err:
            return err

        raw = _bridge_send_and_wait(js, timeout=15.0)
        if raw is None:
            return _TIMEOUT_MSG
        if raw.startswith("ERROR:"):
            return f"PT error: {raw}"
        try:
            data = json.loads(raw)
        except Exception as exc:
            return f"PT illegible response: {exc}"

        if not data.get("found"):
            return (
                f"'{device}' does not exist in the active topology. "
                "Use pt_query_topology to see the real names."
            )
        if not data.get("supported"):
            return f"'{device}' does not expose NetFlow (PT switches and hosts do not)."

        payload.update(data)
        payload["sent"] = True
        if remove:
            payload["summary"] = f" ✅ Exporter '{name}' removed from {device}."
        elif data.get("fully_configured"):
            payload["summary"] = (
                f" ✅ '{name}' {'created' if data.get('created') else 'updated'} in {device} "
                f"→ {data.get('destination')}:{data.get('udp_port')} (v{data.get('version')})."
            )
        else:
            payload["summary"] = (
                f" ⚠ '{name}' exists in {device} but PT reports it incomplete: "
                "Without a destination, it does not export flows."
            )
        return json.dumps(payload, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # QoS — SOLO LECTURA: la API de PT no permite crear class/policy-maps
    # ------------------------------------------------------------------

    @mcp.tool()
    def pt_read_qos(device: str) -> str:
        """
        Reads the REAL QoS settings for a device: class-maps and policy-maps. 
        
        Read Only: QoS cannot be created programmatically in PT, so for CONFIGURE it, 
        you have to send the IOS CLI with pt_send_raw ('configureIosDevice'). 
        This tool is used to verify that it was applied. 
        
        Returns, by class-map, its match type and its CLI representation; by policy-map, 
        how many classes it has and what features it uses (bandwidth, priority, shaping, 
        fair-queue). 
        
        Parameters: 
        - device: name of the router in PT. 
        
        Example: pt_read_qos(device="R1")
        """
        err = _check_bridge()
        if err:
            return err

        dev = json.dumps(device.strip())
        js = (
            "try {"
            f"  var __d = ipc.network().getDevice({dev});"
            "  if (!__d) { reportResult(JSON.stringify({ found: false })); }"
            "  else if (typeof __d.getClassMapManager !== 'function') {"
            "    reportResult(JSON.stringify({ found: true, supported: false }));"
            "  } else {"
            "    var __cm = __d.getClassMapManager();"
            "    var __pm = (typeof __d.getPolicyMapManager === 'function')"
            "      ? __d.getPolicyMapManager() : null;"
            "    var __cs = [], __ps = [];"
            "    var __cn = __cm.getClassMapCount();"
            "    for (var __i = 0; __i < __cn; __i++) {"
            "      try {"
            "        var __c = __cm.getClassMapAt(__i);"
            "        if (!__c) continue;"
            "        __cs.push({ name: __c.getMapName(), description: __c.getDescription(),"
            "          match: __c.getMatchTypeString(), statements: __c.getStatementCnt(),"
            "          is_default: !!__c.isClassDefault(), cli: __c.toString() });"
            "      } catch (__ce) {}"
            "    }"
            "    if (__pm) {"
            "      var __pn = __pm.getPolicyMapCount();"
            "      for (var __j = 0; __j < __pn; __j++) {"
            "        try {"
            "          var __p = __pm.getPolicyMapAt(__j);"
            "          if (!__p) continue;"
            "          __ps.push({ name: __p.getMapName(), classes: __p.getClassCnt(),"
            "            total_bandwidth: __p.getTotalBandwidth(),"
            "            bandwidth: !!__p.isBandwidthConfigured(),"
            "            priority: !!__p.isPriorityConfigured(),"
            "            shaping: !!__p.isShapeConfigured(),"
            "            fair_queue: !!__p.isFairQueueConfigured(),"
            "            cli: __p.toString(true) });"
            "        } catch (__pe) {}"
            "      }"
            "    }"
            "    reportResult(JSON.stringify({ found: true, supported: true,"
            "      class_maps: __cs, policy_maps: __ps }));"
            "  }"
            "} catch (__e) { reportResult('ERROR:' + __e); }"
        )

        raw = _bridge_send_and_wait(js, timeout=15.0)
        if raw is None:
            return _TIMEOUT_MSG
        if raw.startswith("ERROR:"):
            return f"PT error: {raw}"
        try:
            data = json.loads(raw)
        except Exception as exc:
            return f"PT illegible response: {exc}"

        if not data.get("found"):
            return (
                f"'{device}' does not exist in the active topology. "
                "Use pt_query_topology to see the real names."
            )
        if not data.get("supported"):
            return f"'{device}' does not expose QoS (PT hosts do not)."

        cmaps = data.get("class_maps", [])
        pmaps = data.get("policy_maps", [])
        custom = [c for c in cmaps if not c.get("is_default")]
        data["summary"] = (
            f"{len(cmaps)} class-map(s) ({len(custom)} own(s)), "
            f"{len(pmaps)} policy-map(s). QoS is read-only per API: "
            "to configure it use IOS CLI."
        )
        return json.dumps(data, indent=2, ensure_ascii=False)
