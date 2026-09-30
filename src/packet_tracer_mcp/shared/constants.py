"""System constants."""

# Default router/switch
DEFAULT_ROUTER = "2911"
DEFAULT_SWITCH = "2960-24TT"

# Layout (position in pixels for the Packet Tracer canvas)
LAYOUT_X_START = 100
LAYOUT_Y_ROUTER = 100
LAYOUT_Y_SWITCH = 250
LAYOUT_Y_PC = 400
LAYOUT_X_SPACING = 250
LAYOUT_PC_X_SPACING = 80
LAYOUT_CLOUD_X_OFFSET = 150

# IP defaults
DEFAULT_LAN_BASE = "192.168.0.0/16"
DEFAULT_LINK_BASE = "10.0.0.0/16"
DEFAULT_LAN_PREFIX = 24
DEFAULT_LINK_PREFIX = 30
DEFAULT_DNS = "8.8.8.8"

# System capabilities (so the LLM knows what we support). 
# 
# NOTE: the source of truth for what *tools* exist is the live MCP log — 
# 'pt://capabilities' introspects the actual tools and derives 'nat'/'acl'/'modules'/... 
# over there (see resource_registry.py), so this list can NOT lie again as 
# before (it said nat="unsupported" while pt_apply_nat existed). The bottom are the 
# Base values that the resource dynamically enriches.

CAPABILITIES = {
    "version": "0.8.0",
    "routing": ["static", "static_floating", "ospf", "eigrp", "rip", "none"],
    "features": ["dhcp", "wan", "switching", "auto_fix", "explain", "dry_run",
                 "floating_routes", "ospf_multi_process", "eigrp_as_config",
                 "acl_standard", "acl_extended", "acl_apply_via_bridge",
                 "nat_static", "nat_dynamic", "nat_pat",
                 "modules", "module_compat_check", "live_deploy", "raw_js",
                 # Reading the living state: they do not consult the plan, they consult the 
                 # device. Verified against PT 9.0.0.0810.
                 "security_audit", "port_inspect", "vlan_read", "device_power",
                 "simulation_mode", "simulation_step", "packet_trace",
                 "netflow", "qos_read",
                 "config_backup", "project_metadata", "workspace_options",
                 "screenshot", "canvas_annotations"],
    # Supported TODAY via IOS Raw CLI (configureIosDevice / pt_send_raw) but without tool 
    # dedicated to high level still — candidates for future expansion, NOT "impossible". 
    # vlan/trunk/stp/port_security/IPv6 came out of here: they already have their own tool. 
    # QoS stays: can be READ with pt_read_qos but not created by API.
    
    "supported_via_cli": ["qos", "bgp", "hsrp", "voip"],
    # Genuinely not implemented in any form. Originating a PDU is not: 
    #PT doesn't expose you to extensions (the "Add Simple PDU" is GUI only).

    "unsupported": ["originate_pdu"],
    "max_routers": 20,
    "max_pcs_per_lan": 24,
    "max_switches_per_router": 4,
}

# PT IpcAPI DeviceType enum values (de class_logical_workspace.html addDevice doc). 
# Used by lwAddDevice helper to create visible devices in the Logical view 
# (the global addDevice only writes to the physical model + canvas, not the logical one.)

PT_DEVICE_TYPE = {
    "router": 0,
    "switch": 1,
    "cloud": 2,
    "bridge": 3,
    "hub": 4,
    "repeater": 5,
    "splitter": 6,
    "accesspoint": 7,
    "pc": 8,
    "server": 9,
    "printer": 10,
    "wireless_router": 11,
    "ip_phone": 12,
    "modem": 13,
    "remote_network": 15,
    "multilayer_switch": 16,
    "laptop": 17,
    "tablet": 18,
    "pda": 19,
    "wireless_end_device": 20,
    "wired_end_device": 21,
    "tv": 22,
    "voip": 23,
    "analog_phone": 24,
    "firewall": 26,
    "iot": 27,
    "home_gateway": 28,
    "cell_tower": 29,
    "central_office": 30,
    "sniffer": 33,
    "mcu": 34,
    "sbc": 35,
    "thing": 36,
    "embedded_server": 38,
}

# Default PT DeviceType when the category is not on the map. eWiredEndDevice (21) 
# is the most permissive — it works for any generic device with a wired interface.

PT_DEVICE_TYPE_DEFAULT = 21

# PT IpcAPI CONNECT_TYPES enum values (de class_logical_workspace.html createLink doc).
PT_CONNECT_TYPE = {
    "straight": 8100,
    "cross": 8101,
    "crossover": 8101,
    "roll": 8102,
    "fiber": 8103,
    "phone": 8104,
    "cable": 8105,
    "serial": 8106,
    "auto": 8107,
    "console": 8108,
    "wireless": 8109,
    "coaxial": 8110,
    "octal": 8111,
    "cellular": 8112,
    "usb": 8113,
    "custom_io": 8114,
}

PT_CONNECT_TYPE_DEFAULT = 8107  #AUTO — lets PT detect the right type


# Masks lookup
PREFIX_TO_MASK = {
    8:  "255.0.0.0",
    16: "255.255.0.0",
    24: "255.255.255.0",
    25: "255.255.255.128",
    26: "255.255.255.192",
    27: "255.255.255.224",
    28: "255.255.255.240",
    29: "255.255.255.248",
    30: "255.255.255.252",
    32: "255.255.255.255",
}
