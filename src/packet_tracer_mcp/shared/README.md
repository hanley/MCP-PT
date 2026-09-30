# shared/

Utilities, constants, and enumerations shared by all layers of the project. 

## Archives

### `constants.py`
System constants used globally: 

| Constant | Value | Description | 
|-----------|-------|-------------| 
| `DEFAULT_ROUTER` | `"2911"` | Default Router Model | 
| `DEFAULT_SWITCH` | `"2960-24TT"` | Default Switch Model | 
| `LAYOUT_X_START`, `LAYOUT_Y_ROUTER`, etc. | px | Packet Tracer Canvas Positions for Automatic Layout | 
| `DEFAULT_LAN_BASE` | `"192.168.0.0/16"` | LAN Subnet Base (/24 default) | 
| `DEFAULT_LINK_BASE` | `"10.0.0.0/16"` | Inter-router link base (/30) | 
| `DEFAULT_DNS` | `"8.8.8.8"` | Default DNS Server | 
| `PREFIX_TO_MASK` | dict | Lookup CIDR → decimal mask (ex: 24 → 255.255.255.0) | 
| `CAPABILITIES` | dict | Supported features, limits, and version — exposed as MCP resource |

### `enums.py`
6 `str, Enum` enumerations for strong typing: 

| Enum | Values | Use | 
|------|---------|-----| 
| `RoutingProtocol` | Static, OSPF, EIGRP, RIP, None | Plan Routing Protocol | 
| `TopologyTemplate` | single_lan, multi_lan, star, hub_spoke, etc. (9 total) | Topology Template | 
| `DeviceCategory` | Router, Switch, PC, Server, Laptop, Cloud, AccessPoint | Device Category | 
| `DeviceRole` | core_router, branch_router, edge_router, access_switch, etc. | Semantic Role in Topology | 
| `CableType` | straight, cross, serial, fiber, console | Cable Type | 
| `PortSpeed` | FastEthernet, GigabitEthernet, Serial, Console | Port Speed |

### `utils.py`
3 Utility Functions: 

| Function | Signature | Description | 
|---------|-------|-------------| 
| `prefix_to_mask(prefix)` | `int → str` | CIDR to decimal mask (ex: 24 → "255.255.255.0") | 
| `wildcard_mask(network)` | `IPv4Network → str` | Calculate wildcard mask (for OSPF) | 
| `first_ip(interfaces)` | `dict → str` | Extract the first IP from an interface dict |