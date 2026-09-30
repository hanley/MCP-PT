# domain/models/ 

Pydantic models that define the system's data contract. They are the language shared between all layers. 

## Archives 

### 'requests.py' — TopologyRequest 

LLM input model — defines which topology to build.

| Field | Type | Default | Description | 
|-------|------|---------|-------------| 
| `template` | `TopologyTemplate` | `multi_lan` | Topology Base Template | 
| `routers` | `int (1–20)` | `2` | Number of routers | 
| `switches_per_router` | `int (0–4)` | `1` | Switches connected to each router | 
| `pcs_per_lan` | `list[int] \| int` | `3` | PCs per LAN (int replicates to each router) | 
| `laptops_per_lan` | `list[int] \| int` | `0` | LAN Laptops | 
| `servers` | `int (0–10)` | `0` | Servers on the first LAN | 
| `access_points` | `int (0–10)` | `0` | Access Points | 
| `has_wan` | `Bool` | `False` | Include WAN cloud connected to the first router | 
| `dhcp` | `bool` | `True` | Enable DHCP Configuration on Routers |
| `routing` | `routingProtocol` | `static` | Routing Protocol | 
| `router_model` | `str` | `"2911"` | Router model to use | 
| `switch_model` | `str` | `"2960-24TT"` | Switch model to use | 
| `base_network` | `str` | `"192.168.0.0/16"` | LANs Baseline (/24) | 
| `inter_router_network` | `str` | `"10.0.0.0/16"` | Base Network for Inter-Router Links (/30) | 
| `floating_routes` | `bool` | `False` | Generate Static Backup Paths (AD=254) | 
| `ospf_process_id` | `int` | `1` | OSPF Process ID | 
| `eigrp_as` | `int` | `100` | EIGRP AS number |

---

### 'plans.py' — Plan Templates 

Complete and validated planning result. `TopologyPlan` is the central model of the system.

#### 'DevicePlan' 
It represents a particular device in the topology.

| Field | Type | Description | 
|-------|------|-------------| 
| `name` | `str` | Unique name (e.g.: `R1`, `SW1`, `PC1`) | 
| `model` | `str` | Catalog model (e.g. `2911`, `PC-PT`) | 
| `category` | `DeviceCategory` | Category (router, switch, pc, etc.) | 
| `role` | `DeviceRole \| None` | Semantic role (core_router, access_switch, etc.) | 
| `x`, `y` | `int` | Position on the Packet Tracer canvas | 
| `interfaces` | `dict[str, str]` | IP/CIDR → interface map (e.g.: `{"GigabitEthernet0/0": "192.168.1.1/24"}`) | 
| `gateway` | `str \| None` | Default gateway (PCs/servers only) |

#### 'LinkPlan' 
Physical connection between two devices. 

| Field | Type | Description | |-------|------|-------------| 
| `from_device` | `str` | Device Name A | 
| `from_port` | `str` | Port on device A | 
| `to_device` | `str` | Device Name B | 
| `to_port` | `str` | Port on device B | 
| `cable_type` | `CableType` | Cable Type (straight, cross, etc.) |

#### 'DHCPPool' 
Configuring DHCP pool on a router. 

| Field | Type | Description | 
|-------|------|-------------| 
| `pool_name` | `str` | Name of the pool (ex: `LAN1_POOL`) | 
| `router` | `str` | Router serving pool | 
| `network` | `str` | Pool network (e.g. `192.168.1.0`) | 
| `mask` | `str` | Mask (ex: `255.255.255.0`) | 
| `gateway` | `str` | Pool gateway (ex: `192.168.1.1`) | 
| `dns` | `str` | DNS server (default `8.8.8.8`) | 
| `excluded_start` | `str` | Start of Excluded Range | 
| `excluded_end` | `str` | End of Excluded Range |

#### 'StaticRoute' 
Static route for a router. 

| Field | Type | Description | 
|-------|------|-------------| 
| `destination` | `str` | destination network | 
| `mask` | `str` | Mask of Destiny | 
| `next_hop` | `str` | Next hop IP | 
| `admin_distance` | `int \| None` | Administrative distance (254 for floating) | 

#### 'OSPFConfig', 'RIPConfig', 'EIGRPConfig' 
Configuring dynamic routing protocols per router. 

#### 'ValidationCheck' 
Post-deployment verification testing (ping tests).

#### 'TopologyPlan' 
Central model that groups the entire plan: 

| Field | Type | Description | 
|-------|------|-------------| 
| `name` | `str` | Topology name | 
| `devices` | `list[DevicePlan]` | All Devices | 
| `links` | `list[LinkPlan]` | All links | 
| `dhcp_pools` | `list[DHCPPool]` | DHCP Pools | 
| `static_routes` | `dict[str, list[StaticRoute]]` | Router Routes | 
| `ospf_configs` | `dict[str, OSPFConfig]` | OSPF Config per router | 
| `rip_configs` | `dict[str, RIPConfig]` | Config RIP per router | 
| `eigrp_configs` | `dict[str, EIGRPConfig]` | Config EIGRP per router | 
| `validations` | `list[ValidationCheck]` | Verification tests | 
| `errors` | `list[dict]` | Validation errors | 
| `warnings` | `list[dict]` | Warnings | 
| `is_valid` | `bool` | Validation status |

**Methods:** `device_by_name(name)`, `devices_by_category(category)`


---

### 'errors.py' — Error taxonomy 

Error-typing system with 18 codes grouped by category.

#### 'ErrorCode' (Enum) 
| Code | Category | Description | 
|--------|-----------|-------------| 
| `UNKNOWN_DEVICE_MODEL` | Device | Model does not exist in catalog | 
| `DUPLICATE_DEVICE_NAME` | Device | Duplicate Name | 
| `INSUFFICIENT_PORTS` | Device | Not enough ports | 
| `DEVICE_NOT_FOUND` | Link | Referenced device does not exist | 
| `INVALID_PORT` | Link | Port does not exist in the model | 
| `PORT_ALREADY_USED` | Link | Port already occupied by another link | 
| `INVALID_CABLE_TYPE` | Link | Unknown cable type | 
| `INVALID_IP_ADDRESS` | IP | Invalid IP address |
| `SUBNET_OVERLAP` | IP | Overlapping subnets | 
| `IP_CONFLICT` | IP | Duplicate IP | 
| `DHCP_ROUTER_NOT_FOUND` | DHCP | Pool Router Does Not Exist | 
| `DHCP_GATEWAY_MISMATCH` | DHCP | Gateway does not match interface | 
| `UNSUPPORTED_ROUTING_PROTOCOL` | Routing | Unsupported Protocol | 
| `TEMPLATE_CONSTRAINT_VIOLATION` | Template | Parameters Violate Constraints | 
| `INVALID_INTERFACE_ASSIGNMENT` | IP | Invalid Interface | 
| `VALIDATION_ERROR` | General | Generic validation error |

#### 'PlanError' 
Individual error: 'code', 'message', 'device', 'suggestion', 'to_dict()'. 

#### 'ValidationResult' 
Collection of errors and warnings with 'is_valid' property (True if there are no errors).