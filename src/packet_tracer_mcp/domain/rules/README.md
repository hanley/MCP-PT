# domain/rules/

Independent validation rules organized by domain. Each file contains 
pure functions that receive a `TopologyPlan` and return lists of `PlanError`. 

They are invoked by the `validator.py` service — never directly from outside the domain. 

## Archives 

### 'device_rules.py' — Device Validation

```python
validate_devices(plan: TopologyPlan) → list[PlanError]
```

**Verifications:** 
| Check | ErrorCode | Description | 
|-------|-----------|-------------| 
| Duplicate Names | `DUPLICATE_DEVICE_NAME` | Two Devices with the Same Name | 
| Invalid model | `UNKNOWN_DEVICE_MODEL` | Model does not exist in the catalog of `devices.py` | 

--- 

### `cable_rules.py` — Link and cable validation

```python
validate_links(plan: TopologyPlan) → tuple[list[PlanError], list[PlanError]]
```

Return `(errors, warnings)` — warnings are for incorrect but not fatal cables. 

**Verifications:** 
| Check | ErrorCode | Description | 
|-------|-----------|-------------| 
| Device does not exist | `DEVICE_NOT_FOUND` | Link references a non-existent device | 
| Port does not exist | `INVALID_PORT` | Port does not exist on device model | 
| Reused port | `PORT_ALREADY_USED` | Same port used on two different links | 
| Unknown cable | `INVALID_CABLE_TYPE` | Cable type not recognized | 
| Incorrect Cable | (warning) | Cable is not recommended for that combination |

**Internal Helper:** 
- `_check_port(port, model_name)` — Validates that a port exists in the catalog model 

--- 

### `ip_rules.py` — IP and DHCP Validation

```python
validate_ips(plan: TopologyPlan) → list[PlanError]
validate_dhcp(plan: TopologyPlan) → list[PlanError]
```

**IP Checks:** 
| Check | ErrorCode | Description | 
|-------|-----------|-------------| 
| Invalid IP | `INVALID_IP_ADDRESS` | Incorrect IP Format | 
| Duplicate IP | `IP_CONFLICT` | Same IP assigned to two interfaces | 

**DHCP Checks:** 
| Check | ErrorCode | Description | 
|-------|-----------|-------------| 
| Router does not exist | `DHCP_ROUTER_NOT_FOUND` | Pool assigned to non-existent router | 
| Gateway does not match | `DHCP_GATEWAY_MISMATCH` | Pool gateway is not IP of any router interface |