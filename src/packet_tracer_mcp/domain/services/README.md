# domain/services/

6 business services that implement all the logic of planning, validation, and transformation of topologies. They do not depend on infrastructure — only on domain models. 

## Archives 

### 'orchestrator.py' — Main Pipeline

Transform a `TopologyRequest` into a complete and validated `TopologyPlan`. 

**Main Function:**

```python
plan_from_request(request: TopologyRequest) → tuple[TopologyPlan, ValidationResult]
```

**Internal pipeline:** 
1. Normalize `pcs_per_lan` and `laptops_per_lan` (expand int → list per router) 
2. `_create_devices()` — Create routers, switches, PCs, laptops, APs, servers, cloud 
3. `_create_links()` — Connect devices according to template (router↔router,  router↔switch, switch↔PC, etc.) 
4. `ip_planner.plan_addressing()` — Assign IPs, DHCP pools, routes 
5. `_create_validations()` — Generates post-deployment ping tests 
6. `validate_plan()` — Final validation of the plan

**Automatic layout:** Calculates X/Y positions based on `shared/constants.py` constants for visual distribution on the PT canvas. 

**Helper functions:** 
- `_normalize_pcs(value, count)` — Converts int to replicated list 
- `_normalize_laptops(value, count)` — Same for laptops

---

### `ip_planner.py` — IP Addressing Engine 

Assign IP addresses to all interfaces, configure DHCP, and generate routes. 

**Class:** `IPPlanner`

| Method | Description | 
|--------|-------------| 
| `__init__(lan_base, link_base)` | Initialize Subnet Generators | 
| `next_lan_subnet()` | Next /24 subnet for LAN | 
| `next_link_subnet()` | Next /30 subnet for inter-router link | 
| `plan_addressing(plan, routing, dhcp,...)` | Full Allocation Pipeline | 

**Addressing scheme:** 
- **LANs:** `192.168.x.0/24` — Gateway = `.1`, PCs from `.2` 
- **Inter-router:** `10.0.x.0/30` — 2 hosts per link

**Route generation:** 
| Method | Protocol | Description | 
|--------|-----------|-------------| 
| `_plan_static_routes()` | static | BFS Discovery + IP Route Generation | 
| `_plan_ospf()` | OSPF | router-id, networks with wildcard mask, area 0 | 
| `_plan_rip()` | RIP v2 | networks classful, not auto-summary | 
| `_plan_eigrp()` | EIGRP | AS number, wildcard networks, not auto-summary | 
| `_plan_floating_static_routes()` | static (backup) | Alternate paths with AD=254 |

---

### 'validator.py' — Validation Orchestrator 

Runs all validation rules on a plan. 

**Main Function:**
```python
validate_plan(plan: TopologyPlan) → ValidationResult
```

**Flow:** Call sequentially to: 
1. `validate_devices(plan)` — from `rules/device_rules.py` 
2. `validate_links(plan)` — from `rules/cable_rules.py`
3. `validate_ips(plan)` — from `rules/ip_rules.py` 
4. `validate_dhcp(plan)` — from `rules/ip_rules.py` 

Sync errors/warnings back to `plan.errors` and `plan.warnings` for compatibility.

---

### 'auto_fixer.py' — Auto-correct errors 

Automatically corrects common errors in malformed plans. 

**Main Function:**
```python
fix_plan(plan: TopologyPlan) → tuple[TopologyPlan, list[str]]
```

Returns the corrected plan + list of applied fixes (human-readable). 

**Fixes available:** 
| Internal fix | What it fixes | 
|-------------|-------------| 
| `_fix_cables()` | Incorrect cable type → infers the correct one according to categories | 
| `_fix_insufficient_ports()` | Router without enough GigE ports → upgrade to model 2911 | 
| `_fix_invalid_ports()` | Non-existent port → reassigned to the first available valid port |

---

### 'explainer.py' — Explanation Generator 

Produces natural language explanations of plan decisions. 

**Main Function:**
```python
explain_plan(plan: TopologyPlan) → list[str]
```

**Generate explanations about:** 
- Device count by category 
- Subnet strategy (LANs and links) 
- Types of cable used and reason 
- DHCP configuration (pools, exclusions) 
- Routing and configuration protocol 
- Validation tests included

---

### 'estimator.py' — Estimate without full build 

Dry-run that estimates complexity and resources without generating the complete plan. 

**Features:** 
| Function | Input | Output | 
|---------|---------|--------| 
| `estimate_from_request(request)` | `TopologyRequest` | `dict` with estimated counts | 
| `estimate_from_plan(plan)` | `TopologyPlan` | `dict` with actual counts + status | 
| `_estimate_complexity(req)` | `TopologyRequest` | `str`: "simple", "moderate", "complex", "very complex" | 

**Complexity criteria:** 
- **Simple:** ≤2 routers, no WAN, static routing 
- Moderate: 3–4 routers, or OSPF/EIGRP 
- **Complex:** 5–8 routers, or WAN + dynamic routing 
- **Very complex:** 9+ routers