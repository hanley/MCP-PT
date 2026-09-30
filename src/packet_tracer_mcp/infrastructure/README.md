# infrastructure/

External concerns — device catalog, code generation, execution/deployment, and persistence.

## Structure

```
infrastructure/ 
├── catalog/ → Catalog of devices, cables, aliases, templates 
├── generator/ → PTBuilder script generators and CLI configs 
├── execution/ → Deployment (manual, clipboard) + channels to PT (HTTP bridge / file bridge) └── persistence/ → Save/load projects to disk
```

---

## catalog/ 

Data verified against Packet Tracer 8.x. All models use 'frozen=True'.(inmutables).

### 'devices.py' — Device Catalog 
**11 verified models:** 

| Model  | Category  | Notable Ports |
|--------|-----------|-----------------|
| `1941` | Router | 2× GigabitEthernet |
| `2901` | Router | 2× GigabitEthernet |
| `2911` | Router | 3× GigabitEthernet (default) |
| `ISR4321` | Router | 2× GigabitEthernet |
| `2960-24TT` | Switch | 24× FastEthernet + 2× GigabitEthernet (default) |
| `3560-24PS` | Switch | 24× FastEthernet + 2× GigabitEthernet |
| `PC-PT` | PC | 1× FastEthernet |
| `Server-PT` | Server | 1× FastEthernet |
| `Laptop-PT` | Laptop | 1× FastEthernet |
| `Cloud-PT` | Cloud | 1× Ethernet |
| `AccessPoint-PT` | AP | 1× FastEthernet |

**Important note:** No routers have serial ports by default — it requires HWIC modules. 

Functions: `resolve_model(name)`, `get_ports_by_speed(model, speed)`, `get_valid_ports(model`.

### `cables.py` — Cable Types 
5 Types: straight, cross, serial, fiber, console.

Automatic rules: 
- Router ↔ Router = **cross** 
- PC router ↔ = **cross** 
- Switch ↔ anything = **straight**

Function: `infer_cable(cat_a, cat_b) → str`

### 'aliases.py' — Model Aliases 
20+ common aliases an LLM might use: 
- `"router"` → `"2911"`, `"switch"` → `"2960-24TT"`, `"cloud"` → `"Cloud-PT"`, etc.

Dict: `MODEL_ALIASES`

### `templates.py` — Topology Templates
**9 TemplateSpec** (frozen dataclass):

| Template | Routers | Default Routing | Note |
|----------|---------|----------------|------|
| single_lan | 1 | none | 1 router, 1 LAN | 
| multi_lan | 2-6 | static | Multiple LANs connected | 
| multi_lan_wan | 2-6 | static | With WAN cloud | 
| star | 3-8 | static | star topology | 
| hub_spoke | 3-8 | static | Hub & spoke | 
| branch_office | 2-4 | OSPF | Branch Offices | 
| three_router_triangle | 3 | OSPF | 3 Router Triangle | 
| router_on_a_stick | 1 | none | Router-on-a-stick | 
| custom | 1-20 | static | No restrictions |

Function: `list_templates() → list[TemplateSpec]`

---

## generator/

### `ptbuilder_generator.py` — Scripts PTBuilder (JavaScript)
3 generation levels:

| Function | Includes | Application |
|---------|---------|-----|
| `generate_ptbuilder_script(plan)` | `addDevice()` + `addLink()` | Topology only | 
| `generate_executable_script(plan)` | + `configureIosDevice()` + `configurePcIp()` | Topology + configuration | 
| `generate_full_script(plan)` | + configs CLI as comments | All together |


### `cli_config_generator.py` — Configs CLI (IOS)
Generates ready-to-paste command blocks into router/switch terminal:

| Function | Description |
|---------|-------------|
| `generate_all_configs(plan)` | `dict[device_name, cli_block]` for all devices |
| `generate_pc_config(device, use_dhcp)` | PC Setup Instructions |

Supports: hostname, interfaces, DHCP pools (with excluded-address), static routes (with AD), OSPF (router-id + networks), RIP v2, EIGRP.

---

## execution/

Deployment executors + two communication channels with Packet Tracer.

### `executor_base.py` — Base Interface
Abstract class: `ExecutorBase`
- `execute(plan, project_name) → dict`
- `is_available() → bool`

### `manual_executor.py` — Export to disk 
Generates low files `projects/{safe_name}/`:
- `topology.js` — Script PTBuilder
- `full_build.js` — Script Complete with configs
- `{device}_config.txt` — Config CLI per device
- `plan.json` — Serialized Plan
- `metadata.json` — Timestamps, counts, name

### `deploy_executor.py` — Clipboard deployment
Extend ManualExecutor + copy `topology.js` to clipboard (Windows via `clip.exe`) + generate step-by-step instructions.

### Channels to PT — server chooses ONE per command

Live deployment sends batch plan commands. Depending on whether the If the 
extension is open or closed, the server routes each command over HTTP or through 
the mailbox (see `_pick_channel` in `adapters/mcp/tool_registry.py`), never by both.

### `live_bridge.py` — HTTP Bridge (open window) 
HTTP server on '127.0.0.1:54321' for two-way communication with PT:

| Endpoint | Method | Purpose | 
|----------|--------|-----------| 
| '/next' | GET | PT polls for next command | 
| '/queue' | POST | Python queues JS command | 
| '/ping' | GET | Heartbeat | 
| '/result' | POST | PT reports execution result | 
| '/status' | GET | PT Connectivity Status |

Class: `PTCommandBridge` — Singleton with `ThreadingHTTPServer`, thread-safe Queue, CORS. Authenticated with a self-generated local token (see `bridge_token.py`).

### `file_bridge.py` — File Bridge (window closed) 
File mailbox under `%LOCALAPPDATA%\packet-tracer-mcp\bridge\`: Server writes 
`req_*.js`, the Script Engine reads it, executes it and returns `res_*.txt`. 
Class: `FileBridge` — `send(js)`, `send_and_wait(js, timeout)`.

### `bridge_token.py` — HTTP bridge token 
Auto-generated local token (under `%LOCALAPPDATA%`) that authenticates the HTTP bridge. Without bootstrap manual it's pairing; server and extension read it from disk.

---

## persistence/

### `project_repository.py` — Project repository 
CRUD for disk-saved topologies: 

| Method | Description | 
|--------|-------------| 
| `save_plan(plan, name)` | Save plan.json + metadata.json | 
| `load_plan(name)` | Load TopologyPlan from JSON | 
| `list_projects()` | List Saved Project Names | 
| `delete_project(name)` | Delete project | 

Storage: `projects/{name}/plan.json` with timestamps timezone-aware.