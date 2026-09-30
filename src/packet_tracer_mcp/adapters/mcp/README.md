# adapters/mcp/ 

MCP protocol layer — records the tools and resources that the LLM can invoke. 

## Archives 

### 'tool_registry.py' 
**~3200 lines** — Monolithic register of the 46 MCP tools. 

Main function: `register_tools(mcp: FastMCP) → None` 

Each tool is defined as a function decorated with `@mcp.tool()` inside `register_tools()`.

The log not only declares the tools: it also resolves **which channel** each one travels on. command to Packet Tracer. When the extension window is open, the HTTP bridge (`127.0.0.1:54321`); when closed, the command is left as a file in the mailbox that the Script Engine reads to disk (see `_pick_channel` and the `infrastructure/execution/`). The server chooses **one** channel per command, never both.

#### Tools registradas (46)

| Group | Tool | Description | 
|-------|------|-------------| 
| **Query** | `pt_list_devices` | Catalog of devices with ports | 
| | `pt_list_templates` | Topology Templates Available | 
| | `pt_get_device_details` | Detail of a specific model | 
| | `pt_list_modules` | Expansion Modules for a Model | 
| **Estimate** | `pt_estimate_plan` | Dry-run without generating a full plan | 
| **Planning** | `pt_plan_topology` | Generate complete plan → JSON | 
| **Validation** | `pt_validate_plan` | Typed errors/warnings | 
| | `pt_fix_plan` | Auto-correction + re-validation | 
| | `pt_explain_plan` | Natural Language Explanation | 
| | `pt_diff` | Differences between plan and topology in PT |
| **Build** | `pt_generate_script` | PTBuilder JS Script (± configs) | 
| | `pt_generate_configs` | IOS CLI per device | 
| **Pipeline** | `pt_full_build` | Plan + validate + generate + explain + estimate | 
| **Deployment** | `pt_deploy` | Clipboard + Files + Instructions | 
| | `pt_export` | Files to disk only | 
| | `pt_export_topology` | Export PT Live Topology to Plan | 
| | `pt_live_deploy` | Direct deployment via bridge (HTTP or file) | 
| **Projects (JSON plan)** | `pt_list_projects` | List Saved Topologies (plan.json) | 
| | `pt_load_project` | Upload Project by Name (plan.json) | 
| **Projects (.pkt real)** | `pt_save_project` | Save PT's REAL `.pkt` via bridge | 
| | `pt_open_project` | Open a REAL PT `.pkt` via bridge | 
| **Verification** | `pt_verify_connectivity` | Real ping with result parsing | 
| | `pt_health_check` | Server/Environment Health Check | 
| | `pt_bridge_status` | Bridge status and connection to PT |
| **Interaction** | `pt_query_topology` | Check current devices/links in PT | 
| | `pt_add_device` | Add Device | 
| | `pt_delete_device` | Remove Device | 
| | `pt_rename_device` | Rename Device | 
| | `pt_move_device` | Move Device on Canvas | 
| | `pt_add_link` | Add Link (Validates Ports & Cable) | 
| | `pt_delete_link` | Remove link | 
| | `pt_set_port` | Configure a Port | 
| | `pt_send_raw` | Sending Arbitrary JS to the Script Engine | 
| **Modules** | `pt_add_module` | Installing a module in a slot | 
| | `pt_install_modules_batch` | Install multiple modules in batch |
| **Advanced Config** | `pt_apply_vlan` | Apply VLANs | 
| | `pt_apply_stp` | Apply Spanning Tree | 
| | `pt_apply_acl` | Apply ACL | 
| | `pt_apply_acl_object` | Apply Object-Based ACLs | 
| | `pt_remove_acl` | Remove ACL | 
| | `pt_remove_acl_object` | Remove ACLs from Objects | 
| | `pt_apply_nat` | Apply NAT | 
| | `pt_remove_nat` | Remove NAT | 
| | `pt_apply_port_security` | Apply port-security | 
| | `pt_apply_hardening` | Apply device hardening | 
| | `pt_apply_interface_tuning` | Interface Tuning |

### Internal helpers 
- `_pick_channel(...) ` — Routes each command via HTTP (:54321) or through the file mailbox depending on whether the extension window is open 
- `_http_get(url)` / `_http_post(url, data)` — HTTP communication with the bridge 
- `_js_escape(s)` — String escape for JS 
- `_bridge_is_up()` / `_bridge_pt_connected()` — Connectivity Check 

### `resource_registry.py` 
**~64 lines** — Record of 5 static MCP resources. 

Main function: `register_resources(mcp: FastMCP) → None`

| Resource URI | Content | 
|-------------|-----------| 
| `pt://catalog/devices` | Full Catalog of Ported Devices | 
| `pt://catalog/cables` | Available cable types | 
| `pt://catalog/aliases` | Common aliases → real model | 
| `pt://catalog/templates` | Templates with description, ranges, routing default | 
| `pt://capabilities` | Version, features, server limits |