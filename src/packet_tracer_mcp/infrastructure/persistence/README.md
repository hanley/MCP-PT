# infrastructure/persistence/

Persistencia de proyectos — guardar, cargar y listar topologías en disco.

## Archivos

### `project_repository.py` — Repositorio de proyectos

Project persistence — saving, loading, and listing topologies on disk.

```python
class ProjectRepository:
    def __init__(base_dir="projects")
    def save_plan(plan, project_name) → Path
    def load_plan(project_name) → TopologyPlan
    def list_projects() → list[dict]
    def delete_project(project_name) → bool
```

**Structure of a saved project:** 

``` 
projects/ 
└── mi_topologia/
 ├── plan.json ← TopologyPlan serialized (Pydantic JSON) 
 └── metadata.json ← Metadata of the project
**Estructura de un proyecto guardado:**
```

**Methods:** 

| Method | Description | 
|--------|-------------| 
| `save_plan(plan, name)` | Serialize the plan as JSON + generate metadata (name, date, counts, is_valid) | 
| `load_plan(name)` | Deserialize JSON → `TopologyPlan` via `model_validate_json()` | 
| `list_projects()` | Scan the base directory, return list of metadata by project | 
| `delete_project(name)` | Deletes directory from the entire project (`shutil.rmtree`) |

**Generated Metadata:**
```json
{
  "project_name": "mi_topology",
  "created_at": "2026-03-25T10:00:00+00:00",
  "devices": 8,
  "links": 7,
  "is_valid": true
}
```

Note: The default base directory is `projects/` relative to the CWD of the server. The `pt_list_projects` and `pt_load_project` MCP tools use this repository directly.

**Important — this is NOT the same as saving the Packet Tracer file.** 
`ProjectRepository` persists the **PLAN** (the `TopologyPlan` as `plan.json`), which is the Description of the server-side topology. Distinct from MCP tools `pt_save_project` / `pt_open_project`, which save/open the REAL Packet **`.pkt` file Tracer** via the bridge (not the JSON plan). In summary:

| | What to save/open | How to | 
|--|-----------------|------| 
| `ProjectRepository` (`pt_list_projects` / `pt_load_project`) | The PLAN (`plan.json` + metadata) | Disk, this repository | 
| `pt_save_project` / `pt_open_project` | PT's REAL `.pkt` file | Bridge to Packet Tracer |
