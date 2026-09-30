# packet_tracer_mcp 

MCP server core module for Cisco Packet Tracer. 

## Architecture 

Follow **Clean Architecture / Domain-Driven Design** with clear layer separation:

```
packet_tracer_mcp/ 
├── adapters/mcp/ → MCP protocol layer (tools + resources) 
├── application/ → Use cases + DTOs (input/output) 
├── domain/ → Pure business logic 
│ ├── models/ → Data Models (Plan, Request, Error) 
│ ├── services/ → Services (Orchestrator, IPPlanner, Validator...) 
│ └── rules/ → Validation rules (devices, cables, IPs) 
├── infrastructure/ → External concerns 
│ ├── catalog/ → Catalog of devices, cables, templates 
│ ├── generator/ → PTBuilder script generators + CLI configs 
│ ├── execution/ → Deployment strategies (manual, live bridge) 
│ └── persistence/ → Project persistence 
├── shared/ → Enums, constants, utilities 
├── server.py → MCP Entry Point 
├── settings.py → Global Settings 
└── __main__.py → Entry point: python -m packet_tracer_mcp
```

## Data flow

```-
Request → TopologyRequest → Orchestrator → TopologyPlan → Validator
                                                ↓
                                    Generator (PTBuilder JS + CLI configs)
                                                ↓
                                    Executor (Manual / Deploy / Live Bridge)
```

## Root Files 

| Archive | Purpose | 
|---------|-----------| 
| `server.py` | Create the `FastMCP` instance, register tools/resources, boot into HTTP (:39000) or stdio | 
| `__main__.py` | Entry point for `python -m packet_tracer_mcp` — invoke `server.main()` | 
| `settings.py` | Global constants: 'VERSION' (0.4.0), `SERVER_NAME`, 
`SERVER_INSTRUCTIONS` |


## Execution

```bash
# Streamable HTTP (default, port 39000)
python -m packet_tracer_mcp

# Modo stdio (debug/legacy)
python -m packet_tracer_mcp --stdio
```

## Dependencies between layers

```
adapters/mcp → application/use_cases → domain/services → domain/models
                                              ↓
                                    infrastructure/ (catalog, generator, execution)
                                              ↓
                                         shared/ (enums, constants, utils)
```

No circular dependencies. The `domain` layer never imports from `infrastructure` directly 
— communication is through interfaces.