# application/use_cases/

8 use cases that orchestrate the interaction between the MCP layer and the domain. 
They are thin wrappers — they convert DTOs into calls to domain services and format the response. 

## Design Principle 

Each use case: 
1. Receive a DTO or domain model 
2. Call one or more domain services 
3. Return a response DTO 

They don't contain business logic — that lives in 'domain/services/'.

## Archives 

### `plan_topology.py` 

```python 
plan_topology(dto: PlanTopologyDTO) → tuple[TopologyPlan, ValidationResult] 
``` 
Convert `PlanTopologyDTO` → `TopologyRequest` → `orchestrator.plan_from_request()`.

---

### `full_build.py` 
```python 
full_build(dto: PlanTopologyDTO) → BuildResponse 
``` 
Full pipeline: Plan → validate → generate script + configs → explain → estimate. 
It is the most used use case by `pt_full_build`.

---

### `validate_plan.py`
```python 
validate_plan_uc(plan: TopologyPlan) → ValidationResponse 
``` 
Wrapper on `validator.validate_plan()`.

---

### `fix_plan.py`
```python
fix_plan_uc(plan: TopologyPlan) → FixResponse
```
Call `auto_fixer.fix_plan()`, re-validate, return applied fixes and status.

---

### `explain_plan.py`
```python
explain_plan_uc(plan: TopologyPlan) → list[str]
```
Wrapper about `explainer.explain_plan()`.

---

### `generate_script.py`
```python
generate_script_uc(plan: TopologyPlan, include_configs: bool = True) → str
```
Generates PTBuilder JS script. With `include_configs=True` includes embedded 
CLI settings.

---

### `generate_configs.py`
```python
generate_configs_uc(plan: TopologyPlan) → dict[str, str]
```
Wrapper about `cli_config_generator.generate_all_configs()`. Return `{device_name: config_text}`.

---

### `export_artifacts.py`
```python
export_artifacts_uc(plan: TopologyPlan, output_dir: str) → ExportResponse
```
Wrapper on `ManualExecutor.execute()`. Exports all artifacts to disk.