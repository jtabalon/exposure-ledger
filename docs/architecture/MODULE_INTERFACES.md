# Module interfaces and test seams

## Selected Investigation interface

```python
class InvestigationRunner(Protocol):
    async def run(self, command: RunInvestigation) -> InvestigationRevision: ...
```

`RunInvestigation` identifies an existing Exposure, the evidence and execution budgets, and pinned configuration versions. The returned immutable revision contains the stopping condition, Claims, Evidence relationships, Recommendation, Policy Decisions, events, and operational measurements.

This is the selected external seam because it gives API and worker callers one correct operation while hiding graph stages, retry mechanics, source adapters, model payloads, checkpointing, and validation.

## Alternatives considered

### Stage-oriented interface

```python
await runner.acquire_evidence(exposure_id)
await runner.retrieve(exposure_id)
await runner.synthesize(exposure_id)
await runner.validate(exposure_id)
await runner.finalize(exposure_id)
```

This maximizes operational flexibility, but it is shallow: callers must understand ordering, intermediate state, retry behavior, and partial failure. It makes misuse easy and leaks LangGraph's shape into every caller.

### Event-command interface

```python
await bus.dispatch(StartInvestigation(exposure_id))
async for event in bus.subscribe(investigation_id): ...
```

This supports distributed execution and multiple consumers, but introduces command routing, correlation, delivery semantics, and eventual-consistency questions before the single-worker product needs them.

### Why the selected interface wins

The one-method runner has the smallest interface and greatest depth for the primary use case. Progress remains observable through persisted domain events, so the caller does not need control over internal stages. If multiple independent workers or event consumers later become real requirements, the event-command shape can be reconsidered without changing the domain model.

## Confirmed test seams

These seams were agreed during design and are the only initial surfaces tested directly:

1. **Recommendation policy:** a proposed Recommendation plus evidence state produces an accepted or safely downgraded decision.
2. **Cyber policy:** an operation produces an auditable allow, restrict, or block decision for a policy version.
3. **Asset snapshot:** a supported repository fixture produces a normalized snapshot or a typed rejection without executing content.
4. **Exposure discovery:** an Asset Snapshot plus captured OSV responses produces normalized Vulnerability Records and a deterministically ranked, package-specific Exposure queue.
5. **Source adapter contract:** each adapter turns captured provider responses into immutable Evidence Records under shared provenance rules.
6. **HTTP contract:** FastAPI exposes health, versioned resources, job creation, and SSE progress through OpenAPI.
7. **Workbench flow:** an operator can follow Exposure → Claim → Evidence and distinguish precomputed from live content.
8. **Retrieval:** an Exposure-scoped, metadata-filtered query and one explicit Embedding Space
   produce deterministic full-text, vector, and fused ranks, or a typed unavailable result. Known
   answers report recall@k without changing rank order.

Tests cross these interfaces and avoid assertions against private graph nodes, SQL layout, or internal helper calls.
