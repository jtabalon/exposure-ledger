# Use LangGraph without making it the domain model

The investigation worker uses LangGraph's low-level graph API for bounded orchestration, while domain
entities and immutable Investigation Revisions remain authoritative in PostgreSQL. Each selected
Exposure receives a durable Investigation operation identity. LangGraph checkpoints use that identity
as their thread key and are written synchronously to PostgreSQL after each graph step. A worker that
reclaims an interrupted Assessment resumes the same operation from its latest valid checkpoint and
ultimately links it to one immutable Revision with the same identity.

Checkpoint threads, pending writes, and serialized graph state remain execution details: they neither
replace the Investigation domain model nor become API resources. The worker validates a restored
command against the requested Assessment, Exposure, Asset Snapshot, configuration, and budgets before
resuming. Invalid state fails explicitly. Persisted Asset Snapshots, evidence, embeddings, Policy
Decisions, progress events, and Revisions use idempotent writes so recovery does not repeat completed
external reads or append duplicate immutable records.
