# Use LangGraph without making it the domain model

The investigation worker uses LangGraph's low-level graph API for bounded orchestration, checkpointing, and resumable execution, while domain entities and immutable Investigation Revisions remain authoritative in the application database. This accepts framework coupling in the execution layer to gain explicit, inspectable agent control without allowing LangGraph threads, messages, or checkpoints to define the product's language or history.
