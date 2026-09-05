# Use PostgreSQL as the only operational database

The first release stores domain records, source payloads, lexical search data, embeddings, provenance,
jobs, progress events, Investigation operation state, and LangGraph checkpoints in PostgreSQL, using
`jsonb`, native full-text search, and pgvector where appropriate. This trades specialized
vector-database and checkpoint services for transactional consistency, simpler local and hosted
operations, and direct joins across claims, evidence, revisions, and retrieval results; another store
will be introduced only when measured limits justify it.
