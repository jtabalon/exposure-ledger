# Preserve Investigation history as immutable revisions

Changes to an Investigation create immutable Investigation Revisions instead of mutating prior conclusions. This costs more storage and requires explicit revision handling, but preserves the repository state, evidence, conclusions, and execution circumstances needed to explain changes over time, reproduce prior results, and compare system versions honestly.
