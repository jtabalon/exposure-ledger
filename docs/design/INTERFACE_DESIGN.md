# Investigation workbench design

## Product character

Exposure Ledger is a calm forensic workspace: dense enough for an AppSec engineer, but organized like an evidence brief rather than a SIEM dashboard. It avoids neon cyber imagery, fake terminals, decorative charts, and chat-first interaction.

## Explored directions

### Claim-first tri-pane — selected

```text
┌ Navigation ┬ Exposure and recommendation ┬ Atomic claims ┬ Evidence trace ┐
│ Runs       │ affected package            │ fact          │ source         │
│ Exposures  │ dependency path             │ inference     │ captured at    │
│ Investig.  │ policy decision             │ contradiction │ retrieval rank │
│ Evaluations│ limitations                 │ evidence gap  │ exact passage  │
└────────────┴──────────────────────────────┴───────────────┴────────────────┘
```

This direction makes the core Claim ↔ Evidence relationship continuously visible and supports rapid review. Its cost is horizontal density, handled through a claim-first mobile sequence.

### Evidence notebook

A single editorial column presents Recommendation, Claims, and expandable evidence footnotes in reading order. It is excellent for sharing and long-form review but makes comparison and contradiction scanning slower.

### Operations board

A queue-led layout places exposure ranking and workflow state first, opening evidence in a side sheet. It is strongest for high-volume triage but under-emphasizes retrieval transparency—the project's most distinctive portfolio feature.

## Selected layout

- A restrained navigation rail exposes Assessment Runs, Exposures, Investigations, and Evaluations.
- The page header identifies the repository revision, Environment Profile, vulnerability aliases, package, and immutable revision.
- A stage timeline distinguishes deterministic stages, retrieval, model interpretation, follow-up decisions, and validation without revealing chain-of-thought.
- The desktop workspace uses three content columns: Exposure, Claims, and Evidence Trace.
- Selecting a Claim filters and highlights its supporting, contradicting, and contextual evidence. Selecting evidence highlights the Claims that use it.
- The hosted demonstration carries a persistent `Precomputed demo` label and exposes pinned inputs.

## Visual system

- **Typography:** Geist Sans for interface text and Geist Mono for versions, identifiers, hashes, ranks, and timestamps.
- **Palette:** warm neutral canvas, ink foreground, restrained teal accent, amber for uncertainty, red only for urgent action or blocking failure.
- **Shape:** thin borders, small consistent radii, almost no shadow, generous line height inside evidence.
- **Status:** every status combines wording, icon, and color.
- **Motion:** only short opacity/transform transitions under 200 ms, disabled under reduced-motion preferences.

## Responsive sequence

Desktop preserves the tri-pane relationship. Below 1100 px, Evidence Trace becomes an adjacent tab. On narrow screens the order is Recommendation → Claims → selected evidence → provenance, while assessment creation remains a desktop-first workflow.

## Accessibility

- WCAG 2.2 AA contrast and focus visibility
- complete keyboard navigation and logical reading order
- semantic headings, lists, tables, and buttons
- no status encoded by color alone
- timestamps include timezone; scores include text labels
- retrieval ranks and evidence relationships have accessible explanations
