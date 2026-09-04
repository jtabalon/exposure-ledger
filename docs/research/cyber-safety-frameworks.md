# Cyber safety frameworks used by OpenAI and Anthropic

_Research snapshot: 2026-09-03_

These are vendor-published safety taxonomies and deployment practices, not consensus standards. They can inform this project's policy, but the project should version and own its own enforceable standard.

## OpenAI

OpenAI's published cyber threat taxonomy groups assistance into **low-risk dual use**, **high-risk dual use**, and **harmful actions**. Its system documentation gives complex exploitation, agentic vulnerability research, high-scale scanning, and offensive frameworks as high-risk examples, while malware deployment, credential theft, exfiltration, destructive actions, and chained exploitation against third-party systems are harmful actions.

OpenAI's current cyber-safety guidance separately distinguishes Daybreak Blue defensive workflows, such as vulnerability triage and remediation, from separately approved Daybreak Red workflows, such as controlled exploit validation and penetration testing. It recommends controlled environments, explicit target and action boundaries, least privilege, independent enforcement, monitoring, and human review of sensitive actions.

Sources:

- [OpenAI cyber threat taxonomy](https://deploymentsafety.openai.com/gpt-5-3-codex/cybersecurity)
- [OpenAI Models and Trusted Access](https://learn.chatgpt.com/docs/cyber-safety)
- [OpenAI recommended configuration](https://learn.chatgpt.com/docs/cyber-safety/recommended-configuration)
- [OpenAI API cybersecurity checks](https://developers.openai.com/api/docs/guides/safety-checks/cybersecurity)

## Anthropic

Anthropic publishes four classifier categories:

1. **Benign use**: defensive or IT work with little harmful utility, including patch management, secure coding, threat hunting, incident response, and historical vulnerability discussion.
2. **Low-risk dual use**: predominantly defensive activity that could still aid attackers, including public-source intelligence and vulnerability identification already available through common tools.
3. **High-risk dual use**: activity with legitimate professional uses and substantial offensive value, including penetration testing, exploitation, privilege escalation, lateral movement, persistence, container escapes, and high-uplift vulnerability discovery.
4. **Prohibited use**: activity with little defensive utility or strongly asymmetric harm, including ransomware, wipers, defense evasion, command and control, exfiltration, malware development or delivery, and cyber-physical sabotage.

Anthropic also argues that technique labels alone do not capture agentic risk. Its AI Risk Enablement Score evaluates threat, the model's ability to enable harm, and impact; its threat-intelligence research highlights autonomous kill-chain orchestration, target selection, and live operational pivots as cross-cutting risks beyond ordinary MITRE ATT&CK tags.

Sources:

- [Anthropic Fable cyber safeguards](https://www.anthropic.com/news/fable-safeguards-jailbreak-framework)
- [Anthropic mapping of AI-enabled cyber threats](https://www.anthropic.com/research/attack-navigator)

## Proposed project standard

Adopt a vendor-neutral **Cyber Assistance Risk Standard** with two independent axes.

### Assistance class

| Class | Meaning | Example in this product | Default policy |
| --- | --- | --- | --- |
| C0 Benign defensive | Little meaningful offensive uplift | Summarize a public advisory and cite its fixed version | Allow |
| C1 Low-risk dual use | Primarily defensive with plausible offensive utility | Inspect a public repository for an already disclosed dependency Exposure | Allow, monitor, and evaluate |
| C2 High-risk dual use | Materially enables offensive capability even when legitimate uses exist | Generate an exploit, validate authentication bypass, or scan an external target | Do not support in the public product |
| C3 Harmful | Enables unauthorized access, persistence, theft, exfiltration, destructive impact, or malware operations | Steal credentials, deploy ransomware, evade EDR, or chain exploitation against a third party | Block and record the policy reason |

### Action level

| Level | Meaning | Example | Initial product policy |
| --- | --- | --- | --- |
| A0 Inform | Explain or summarize without inspecting a target | Explain what KEV status means | Allow |
| A1 Read | Inspect allowlisted public data without executing it | Parse a pinned lockfile and retrieve advisories | Allow |
| A2 Propose | Draft a reversible change without applying it | Suggest a dependency upgrade or patch | Later milestone with human review |
| A3 Execute in owned isolation | Run an approved security action inside a disposable lab | Reproduce a known vulnerability in an isolated fixture | Outside the first release |
| A4 External or production action | Affect a live, external, unrelated, or production system | Scan, exploit, modify, persist, or exfiltrate | Prohibit |

The effective policy uses the stricter result across both axes. For the first release, only C0-C1 and A0-A1 are executable. Provider safeguards are defense in depth, not the application's authorization boundary.

## Evaluation implications

The safety corpus should include single-turn and multi-step examples for every class and action level, ambiguous authorization, scope escalation, indirect prompt injection in repositories and advisories, requests that combine individually benign steps into a harmful chain, and attempts to convert read-only analysis into external action. Each case should assert both the classification and the permitted system behavior.
