# OWASP GenAI Security Project Threat Intelligence Initiative

**The operational threat-intelligence layer of the OWASP GenAI Security Project.**

Established in 2024, the Threat Intelligence Initiative was founded and is co-led by
**Rachel James** ([GitHub](https://github.com/cybershujin) · [LinkedIn](https://www.linkedin.com/in/cybershujin))
and **Bryan Nakayama** ([LinkedIn](https://www.linkedin.com/in/bryannakayama/)).
Learn more on the [OWASP GenAI initiative page](https://genai.owasp.org/initiatives/#ai-threat-intel).

> 🚧 **This repository is in a building phase.** The initiative itself is well established — what's
> new is the **AI-CTI platform** hosted here: the collection pipeline, public catalog, website, and
> STIX/TAXII feed described below are in active development. Expect this repo to change rapidly.
> Contributions and reviewers welcome.

**📊 Live now:** the existing Category A corpus — **158 tracked threat actors / UnSubs** mapped to
TTPs — has been migrated into this repo: **[tracker table](TRACKER.md)** ·
**[STIX 2.1 bundle](stix/threat-actors-ai-stix2.1.json)** · **[JSON](tracker.json)** ·
**[IOC feeds](iocs/)**. The interactive, searchable site publishes to
`https://genai-security-project.github.io/GenAI-Threat-Intelligence-Initiative/` once GitHub Pages is
enabled. All exports regenerate automatically from `TRACKER.md` on every change
(see [`tools/build_exports.py`](tools/build_exports.py)).

---

## What this is

The rapid adoption of LLMs and Generative AI has opened a threat landscape that traditional
CTI approaches don't fully cover. This initiative fills the **tactical middle layer** between
high-level risk frameworks (the OWASP Top 10 for LLM Applications, the CISO Governance
Checklist) and the hands-on intelligence that security operations teams need to detect and
respond to real-world attacks.

We produce **threat-informed, actionable guidance** for the practitioners defending GenAI
systems in production — SOC analysts, CTI analysts, threat hunters, incident responders,
detection engineers, security researchers, and MLSecOps teams.

## Scope — two categories we track

- **Category A — Threat actors *using* AI to conduct attacks.** LLM-enhanced phishing, malware
  development, reconnaissance, and deepfake-enabled fraud. Mapped to **MITRE ATT&CK** plus a
  custom LLM-TTP taxonomy.
- **Category B — Threat actors *attacking* AI systems.** Confirmed adversary (not researcher)
  activity against AI/ML/LLM systems — prompt injection, RAG poisoning, model supply-chain
  compromise. Mapped to **MITRE ATLAS**.

**The golden rule:** only confirmed, attributed, cited activity is published. Nothing goes live
until a human analyst marks it *Analyst Confirmed*.

## What we're building

A sustainable, OWASP-owned **AI-CTI platform** that turns curated research into a
standards-based intelligence service:

1. **AI-assisted collection pipeline** — automated discovery of new reports (with sources) and
   structured extraction into candidate records: actor, aliases, brief, TTPs, and citations.
2. **Human review & approval** — a lightweight dashboard with notifications, where analysts
   confirm or correct each draft and set the publish gate.
3. **Public website** — published, confirmed entries for both categories.
4. **STIX 2.1 / TAXII 2.1 feed** — a machine-readable feed other organizations can ingest into
   their threat-intelligence platforms (OpenCTI, MISP, SIEMs).

Data is **Git-centric**: approved records live as structured YAML/JSON in this OWASP org, and
the website, STIX bundles, and TAXII feed all generate from them. Every automated draft passes
through human analyst review before publication.

## Deliverables (per the Initiative Charter)

- Threat intelligence briefings on active campaigns, emerging attack patterns, and adversary TTPs
- IOCs / IOAs for GenAI-specific threats (prompt-injection patterns, jailbreak attempts, model
  extraction and data-exfiltration signatures)
- Detection-engineering guidance (SIEM rules, detection logic, monitoring frameworks)
- Incident-response playbooks tailored to GenAI incidents
- Threat-actor tracking of AI weaponization and associated TTPs
- Real-world attack case studies and lessons learned

## Standards & interoperability

STIX / TAXII · MITRE ATT&CK · MITRE ATLAS · industry-standard IOC formats. We reference
authoritative sources rather than duplicating them, and maintain vendor/product neutrality.

## Roadmap

| Phase | What | Status |
|---|---|---|
| 0 | Foundations: OWASP repo, schema, migrate existing catalog | ✅ Catalog migrated |
| 1 | Publish existing corpus: website + STIX/TAXII feed | 🔨 In progress |
| 2 | AI collection pipeline + spend caps | ⬜ Planned |
| 3 | Review dashboard + notifications | ⬜ Planned |
| 4 | Agentic-AI incidents data exchange | ⬜ Planned |
| 5 | Hardening, backups & maintainer handoff | ⬜ Planned |

## Working groups

The initiative organizes its work into groups spanning threat research, detection engineering,
incident response, and adversary tracking, with regular community meetings to coordinate research
and discuss emerging threats.

## Get involved

- **Reviewers** — ~1 hr/week confirming entries. No coding required.
- **STIX / CTI builders** — help with the TAXII feed and STIX mapping.
- **Pipeline / dashboard builders** — building the collection pipeline and review dashboard.

Contribution guidelines and an open-source license for this repository are being finalized as
part of the building phase.

---

*OWASP GenAI Security Project — Threat Intelligence Initiative.*
# Threat-Intelligence-Initiative
Github Location for the GenAI Security Project's Threat Intelligence Initiative
