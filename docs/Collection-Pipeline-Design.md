# Collection Pipeline — Category Model & Inclusion Rubric (Phase 2)

> Design spec for the AI-assisted collection pipeline: **Perplexity Sonar** (discovery sweep) →
> **Claude "Skeptic"** (inclusion gate + category) → **Claude "Parser/Enricher"** (structured
> extraction + TTP mapping) → review queue → human approval. This document defines the two scope
> categories and the **in-the-wild-not-PoC** inclusion rule, and encodes both into each agent's
> prompt. Everything here feeds the data model (see `CLAUDE.md`) and nothing publishes without a
> human marking it **Analyst Confirmed**.

---

## 1. The two categories (every record is tagged)

| Category | Definition | Framework | Example activity |
|---|---|---|---|
| **A** | Threat actors **using AI/LLMs to conduct attacks** | MITRE **ATT&CK** + custom **LLM-TTP** taxonomy (Appendix A) | LLM-written phishing/malware, AI-assisted recon/vuln analysis, deepfake-enabled fraud, malicious LLM tooling (WormGPT-class) sold/used in the wild |
| **B** | Threat actors **attacking AI/ML/LLM systems** | MITRE **ATLAS** | Prompt injection against a deployed assistant/agent, RAG/data-store poisoning, model or model-supply-chain compromise, extraction/evasion against a production model, abuse of an agent's tools |

**Category is a classification output, not a filter.** A candidate can be:
- **A** only, **B** only, or **A + B** (e.g., an actor that *uses* an LLM to *attack* another org's AI agent).
- The Skeptic assigns the category; the Parser maps to the matching framework (A→ATT&CK, B→ATLAS).

Category B is **new** to this initiative (the origin cybershujin repo is A-only). The pipeline must
treat B as first-class, not an afterthought.

---

## 2. The inclusion gate — the one rule that matters

> **Publish only confirmed, attributed, cited, real-world threat-actor activity.**
> Reporting is not performing. Demonstrating is not doing.

### INCLUDE
- A **real threat actor** (named, or **UnSub** / Multiple UnSub for unnamed) conducting **actual
  operations against real targets** — regardless of **who reports it**. Activity reported by a
  researcher, vendor, or government is in scope; the *researcher is the source, the adversary is the
  subject*.
- First-party platform telemetry of misuse (OpenAI, Anthropic, Google/GTIG, Microsoft disrupting real
  abuse of their models), IR findings, government advisories, credible press on a real incident.
- An adversary **adopting a researcher's PoC or public tool in the wild** — the in-the-wild *use* is
  the record, not the original PoC.

### EXCLUDE
- **Researcher / security-expert proof-of-concept**, red-team demos, academic feasibility studies,
  "this *could* be used to…" articles, conference/CTF/bug-bounty demonstrations — where the AI-enabled
  action is performed **by the researcher to show it is possible**, not by an adversary in a real
  operation.
- Pure **mis/dis/mal-information and influence campaigns** using deepfakes (tracked elsewhere, if at all).
- Vendor marketing, vulnerability disclosures with no observed exploitation, and general "state of AI
  threats" commentary with no specific actor/incident.

### The decisive test (apply to every candidate)
1. **Who performed the AI-enabled action?** An adversary → keep going. A researcher/vendor/student
   demonstrating → **EXCLUDE** (PoC).
2. **Was it a real operation against a real target (or real sale/use of malicious tooling)?** Yes →
   **INCLUDE**. Only a lab/demo/hypothetical → **EXCLUDE**.
3. **Unsure on either?** → **NEEDS-HUMAN** (never auto-include). The pipeline **fails closed**.

### Edge cases (resolved)
| Situation | Call |
|---|---|
| Vendor reports a nation-state actor used its LLM for recon | **INCLUDE** (A). Researcher = source, actor = subject. |
| Academic paper jailbreaks a model to show data exfiltration is possible | **EXCLUDE** (PoC, Cat B shape but no real actor). |
| WormGPT/FraudGPT-class tool advertised on a forum | **INCLUDE** as **UnSub**, lower confidence, with evidence of real sale/use; advertising-only → low confidence / NEEDS-HUMAN. |
| Red team reproduces an actor's AI technique for a client | **EXCLUDE** (demonstration, not adversary operation). |
| Real prompt-injection attack reported against a live customer-facing agent | **INCLUDE** (B). |
| Threat actor picks up a public PoC and deploys it against victims | **INCLUDE** — the in-the-wild deployment, not the PoC. |

---

## 3. Agent prompts (the rubric, encoded)

All three roles share a **category + inclusion preamble** (Sections 1–2 condensed). Below is the
per-role operative prompt. Keep these in version control; they are the real enforcement surface.

### 3a. Perplexity Sonar — discovery sweep
Run **two query families** on the weekly schedule, so Category B is swept deliberately (it won't
surface on A-shaped queries). Dedup against already-ingested URLs; emit candidates
`{url, title, publisher, date, snippet}` to the Skeptic. Respect spend caps (`MAX_RECORDS_PER_RUN`,
token ceilings; fails closed on the OpenRouter/Perplexity prepaid balance).

**Category A queries (illustrative):**
- `threat actor used AI OR LLM to <phishing|write malware|reconnaissance|vulnerability analysis>` (last N days)
- `OpenAI OR Anthropic OR Google OR Microsoft disrupted OR banned threat actor misuse of <model>`
- `deepfake voice OR video fraud attack company finance` (exclude "influence/election")
- `WormGPT OR FraudGPT OR malicious LLM sold forum telegram`

**Category B queries (illustrative):**
- `prompt injection attack against production AI agent OR assistant in the wild`
- `data poisoning OR RAG poisoning attack real-world`
- `attack on AI model supply chain OR compromised model weights OR malicious model on Hugging Face`
- `adversary exploited AI agent tools OR model extraction OR evasion against deployed model`

> Sonar discovers; it does **not** decide inclusion. Over-collect here, let the Skeptic cut.

### 3b. Claude "Skeptic" — inclusion gate + category (fails closed)

```
You are the Skeptic for the OWASP GenAI Threat Intelligence Initiative. You triage one candidate
report at a time. Your job is to KEEP OUT anything that is not confirmed, in-the-wild threat-actor
activity. When in doubt, you escalate to a human — you never wave something through.

Scope — two categories you recognize:
- A: a threat actor USING AI/LLMs to conduct an attack (maps to MITRE ATT&CK + LLM-TTP taxonomy).
- B: a threat actor ATTACKING an AI/ML/LLM system (maps to MITRE ATLAS).
A candidate may be A, B, or both.

The one rule: publish only confirmed, attributed, cited, REAL-WORLD threat-actor activity.
Reporting is not performing; demonstrating is not doing.
- INCLUDE: a real adversary (named or UnSub) in an actual operation against a real target — even when
  a researcher, vendor, or government is the one reporting it. First-party misuse telemetry, IR
  findings, and advisories count.
- EXCLUDE: researcher / security-expert proof-of-concept, red-team demos, academic feasibility,
  "could be used to" pieces, CTF/bug-bounty demos, pure influence/disinformation campaigns, vendor
  marketing, and disclosures with no observed exploitation.

Decide with these questions, in order:
1. Who performed the AI-enabled action — an adversary, or a researcher/vendor demonstrating? (demo → EXCLUDE)
2. Was it a real operation / real sale or use of malicious tooling, against real targets? (only a lab/demo → EXCLUDE)
3. Unsure on either? → NEEDS_HUMAN.

Return ONLY this JSON:
{
  "decision": "INCLUDE" | "EXCLUDE" | "NEEDS_HUMAN",
  "category": ["A"] | ["B"] | ["A","B"] | [],
  "in_the_wild": true | false,
  "actor_named": true | false,
  "confidence": "high" | "medium" | "low",
  "rationale": "<=2 sentences citing the specific evidence of real-world actor activity",
  "exclusion_reason": "poc | researcher-demo | influence-op | no-exploitation | marketing | off-scope | null"
}
Do not invent facts not in the candidate. If the source does not clearly show a real adversary in a
real operation, you must not return INCLUDE.
```

### 3c. Claude "Parser/Enricher" — structured extraction + TTP mapping
Runs **only on INCLUDE** items. Produces a review-queue record; always leaves the publish gate closed.

```
You are the Parser/Enricher for the OWASP GenAI Threat Intelligence Initiative. You convert one
INCLUDED report into a structured candidate record. You never upgrade scope decisions and never set
the publish gate.

Produce ONLY this JSON (omit nothing; use null/empty when the source doesn't say):
{
  "name": "<actor name, or 'UnSub (<source>)' / 'Multiple UnSub (<source>)'>",
  "akas": ["..."],
  "brief": "<2-4 sentence factual summary of the real-world activity>",
  "category": ["A"] | ["B"] | ["A","B"],
  "ttps": [ {"id": "...", "name": "...", "framework": "ATT&CK" | "ATLAS" | "LLM-TTP"} ],
  "citations": [ {"url": "...", "publisher": "...", "date": "YYYY-MM"} ],
  "reported": "<Mon YYYY>",
  "activity": "<Mon YYYY – Mon YYYY | Unknown>",
  "confidence": "high" | "medium" | "low",
  "analyst_confirmed": "no",
  "status": "pending",
  "source_system": "internal"
}

TTP mapping rules:
- Category A → MITRE ATT&CK technique IDs (Txxxx[.xxx]); add LLM-TTP taxonomy labels (framework
  "LLM-TTP") where ATT&CK has no clean fit (see Appendix A).
- Category B → MITRE ATLAS technique IDs (AML.Txxxx).
- NEVER guess an ID. If you cannot map confidently, emit {"id": null, "name": "Unknown TTPs",
  "framework": ...} rather than inventing one. A wrong ID is worse than an honest gap.
- Every claim in "brief" and every TTP must be supported by a citation. No citation → drop the claim.

You always output analyst_confirmed = "no". A human reviewer sets it to "yes" to publish.
```

---

## 4. How this lands in the data model & review

Each emitted record carries `category`, `confidence`, `status: pending`, `analyst_confirmed: no`,
`source_system: internal`, and its `citations[]` / `ttps[]`. It goes to the **review queue**, where a
human analyst confirms/corrects and flips `analyst_confirmed → yes`. Only then does it commit to the
OWASP Git repo and regenerate the site + STIX/TAXII feed. Category A records map to ATT&CK in STIX
`attack-pattern.external_references`; Category B records map to ATLAS the same way.

## 5. Guardrails (Phase 2, per CLAUDE.md)

`PIPELINE_ENABLED` kill switch · `MAX_RECORDS_PER_RUN` · `MONTHLY_TOKEN_BUDGET` · per-run token
ceiling · OpenRouter prepaid (fails closed) · Perplexity prepaid + monthly limit · billing alerts to
Slack at 50/80/100%. The Skeptic's **fail-closed** default is the quality guardrail; the spend caps
are the cost guardrail.

---

*Draft for review — the category definitions and the INCLUDE/EXCLUDE rubric are the parts worth your
sign-off; the prompts are implementation detail that will evolve as the pipeline is built (Phase 2).*
