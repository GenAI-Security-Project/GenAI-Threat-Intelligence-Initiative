---
name: update-ai-threat-tracker
description: >
  Research and draft an update to the OWASP GenAI Threat-Intelligence tracker. Sweeps new intel
  (Perplexity Sonar deep-research, wide net) for CONFIRMED, in-the-wild threat-actor activity in BOTH
  scope categories — A: actors USING AI/LLMs to attack (MITRE ATT&CK + LLM-TTP taxonomy); B: actors
  ATTACKING AI/ML/LLM systems (MITRE ATLAS). Applies a trust-tier + skeptic filter, parses survivors
  into the tracker schema, and opens a DRAFT pull request for CTI volunteers to review. Use when asked
  to "update the AI threat tracker" or run the scheduled refresh. Never merges; never commits researcher
  PoCs or vendor hype; never publishes an entry a human hasn't confirmed.
---

# update-ai-threat-tracker (OWASP GenAI Threat Intelligence Initiative)

Repeatable, human-in-the-loop refresh of [`GenAI-Security-Project/GenAI-Threat-Intelligence-Initiative`](https://github.com/GenAI-Security-Project/GenAI-Threat-Intelligence-Initiative).
**Architecture:** Sonar casts a wide net (both categories) → trust-tiering → skeptic gate for untrusted → provenance / primary-source resolution → Claude parses → **draft PR** → CTI volunteers approve.
The editorial judgment (real in-the-wild activity vs researcher PoC vs vendor hype, category assignment, dedup, TTP mapping) stays with Claude + the reviewers — that is the project's value.

**Two scope categories (tag every candidate):**
- **A — actor USES AI to attack.** Framework: **MITRE ATT&CK** + the LLM-TTP taxonomy (Appendix A in `TRACKER.md`). Lands in the Category A main table (or the deepfake table).
- **B — actor ATTACKS an AI system.** Framework: **MITRE ATLAS**. Lands in the **Category B** table in `TRACKER.md`.
- A single incident can be **A+B** (an actor that uses AI to attack another AI system) — it then carries both an ATT&CK and an ATLAS mapping. Full rubric + edge cases: `docs/Collection-Pipeline-Design.md`.

## Inputs & prerequisites
- `PERPLEXITY_API_KEY` in the environment (required for retrieval). Never print, log, or commit it.
- GitHub write auth: `gh` authenticated, or a `GH_TOKEN`/PAT in the environment for headless runs.
- Args: `--since YYYY-MM-DD` (default: the repo's last content-update date, see Stage 0). `--budget` (default from `config.json`).
- Files in this skill dir: `config.json` (trusted-source list, budget), `sonar_sweep.py`, `crosswalk.md` (ATT&CK **and** ATLAS).

## The one rule (applies to BOTH categories)
Publish only **confirmed, attributed, cited, real-world threat-actor activity**. Reporting is not performing; demonstrating is not doing.
- INCLUDE a real adversary in an actual operation — even when a researcher/vendor/government is the one *reporting* it.
- EXCLUDE researcher / security-expert proof-of-concept, red-team demos, academic feasibility, "could be used to" pieces, vendor marketing, and (for B) jailbreak/prompt-injection write-ups that are the researcher's own demonstration rather than an adversary's real attack.
- Unsure → leave it for a human (log it, don't commit it). The pipeline fails closed.

## Stage 0 — Baseline & dedupe index
- Fetch live `TRACKER.md` + `Sources.md` from `main` (via `gh api .../contents/...?ref=main`, base64-decode).
- Build a **known-actor index**: every Name + every AKA across the Category A main table, the deepfake table, AND the Category B table (use `crosswalk.md` to expand cross-vendor names).
- Note the known source URLs from `Sources.md` so you don't re-add existing reports.
- Build a **known-primary-report index** from `Sources.md` + the tables' `Link` columns: `{org, report title/edition, actor(s)/campaign it covers}`. Dedup on **primary-report identity**, not just the retrieved URL (a news outlet re-quoting a tracked report arrives with a new URL but is not a new finding).
- Resolve `--since`: default to the date of the newest entry / last content commit (`gh api .../commits?path=TRACKER.md`).
- **Index OPEN PULL REQUESTS too, not just `main`.** A draft PR can sit unmerged for weeks; rows already claimed in one will duplicate or conflict when a later sweep re-finds the same primary report. Run `gh pr list --repo <repo> --state open --json number,title,headRefName`, then for each open PR fetch its branch's `TRACKER.md`/`Sources.md` (or `gh pr diff <n>`) and fold every added actor row, source URL, and primary report into the three indexes above, tagged with the PR number. A candidate matching something already claimed in an open PR is NOT a new row: log it in the PR body under **"Already claimed by #N"**.
- While you're there, note any open PR whose diff no longer applies to current `main` (superseded by a merge) and flag it in this cycle's PR body so a maintainer can close it.

## Stage 1 — Sonar retrieval (WIDE NET, both categories)
Run: `python sonar_sweep.py --since <SINCE> --out candidates.json` (sweeps Category A **and** B; deep-research, no allowlist, date-scoped, budget-guarded). Use `--category A` or `--category B` only for a targeted re-run.
It writes `candidates.json` = `{findings[] (each tagged category A|B), sources[] (each tagged tier: trusted|untrusted), estimated_spend_usd}`.
Do NOT trust model-generated URLs — the real URLs are in `sources[]` (from Sonar `search_results`). Reconcile each finding to a source by matching `source_report_title`/`source_publication` against `sources[].title`/domain.

## Stage 1.5 — Trust tiering
Split reconciled candidates by their source domain (already tagged in `sources[].tier`, from `config.json`):
- **Trusted** (frontier labs, Huntress, Proofpoint, CrowdStrike, Intel471, Recorded Future, Mandiant, Check Point, SentinelOne, NCSC, IC3/FBI, Five Eyes) → skip the skeptic, go to Stage 3. Still dedup + bias-flag.
- **Untrusted** (everything else) → Stage 2.

## Stage 2 — Skeptic gate (UNTRUSTED ONLY)
For each untrusted candidate, spawn a **skeptic subagent** (Agent tool). It `WebFetch`es the primary source and answers, per the candidate's category:
- **Category A:** *Is this a REAL, in-the-wild report of a named/attributable threat actor USING AI for cyber-attack activity — or a researcher PoC / vendor demo / hype?*
- **Category B:** *Is this a REAL, in-the-wild attack by an adversary AGAINST a deployed AI/ML/LLM system — or a researcher's jailbreak/prompt-injection demonstration, academic feasibility study, or vendor hype?*
Decision + one-paragraph rationale + a confidence, plus **provenance** (original primary research, or re-reporting another named report? if citing, name the primary report + org — feeds Stage 2.5).
- **PASS** → Stage 3, carrying the skeptic's rationale as a **review-only annotation**.
- **REJECT** → add to the **"Rejected this cycle"** list: `title · source · url · date · category · reason`. Never enters the tracker.
Trusted-source items are NOT skeptic-gated.

## Stage 2.5 — Provenance & primary-source resolution (ALL surviving items)
Applies to both trusted and skeptic-passed candidates, before parsing. Never add a row that is just a **secondary re-quote of a primary already in the table**, and never leave a **multi-actor frontier report partially parsed**.
1. **Resolve the primary source** (read the sweep's fields; if unclear, `WebFetch` and read the report's own attribution).
2. **Secondary re-report of a KNOWN primary** → match the resolved primary against the Stage-0 known-primary-report index (org + report title/edition + campaign, expanded via `crosswalk.md`; not the URL). If it matches something tracked and adds no new detail → **DROP** (log under "Secondary re-reports collapsed"); if it adds new detail → propose an **UPDATE** to the existing row.
3. **Frontier full-extraction trigger.** If the resolved primary is an Anthropic / OpenAI / GTIG / Microsoft report, `WebFetch` it and **enumerate EVERY actor/campaign it discloses** (both categories), cross-checking each against the Stage-0 known-actor index. Any actor not yet tracked becomes its own new row / update. Record the check for the PR body.
4. **Original primary research** → proceed to Stage 3.

## Stage 3 — Parse, categorize & normalize (trusted + skeptic-passed)
For each surviving item:
- **Confirm the category** (A, B, or A+B) from what the actor actually did — not from where it was found. Use the sweep's `category` tag as a prior; override it if the source shows otherwise.
- **Dedup** against the Stage-0 indexes using `crosswalk.md` — match on **actor/AKA AND primary-report identity**. Already-tracked actor with fresh reporting → **UPDATE an existing row**, not a new row.
- **Map to the schema (7 columns):** `Name | AKAs | Brief (prose + inline source link) | TTP | Link | Reported | Activity Span`.
  - **Category A** TTP = bolded LLM-themed label(s) + validated **MITRE ATT&CK** ID(s), `<br><br>`-separated; validate every ID via `crosswalk.md`; no clean label → propose a new Appendix A label ("CREDIT: Rachel James based on <report>").
  - **Category B** TTP = behavior label(s) + validated **MITRE ATLAS** ID(s) (`AML.T####`), `<br><br>`-separated; validate every ID against `crosswalk.md` / atlas.mitre.org; no clean ID → describe in words and flag for the maintainer.
- **Date columns (`Reported` + `Activity Span`) — no fabrication:** `Reported` = report publication `Mon YYYY`; `Activity Span` = the actor's activity window from the report (`Mon YYYY – Mon YYYY`), distinct from discovery/announcement/publication date. Extract both with the exact quoted string + URL; have the skeptic re-verify the Activity Span against the quote. Unsourceable date → **`Unknown`** (never guess). Put date citations + reasoning in the PR body, not the committed row.
  - Date resolution is BEST-EFFORT and **MUST NEVER BLOCK the run.** At most one in-line follow-up lookup per unresolved date; if it doesn't return, write `Unknown`, note it in the PR body, and continue.
- Route **deepfake/impersonation/synthetic-identity fraud** (Category A) to the **deepfake table**. Route **Category B** items to the **Category B** table. Drop pure influence ops and mis/dis-information.
- **Bias-flag** vendor sources (even trusted ones) with a short note. Tag each item's type (in-the-wild / update / aggregate).

**Pipeline liveness rule (every stage).** Never park the run waiting on a subagent that may not report back. If a stage can't complete, **still open the draft PR** with what survived and record the gap under **"Incomplete this cycle"**. A partial, clearly-annotated draft PR always beats producing nothing.

## Stage 4 — Draft packaging
Write `proposed-update-YYYY-MM.md` (schema-exact, paste-ready), grouped: **new Category A rows · updates to existing A rows · deepfake rows · new Category B rows · updates to existing B rows · proposed Appendix A labels · new `Sources.md` rows**. Each row carries a review-only tag `[category · confidence · evidence class · bias · source date]`; skeptic-passed untrusted rows also carry the skeptic's annotation.

## Stage 5 / 6 — Open the DRAFT PR
Re-fetch `main` **immediately before branching** — it may have moved since Stage 0 (a maintainer merge mid-run is normal) — and build the new blobs by inserting rows into those fresh `main` blobs. **Never reconstruct a whole file from context** — `TRACKER.md` is >200KB; retyping it will corrupt it. Edit **only** `TRACKER.md` + `Sources.md` via the `gh api` blobs→tree→commit→PR flow.
Create a **`claude/`-prefixed** branch off `main` (e.g. `claude/ai-tracker-YYYY-MM-DD`) — cloud routines may push only to `claude/*` branches under the default safe permission, so this needs NO special grant. Open the PR with `"draft": true`.
The **PR description** carries: (1) a summary of proposed rows **grouped by category (A / B / A+B)**, (2) the **"Rejected this cycle"** list with reasons, (3) skeptic annotations for passed-untrusted items, (4) the **date citations + skeptic verdicts** for `Reported`/`Activity Span` (exact quote + URL per date), (5) **"Secondary re-reports collapsed"**, (6) a **"Frontier-report completeness check"**, (7) **"Already claimed by #N"** for anything an open PR already covers. None of that review scaffolding is committed — the commit touches only `TRACKER.md` + `Sources.md`. **Never auto-merge. Hold as draft until a CTI reviewer marks it ready.** Post the PR URL back.

## Guardrails
- Draft PR only; never merge; never push to `main`; never push to a non-`claude/*` branch.
- Both categories every run (A → ATT&CK, B → ATLAS); tag each row's category.
- Wide-net retrieval; the ONLY list-based filtering is trust-tiering (skeptic bypass), never retrieval.
- Reject researcher PoCs / vendor hype for BOTH categories (log them in the PR, not the tracker).
- Enumerate every edition of the recurring trackers (GTIG, Microsoft, OpenAI, Anthropic) and ATLAS case studies; re-check reports from the final days of the window.
- **Never add a row already claimed by an open draft PR** (Stage 0) or that is just a secondary re-quote of a tracked primary (Stage 2.5). When any report traces back to a frontier-provider primary, fully enumerate that primary's actors.
- Respect the `--budget` guard and the Perplexity dashboard spend limit. Never expose the API key.
- Nothing publishes to the site/STIX feed until a human merges the PR — `analyst_confirmed` is the merge itself.
