#!/usr/bin/env python3
"""
sonar_sweep.py — Perplexity Sonar retrieval layer for the OWASP GenAI AI-threat tracker.

WIDE NET: no domain allowlist (an allowlist is how real reports slip through). Retrieval is scoped
only by publication date (--since) plus an optional tiny spam denylist. Deep-research-heavy.

Sweeps BOTH scope categories, tagging every finding with the query family that produced it:
  - Category A: threat actors USING AI/LLMs to conduct attacks (-> MITRE ATT&CK + LLM-TTP taxonomy)
  - Category B: threat actors ATTACKING AI/ML/LLM systems (-> MITRE ATLAS)

For each thematic query it runs Perplexity `sonar-deep-research` (async) and collects (a) structured
FINDINGS from the model and (b) the real SOURCE reports from the response `search_results` (never trust
model-generated URLs). Each source is tagged trusted/untrusted by domain so the skill knows which bypass
the skeptic gate. Output: a JSON file the skill (Claude) consumes for Stage 1.5+ (trust-tiering,
skeptic gate, parsing).

Env:  PERPLEXITY_API_KEY  (required unless --dry-run)
Usage:
  python sonar_sweep.py --since 2026-07-13 --out candidates.json
  python sonar_sweep.py --since 2026-07-13 --category B          # sweep one category only
  python sonar_sweep.py --since 2026-07-13 --dry-run             # print payloads, no API calls
  python sonar_sweep.py --since 2026-07-13 --sync --model sonar-pro   # cheap connectivity test
"""
import argparse, json, os, sys, time, urllib.request, urllib.error
from pathlib import Path

CFG = json.loads((Path(__file__).parent / "config.json").read_text(encoding="utf-8"))
API_BASE = "https://api.perplexity.ai"
TRUSTED = [d.lower() for d in CFG["trusted_sources"]["domains"]]
DENY = [d.lower() for d in CFG["spam_denylist"]["domains"]]

# Wide-net thematic queries, tagged by scope category. Deep-research fans out its own sub-searches per
# query; a handful of angles per category ensures exhaustive coverage without an allowlist.
QUERIES = [
    # ---- Category A: threat actors USING AI to attack ----
    ("A",
     "Cybersecurity reports published on or after {since} documenting a REAL, named or clearly-attributed "
     "threat actor (nation-state APT or cybercriminal group) USING artificial intelligence or LLMs in an "
     "actual cyber attack or intrusion — e.g. AI-assisted malware development, LLM-embedded/agentic malware, "
     "phishing, ransomware, or full agentic operations. Include the vendor/government/organization that "
     "reported it and the report date. EXCLUDE security-researcher proof-of-concepts and vendor 'this could "
     "happen' hype."),
    ("A",
     "Reports published on or after {since} of nation-state or state-sponsored APTs (Russia, China, Iran, "
     "North Korea, etc.) observed USING AI/LLM tools (Gemini, ChatGPT, Claude, or others) for reconnaissance, "
     "exploit/vulnerability research, malware or C2 development, or social engineering in real operations. "
     "Name the reporting organization and date."),
    ("A",
     "Reports published on or after {since} of real threat actors using AI-generated deepfakes, synthetic "
     "identities, or voice/video cloning for fraud, extortion, or employment/hiring scams (e.g. DPRK IT "
     "workers). Name the reporting org and date."),
    ("A",
     "Reports published on or after {since} from AI providers' own threat-intelligence teams (Anthropic, "
     "OpenAI, Google GTIG, Microsoft) disclosing threat actors caught USING their models for cyber "
     "operations. List each report, actor, and date."),

    # ---- Category B: threat actors ATTACKING AI systems ----
    ("B",
     "Cybersecurity reports published on or after {since} documenting a REAL, named or clearly-attributed "
     "threat actor ATTACKING a deployed AI/ML/LLM system in the wild — e.g. prompt injection against a "
     "production AI assistant or agent, jailbreaking a live model for abuse, data/RAG poisoning, model or "
     "model-supply-chain compromise (backdoored/trojanized models on Hugging Face), or exfiltration via an "
     "inference API. Include the reporting org and date. EXCLUDE academic/security-researcher "
     "proof-of-concept and 'could happen' demonstrations."),
    ("B",
     "Reports published on or after {since} of real-world attacks on enterprise AI agents or LLM applications "
     "— indirect prompt injection via documents/web/email, abuse of agent tools/plugins, or compromise of AI "
     "coding assistants / MCP tooling — carried out by actual adversaries (NOT red-team or researcher demos). "
     "Name the reporting organization and date."),
    ("B",
     "Reports published on or after {since} of threat actors poisoning training data, model weights, or "
     "retrieval corpora, or distributing backdoored/trojanized ML models in real campaigns. Name the "
     "reporting org and date; map to MITRE ATLAS where possible."),
    ("B",
     "Reports published on or after {since} from AI providers (Anthropic, OpenAI, Google, Microsoft) or IR "
     "vendors disclosing real adversary attempts to attack, manipulate, poison, or extract from their own or "
     "customers' deployed AI systems. List each report, actor/campaign, and date."),
]

FINDINGS_SCHEMA = {
    "type": "json_schema",
    "json_schema": {
        "name": "ai_threat_candidates",
        "schema": {
            "type": "object",
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "actor_or_campaign": {"type": "string"},
                            "what_happened": {"type": "string", "description": "What the actor did: for A, how they USED AI; for B, how they ATTACKED an AI system"},
                            "scope_category": {"type": "string", "description": "A = actor used AI to attack | B = actor attacked an AI system | unclear"},
                            "source_report_title": {"type": "string"},
                            "source_publication": {"type": "string", "description": "Reporting org or site name (text, NOT a URL)"},
                            "approx_date": {"type": "string", "description": "Publication date if known, else empty"},
                            "in_the_wild_assessment": {"type": "string", "description": "real in-the-wild use | researcher PoC | vendor hype | unclear"}
                        },
                        "required": ["actor_or_campaign", "what_happened", "source_report_title",
                                     "source_publication", "in_the_wild_assessment"]
                    }
                }
            },
            "required": ["findings"]
        }
    }
}

def tier_for(url: str) -> str:
    u = (url or "").lower()
    return "trusted" if any(d in u for d in TRUSTED) else "untrusted"

def _post(path, payload, key):
    req = urllib.request.Request(API_BASE + path, data=json.dumps(payload).encode(),
                                 headers={"Authorization": f"Bearer {key}",
                                          "Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode())

def _get(path, key):
    req = urllib.request.Request(API_BASE + path,
                                 headers={"Authorization": f"Bearer {key}"}, method="GET")
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode())

def build_body(query, since, model, effort):
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a precise cyber threat-intelligence retrieval assistant. "
             "Return only findings grounded in real, citable reports. Do not invent sources or URLs."},
            {"role": "user", "content": query},
        ],
        "search_after_date_filter": since_mdy(since),
        "response_format": FINDINGS_SCHEMA,
    }
    if model == "sonar-deep-research":
        body["reasoning_effort"] = effort
    if DENY:
        body["search_domain_filter"] = ["-" + d for d in DENY]  # denylist only; NOT an allowlist
    return body

def since_mdy(iso):
    y, m, d = iso.split("-")
    return f"{int(m)}/{int(d)}/{y}"          # Perplexity wants %m/%d/%Y

def run_query(query, since, key, model, effort, sync):
    body = build_body(query, since, model, effort)
    if sync or model != "sonar-deep-research":
        resp = _post("/chat/completions", body, key)
    else:
        job = _post("/v1/async/sonar", {"request": body}, key)
        rid = job.get("id") or job.get("request_id") or job.get("job_id")
        if not rid:
            raise RuntimeError(f"async submit returned no id: {json.dumps(job)[:400]}")
        for _ in range(120):                 # poll up to ~10 min
            time.sleep(5)
            st = _get(f"/v1/async/sonar/{rid}", key)
            status = st.get("status", "")
            if status in ("COMPLETED", "completed", "succeeded"):
                resp = st.get("response") or st
                break
            if status in ("FAILED", "failed", "error"):
                raise RuntimeError(f"async job failed: {json.dumps(st)[:400]}")
        else:
            raise TimeoutError(f"async job {rid} did not complete in time")
    return resp

def parse_resp(resp):
    msg = resp["choices"][0]["message"]["content"]
    try:
        findings = json.loads(msg).get("findings", [])
    except Exception:
        findings = [{"actor_or_campaign": "PARSE_ERROR", "what_happened": msg[:500],
                     "source_report_title": "", "source_publication": "", "in_the_wild_assessment": "unclear"}]
    results = []
    for sr in (resp.get("search_results") or []):
        url = sr.get("url", "")
        results.append({"title": sr.get("title", ""), "url": url,
                        "date": sr.get("date") or sr.get("last_updated", ""),
                        "snippet": sr.get("snippet", ""), "tier": tier_for(url)})
    usage = resp.get("usage", {})
    return findings, results, usage

def est_cost(usage, model):
    # Rough guard estimate. Perplexity deep-research bills tokens + searches; if the
    # response lacks a cost field we approximate from output tokens.
    if "cost" in usage and isinstance(usage["cost"], (int, float)):
        return float(usage["cost"])
    out = usage.get("completion_tokens", 0) or usage.get("output_tokens", 0)
    reason = usage.get("reasoning_tokens", 0)
    cite = usage.get("citation_tokens", 0)
    searches = usage.get("num_search_queries", usage.get("search_queries", 0))
    return out/1e6*8 + reason/1e6*3 + cite/1e6*2 + searches/1000*5 + 0.5

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", required=True, help="YYYY-MM-DD lower bound on report publication date")
    ap.add_argument("--out", default="candidates.json")
    ap.add_argument("--category", choices=["A", "B", "all"], default="all", help="limit the sweep to one scope category")
    ap.add_argument("--budget", type=float, default=CFG["budget"]["per_run_usd"])
    ap.add_argument("--model", default=CFG["budget"]["model"])
    ap.add_argument("--effort", default=CFG["budget"]["reasoning_effort"])
    ap.add_argument("--sync", action="store_true", help="use /chat/completions (for cheap sonar-pro connectivity tests)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    selected = [(cat, q.format(since=a.since)) for (cat, q) in QUERIES if a.category in ("all", cat)]
    if a.dry_run:
        for i, (cat, q) in enumerate(selected, 1):
            print(f"--- query {i} [Category {cat}] body ---")
            print(json.dumps(build_body(q, a.since, a.model, a.effort), indent=2)[:1200], "\n")
        print(f"[dry-run] {len(selected)} queries · model={a.model} · budget=${a.budget} · no API calls made.")
        return

    key = os.environ.get("PERPLEXITY_API_KEY")
    if not key:
        sys.exit("ERROR: PERPLEXITY_API_KEY not set in environment.")

    all_findings, all_results, spend = [], {}, 0.0
    for i, (cat, q) in enumerate(selected, 1):
        if spend >= a.budget:
            print(f"[budget] ${spend:.2f} >= ${a.budget}; stopping before query {i}.", file=sys.stderr)
            break
        try:
            resp = run_query(q, a.since, key, a.model, a.effort, a.sync)
        except Exception as e:
            print(f"[query {i}/{cat}] error: {e}", file=sys.stderr); continue
        findings, results, usage = parse_resp(resp)
        for f in findings:
            f["category"] = cat                          # query-family tag is authoritative
        c = est_cost(usage, a.model); spend += c
        all_findings += findings
        for r in results:
            all_results[r["url"]] = r                     # dedupe sources by URL
        print(f"[query {i}/{cat}] findings={len(findings)} sources={len(results)} est_cost=${c:.2f} cumulative=${spend:.2f}",
              file=sys.stderr)

    sources = list(all_results.values())
    out = {
        "run_since": a.since, "model": a.model, "queries": len(selected),
        "estimated_spend_usd": round(spend, 2), "budget_usd": a.budget,
        "counts": {"findings": len(all_findings),
                   "findings_A": sum(1 for f in all_findings if f.get("category") == "A"),
                   "findings_B": sum(1 for f in all_findings if f.get("category") == "B"),
                   "sources_trusted": sum(1 for r in sources if r["tier"] == "trusted"),
                   "sources_untrusted": sum(1 for r in sources if r["tier"] == "untrusted")},
        "findings": all_findings,
        "sources": sources,
        "_note": "Each finding is tagged category A (used AI to attack -> ATT&CK) or B (attacked an AI system "
                 "-> ATLAS). Reconcile each finding to a real source URL via `sources` (match on "
                 "title/publication). Trusted-tier sources bypass the skeptic gate; untrusted go through it."
    }
    Path(a.out).write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"wrote {a.out}: {out['counts']} · est ${spend:.2f}")

if __name__ == "__main__":
    main()
