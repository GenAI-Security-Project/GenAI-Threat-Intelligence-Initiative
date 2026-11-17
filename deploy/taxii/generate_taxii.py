#!/usr/bin/env python3
"""
generate_taxii.py — build a static, spec-compliant TAXII 2.1 feed tree from the project's STIX bundle.

The feed is served as plain files by Caddy (see Caddyfile) with the TAXII media type. It is read-only
(polling) TAXII 2.1: discovery -> api-root -> collections -> objects/manifest. Three collections, split
on the `ai_cti_category` tag (the custom extension; see stix/EXTENSION.md):
  - all          every object
  - category-a   actors USING AI (MITRE ATT&CK) + their graph
  - category-b   actors ATTACKING AI systems (MITRE ATLAS) + their graph

Category collections are reference-closed (relationships + referenced SCOs/identities/malware pulled in)
and always include the category extension-definition + the project identity, so each is self-contained.

Deterministic + stdlib-only. Not server-side filterable/paginated — small feed, single page
(`more:false`). Swap in Medallion/Arango later if a consumer needs query filtering.

Usage:
  python3 generate_taxii.py --bundle ../../stix/threat-actors-ai-stix2.1.json \
      --out /var/www/taxii --base-url https://taxii.aithreatintelfeed.org
"""
import argparse, json, re, hashlib, uuid
from pathlib import Path

API_ROOT = "feed"                      # /taxii2/feed/
TAXII_MT = "application/taxii+json;version=2.1"
STIX_MT = "application/stix+json;version=2.1"
ID_PAT = re.compile(r"^[a-z0-9][a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

# Fixed collection UUIDs (stable across runs/hosts).
COLLECTIONS = [
    {"id": "a11c7100-0000-4000-8000-000000000a11", "alias": "all",
     "title": "All AI-CTI", "cats": None,
     "description": "The full OWASP GenAI AI-CTI catalog: both Category A and Category B."},
    {"id": "ca7a0a00-0000-4000-8000-0000000000aa", "alias": "category-a",
     "title": "Category A — threat actors using AI (MITRE ATT&CK)", "cats": {"A"},
     "description": "Threat actors USING AI/LLMs to conduct attacks, mapped to MITRE ATT&CK + the LLM-TTP taxonomy."},
    {"id": "ca7b0b00-0000-4000-8000-0000000000bb", "alias": "category-b",
     "title": "Category B — threat actors attacking AI systems (MITRE ATLAS)", "cats": {"B"},
     "description": "Threat actors ATTACKING AI/ML/LLM systems, mapped to MITRE ATLAS."},
]

def harvest_ids(o):
    out = set()
    def walk(v):
        if isinstance(v, str):
            if ID_PAT.match(v): out.add(v)
        elif isinstance(v, list):
            for x in v: walk(x)
        elif isinstance(v, dict):
            for k, x in v.items():
                if k == "id": continue           # don't re-add the object's own id
                walk(x)
                if isinstance(k, str) and ID_PAT.match(k): out.add(k)   # extension-definition ids live in keys
    walk(o)
    return out

def closure(by_id, seed, always):
    inc = set(seed) | (set(always) & set(by_id))
    changed = True
    while changed:
        changed = False
        # pull in relationships that touch the set (and their endpoints)
        for o in by_id.values():
            if o["type"] == "relationship" and o["id"] not in inc:
                if o.get("source_ref") in inc or o.get("target_ref") in inc:
                    inc.add(o["id"]); changed = True
        # pull in everything referenced by included objects
        for oid in list(inc):
            for rid in harvest_ids(by_id[oid]):
                if rid in by_id and rid not in inc:
                    inc.add(rid); changed = True
    return inc

def envelope(objs):
    return {"more": False, "objects": objs}

def manifest(objs):
    return {"more": False, "objects": [
        {"id": o["id"], "date_added": o.get("modified") or o.get("created"),
         "version": o.get("modified") or o.get("created"), "media_type": STIX_MT}
        for o in objs]}

def write(path: Path, obj):
    path.mkdir(parents=True, exist_ok=True)
    (path / "index.json").write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--base-url", required=True, help="public origin, e.g. https://taxii.aithreatintelfeed.org")
    a = ap.parse_args()
    base = a.base_url.rstrip("/")
    bundle = json.loads(Path(a.bundle).read_text(encoding="utf-8"))
    allobjs = bundle["objects"]
    by_id = {o["id"]: o for o in allobjs}
    # objects that must appear in every collection (meta/provenance)
    always = [o["id"] for o in allobjs if o["type"] in ("extension-definition", "identity")
              and ("project:owasp-genai" in o["id"] or o["type"] == "extension-definition")]

    root_url = f"{base}/taxii2/{API_ROOT}/"
    out = Path(a.out)

    # discovery  (/taxii2/)
    write(out / "taxii2", {
        "title": "OWASP GenAI Threat Intelligence Feed",
        "description": "AI cyber threat intelligence (STIX 2.1) — threat actors using AI (Cat A) and attacking AI (Cat B).",
        "contact": "https://genai.owasp.org/initiatives/#ai-threat-intel",
        "default": root_url, "api_roots": [root_url]})

    # api-root  (/taxii2/feed/)
    write(out / "taxii2" / API_ROOT, {
        "title": "OWASP GenAI AI-CTI", "description": "Read-only TAXII 2.1 API root.",
        "versions": [TAXII_MT], "max_content_length": 104857600})

    # collections
    coll_resources = []
    for c in COLLECTIONS:
        if c["cats"] is None:
            ids = set(by_id)
        else:
            seed = [o["id"] for o in allobjs if set(o.get("ai_cti_category", [])) & c["cats"]]
            ids = closure(by_id, seed, always)
        objs = [by_id[i] for i in sorted(ids)]
        res = {"id": c["id"], "title": c["title"], "description": c["description"],
               "can_read": True, "can_write": False, "media_types": [STIX_MT]}
        coll_resources.append(res)
        cdir = out / "taxii2" / API_ROOT / "collections" / c["id"]
        write(cdir, res)
        write(cdir / "objects", envelope(objs))
        write(cdir / "manifest", manifest(objs))
        # friendly alias path -> same collection resource (convenience, not required by spec)
        write(out / "taxii2" / API_ROOT / "collections" / c["alias"], res)
        print(f"collection {c['alias']:12} id={c['id']} objects={len(objs)}")

    write(out / "taxii2" / API_ROOT / "collections", {"collections": coll_resources})
    print(f"wrote TAXII 2.1 tree to {out}  base={base}")

if __name__ == "__main__":
    main()
