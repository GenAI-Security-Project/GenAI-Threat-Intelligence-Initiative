# TAXII 2.1 feed deployment

Serves the project's STIX 2.1 bundle as a **static, spec-compliant TAXII 2.1 feed** behind **Caddy**
(automatic Let's Encrypt TLS). Read-only (polling). Three collections, split on the `ai_cti_category`
tag (see `../../stix/EXTENSION.md`):

| Collection | Contents |
|---|---|
| `all` | the full catalog |
| `category-a` | threat actors **using** AI (MITRE ATT&CK) + their graph |
| `category-b` | threat actors **attacking** AI systems (MITRE ATLAS) + their graph |

**Discovery:** `https://taxii.aithreatintelfeed.org/taxii2/`

## Design
- **Stateless, Git-driven.** `generate_taxii.py` turns the STIX bundle into a tree of `index.json`
  files; Caddy serves them with the `application/taxii+json;version=2.1` media type. No database, no
  app server. Category collections are reference-closed so each is a self-contained STIX graph, and
  always include the category `extension-definition` + the project `identity`.
- **Self-healing.** A systemd timer (`aictifeed-update.timer`, every 30 min) runs `deploy.sh`, which
  `git reset --hard` to the configured branch, regenerates the feed, and reloads Caddy. **Any fix is a
  commit** — no SSH needed to update the live feed.
- **Portable (Stage 3).** Everything is in this repo. Standing up an OWASP-owned droplet = boot Ubuntu
  24.04 with `cloud-init.yaml`, point DNS, done.

## Files
- `cloud-init.yaml` — droplet bootstrap (install Caddy, clone repo, build feed, enable timer).
- `generate_taxii.py` — STIX bundle → static TAXII 2.1 tree (stdlib only).
- `Caddyfile` — TLS + routing + the TAXII media type; `:8080` plain-HTTP mirror for pre-DNS smoke tests.
- `deploy.sh` — pull + regenerate + reload (run on boot and by the timer).
- `aictifeed-update.{service,timer}` — the refresh timer.
- `site/index.html` — public landing page served at `aithreatintelfeed.org`.

## Operations
- **Source branch:** set in `/opt/aictifeed/branch` on the droplet. It starts at `phase2/taxii-server`
  (so the feed has data before the PRs merge); **switch to `main` once the Phase-1/2 PRs are merged**:
  `echo main > /opt/aictifeed/branch` (the next timer run picks it up).
- **DNS:** point `A` records for `aithreatintelfeed.org`, `www`, `taxii.aithreatintelfeed.org`, and
  `aithreatintelfeed.com` (+`www`) at the droplet IP. Caddy issues certs automatically once they resolve.
- **Smoke test before DNS/TLS:** `curl http://<droplet-ip>:8080/taxii2/`.
- **Smoke test after DNS/TLS:**
  `curl -H 'Accept: application/taxii+json;version=2.1' https://taxii.aithreatintelfeed.org/taxii2/`

## Limitations / upgrade path
A static feed has **no server-side filtering or pagination** (`added_after`, `match[...]`, `limit`);
each collection returns a single page (`more: false`). That's fine for polling the full set. If a
consumer needs query filtering, drop in a real TAXII 2.1 server (OASIS **Medallion**, or **Arango TAXII
Server** for production scale) behind the same Caddy + domain, fed by the same per-category bundles.
