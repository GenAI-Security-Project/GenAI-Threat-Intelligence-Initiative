#!/usr/bin/env bash
# Regenerate the TAXII feed from the repo and reload Caddy. Idempotent; run on boot and on a timer.
set -euo pipefail

REPO=/opt/aictifeed/repo
BRANCH="$(cat /opt/aictifeed/branch 2>/dev/null || echo main)"
BASE_URL="${BASE_URL:-https://taxii.aithreatintelfeed.org}"

cd "$REPO"
# Track the configured branch (switch /opt/aictifeed/branch to 'main' once the PRs merge).
git fetch --depth 1 origin "$BRANCH"
git reset --hard "origin/$BRANCH"

# Build the static TAXII 2.1 tree.
python3 deploy/taxii/generate_taxii.py \
	--bundle stix/threat-actors-ai-stix2.1.json \
	--out /var/www/taxii \
	--base-url "$BASE_URL"

# Landing page + direct STIX bundle download.
mkdir -p /var/www/site/stix
cp -f deploy/taxii/site/index.html /var/www/site/index.html
cp -f stix/threat-actors-ai-stix2.1.json /var/www/site/stix/threat-actors-ai-stix2.1.json

chown -R caddy:caddy /var/www/taxii /var/www/site 2>/dev/null || true
systemctl reload caddy 2>/dev/null || systemctl restart caddy 2>/dev/null || true
echo "feed regenerated from $BRANCH @ $(git rev-parse --short HEAD)"
