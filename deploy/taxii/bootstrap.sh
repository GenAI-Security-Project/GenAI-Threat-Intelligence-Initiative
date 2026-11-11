#!/usr/bin/env bash
# One-shot bootstrap for a fresh Ubuntu 24.04 droplet: install Caddy, clone the repo, build the
# TAXII feed, and enable the self-update timer. Run as root. Idempotent. Usage: bootstrap.sh [branch]
set -euo pipefail
BRANCH="${1:-main}"
REPO_URL="https://github.com/GenAI-Security-Project/GenAI-Threat-Intelligence-Initiative.git"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git python3 curl debian-keyring debian-archive-keyring apt-transport-https

# Caddy (official apt repo)
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
apt-get update
apt-get install -y caddy

# Repo + feed
mkdir -p /opt/aictifeed
echo "$BRANCH" > /opt/aictifeed/branch
rm -rf /opt/aictifeed/repo
git clone --branch "$BRANCH" --depth 1 "$REPO_URL" /opt/aictifeed/repo
chmod +x /opt/aictifeed/repo/deploy/taxii/deploy.sh
bash /opt/aictifeed/repo/deploy/taxii/deploy.sh

# Caddy config
install -m 0644 /opt/aictifeed/repo/deploy/taxii/Caddyfile /etc/caddy/Caddyfile
systemctl enable caddy
systemctl restart caddy

# Self-update timer
install -m 0644 /opt/aictifeed/repo/deploy/taxii/aictifeed-update.service /etc/systemd/system/aictifeed-update.service
install -m 0644 /opt/aictifeed/repo/deploy/taxii/aictifeed-update.timer /etc/systemd/system/aictifeed-update.timer
systemctl daemon-reload
systemctl enable --now aictifeed-update.timer
echo "BOOTSTRAP OK ($BRANCH)"
