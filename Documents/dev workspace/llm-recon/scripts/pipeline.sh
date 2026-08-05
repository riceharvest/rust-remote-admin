#!/usr/bin/env bash
# Silicon Recon — one-shot scan -> publish -> site pipeline (cron-friendly).
#
# Runs the full pipeline: scan (hetzner pack, all frameworks) -> k-anonymized
# publish (site/data/*.json, min_bucket=5, lag_days=7 so the public feed trails
# the live census by a week) -> prints site deployment instructions.
#
# Cron-safe: no TTY, non-interactive, strict mode. Logs to stdout (cron mails
# it); every step exits non-zero on failure so cron notices.
#
# Overridable via environment (defaults shown):
#   SRECON_PACK=hetzner  SRECON_FRAMEWORK=all  SRECON_OUT_DIR=site/data
#   SRECON_MIN_BUCKET=5  SRECON_LAG_DAYS=7     SRECON_WORKERS=1000
set -euo pipefail

# Resolve the repository root from this script's location (handles spaces in
# the path): scripts/pipeline.sh -> repo root.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PACK="${SRECON_PACK:-hetzner}"
FRAMEWORK="${SRECON_FRAMEWORK:-all}"
OUT_DIR="${SRECON_OUT_DIR:-site/data}"
MIN_BUCKET="${SRECON_MIN_BUCKET:-5}"
LAG_DAYS="${SRECON_LAG_DAYS:-7}"
WORKERS="${SRECON_WORKERS:-1000}"

cd "${REPO_ROOT}"

echo "[pipeline] repo: ${REPO_ROOT}"
echo "[pipeline] scan: pack=${PACK} framework=${FRAMEWORK} workers=${WORKERS}"
echo "[pipeline] publish: out-dir=${OUT_DIR} min-bucket=${MIN_BUCKET} lag-days=${LAG_DAYS}"

python3 -m srecon pipeline \
    --pack "${PACK}" \
    --framework "${FRAMEWORK}" \
    --workers "${WORKERS}" \
    --out-dir "${OUT_DIR}" \
    --min-bucket "${MIN_BUCKET}" \
    --lag-days "${LAG_DAYS}"

echo
echo "NEXT: deploy site/ to your static host"
echo "  e.g.  rsync -av site/ user@host:/var/www/silicon-recon/"
