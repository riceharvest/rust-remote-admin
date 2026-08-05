# Silicon Recon — public census site

The public, k-anonymized census dashboard. Static site: vanilla HTML/CSS/JS,
no build step, no dependencies, no CDN, no backend. Everything renders from
the aggregate JSON files in [`data/`](data/) that `srecon publish` writes.

```
site/
├── index.html      single-page census dashboard (hero, summary, trend, tables, status bar)
├── style.css       "engraved terminal" design system
├── app.js          fetches data/*.json and renders; degrades to placeholders when data is absent
├── favicon.svg     engraved Argus/rack mark (cream plate, ultramarine eye, ink hairlines)
├── sitemap.xml     minimal sitemap — see "sitemap.xml" below to replace the placeholder URL
├── data/           publish output (summary.json, trend.json, frameworks.json, asns.json, geo.json)
└── README.md
```

## Regenerate the data

From the repository root, with a populated history DB:

```bash
python3 -m srecon publish                  # writes site/data/*.json (defaults: min_bucket=5, lag_days=0)
python3 -m srecon publish --min-bucket 10  # stronger k-anonymity
python3 -m srecon publish --lag-days 7     # exclude rows scanned in the last 7 days
```

`publish --dry-run` prints the would-be output paths without touching disk.
Until you run publish, `data/` only contains `.gitkeep` and the page shows
dimmed "no data yet — run srecon publish" placeholders.

## Pipeline: scan → publish → site in one command

`python3 -m srecon pipeline` runs the scan engine once (in-process), writes the
k-anonymized feed, and prints the site deployment instructions — the whole
regeneration loop in a single, cron-friendly command:

```bash
# from the repository root: scan hetzner + publish, feed trails by a week
python3 -m srecon pipeline --pack hetzner --framework all \
    --out-dir site/data --min-bucket 5 --lag-days 7
```

It accepts the same target/framework/engine flags as `scan` (`--targets`,
`--pack`, `--cidrs`, `--targets-file`, `--framework`, `--workers`, `--timeout`,
`--no-tls`, ...) plus the `publish` knobs (`--out-dir`, `--min-bucket`,
`--lag-days`, `--db`). The scan and the publish share one engine run — nothing
is scanned twice — and the final summary prints the `scan_id` (for
`report --scan-id N`), the publish file list, and the `NEXT:` deploy hint.

### One-shot shell wrapper (cron)

`scripts/pipeline.sh` wraps the pipeline with production defaults
(pack=hetzner, framework=all, out-dir=site/data, min-bucket=5, lag-days=7) and
is safe to run from cron: `set -euo pipefail`, no TTY, no prompts. It prints
`NEXT: deploy site/ to your static host` when it finishes.

```bash
bash scripts/pipeline.sh          # defaults
SRECON_LAG_DAYS=0 bash scripts/pipeline.sh   # publish immediately, no lag
```

### Cron example — daily at 03:00

```cron
# scan + regenerate the census feed every night; deploy happens separately
0 3 * * *  cd /home/dario/Documents/dev\ workspace/llm-recon && bash scripts/pipeline.sh >> /home/dario/Documents/dev\ workspace/llm-recon/logs/pipeline.log 2>&1
```

(`logs/` must exist or the redirect fails; cron emails the log if you omit the
redirect.) The lag-days=7 default keeps the public feed one week behind the
live census as a privacy buffer.

## Run it locally

Serving over `http://` is **required** — the page fetches `data/*.json` with
`fetch()`, and browsers block JSON fetches from `file://` pages (CORS). If you
open `index.html` directly, nothing renders and `app.js` logs a clear
explanation to the browser console. Any static host works; the simplest:

```bash
cd site
python3 -m http.server 8000
# open http://127.0.0.1:8000/
```

## Monthly writeups

`srecon/writeup.py` renders an offline, long-form monthly census report in the
same "engraved terminal" aesthetic as this dashboard — cream plate,
ultramarine accent, Didone serif headlines, monospace data tables, hairline
rules and cross-hatch accents. It aggregates the month's scans and targets
(verdict mix, framework shift vs the previous month, honeypot ratio, model
families, ASN concentration), folds in the month's change alerts and TLS cert
hygiene, and emits a fully self-contained HTML page (inline CSS, no external
assets) or a plain Markdown version for email/newsletter.

```bash
# from the repository root, with a populated history DB
python3 -m srecon.writeup                      # site/reports/YYYY-MM.html for the current month
python3 -m srecon.writeup --year 2026 --month 7
python3 -m srecon.writeup --format md          # Markdown for email/newsletter
python3 -m srecon.writeup --out /tmp/census.html
python3 -m srecon.writeup --include-targets    # PRIVATE: also list top live targets (ip:port)
```

`--include-targets` is off by default — the report is meant to stay
address-free, mirroring the site's "no raw addresses" guarantee. It is a
**private** artifact: unlike `site/data/*.json` it is not k-anonymized, so do
not publish the HTML output as-is on the public site unless you regenerate
without `--include-targets` and review it.

**Publish idea:** keep monthly archives in `site/reports/YYYY-MM.html` and
link them from `index.html` as a "previous censuses" list — the site stays a
flat, static directory (each report is self-contained), and the monthly
long-form writeups become the narrative companion to the live dashboard. A
cron line the day after month-end:

```cron
0 2 1 * *  cd /home/dario/Documents/dev\\ workspace/llm-recon && python3 -m srecon.writeup --year $(date -d 'yesterday' +%Y) --month $(date -d 'yesterday' +%-m)
```

## Deploy

Any static host works — it is a flat directory with no build step and no
backend. For Vercel the repo ships a [`vercel.json`](../vercel.json) at the
repository root so a one-command deploy serves the census at the domain root:

```bash
# from the repository root
npx vercel --prod            # or: vercel deploy --prod  (CLI installed globally)
```

`vercel.json` pins the pure-static behavior: `framework: null`,
`buildCommand: null`, `outputDirectory: "site"` (the census lives in `site/`,
so the deployed root *is* the site — no `Root Directory` override needed),
and `rewrites: []`. Importing the repo in the Vercel dashboard reads the same
file automatically.

### Data regeneration & what gets committed

`srecon publish` writes `site/data/*.json`. The repository `.gitignore`
already ignores `data/` (that pattern matches at any depth), so the JSON feed
is **never committed** — the deployed numbers are whatever the last `publish`
wrote before you deployed. Regenerate, then redeploy:

```bash
python3 -m srecon publish      # writes site/data/*.json
npx vercel --prod
```

(If you ever host `site/` in a place where `.gitignore` no longer covers it,
add `site/data/*.json` to `.gitignore` — the feed must never be committed.)

### Cache headers

`vercel.json` sets two `Cache-Control` regimes:

- **`site/data/*.json` → `no-store`.** Every page load refetches the feed
  fresh from origin, so a regeneration + redeploy replaces the numbers
  immediately and no stale census is ever served from CDN or browser cache.
- **Everything else** (`style.css`, `app.js`, `favicon.svg`, …) →
  `public, max-age=3600, stale-while-revalidate=86400`. Assets are fresh for
  an hour, then may be served stale for up to a day while the CDN revalidates
  in the background — cheap, resilient caching for versionless static files.

### sitemap.xml

`site/sitemap.xml` ships with the placeholder `https://census.example.com/`.
Replace it with the real site URL before launch.

## Privacy guarantee

The feed is safe to publish on a public website, enforced and tested in
`srecon/publish.py`:

- **k-anonymity** — every count bucket smaller than `min_bucket` (default 5)
  is suppressed or merged into an `other` row, so no category is ever small
  enough to single out an individual host.
- **No raw addresses** — the export never selects or emits IP addresses,
  hostnames, PTR records, `ip:port` targets, or banner fingerprints. Only
  coarse aggregates (verdicts, frameworks, model families, ASNs, countries)
  are published.
- **Optional lag** — `--lag-days N` excludes rows scanned within the last N
  days from the export.
- **Tests** — `tests/test_publish.py` asserts no IPv4-looking string ever
  appears in the output files.

The status bar on every page states the guarantee:
`DATA: k-anonymized, no raw addresses`.
