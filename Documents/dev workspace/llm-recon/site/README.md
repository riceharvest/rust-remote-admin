# Silicon Recon — public census site

The public, k-anonymized census dashboard. Static site: vanilla HTML/CSS/JS,
no build step, no dependencies, no CDN, no backend. Everything renders from
the aggregate JSON files in [`data/`](data/) that `srecon publish` writes.

```
site/
├── index.html      single-page census dashboard (hero, summary, trend, tables, status bar)
├── style.css       "engraved terminal" design system
├── app.js          fetches data/*.json and renders; degrades to placeholders when data is absent
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

## Deploy

Any static host works — it is a flat directory with no build step and no
backend. **Vercel works with zero config**: import the repo, set
`Root Directory` to `site/`, and the default static output serves
`index.html` + `data/*.json` as-is. (Netlify, GitHub Pages, S3/CloudFront,
nginx, etc. all work the same way.)

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
