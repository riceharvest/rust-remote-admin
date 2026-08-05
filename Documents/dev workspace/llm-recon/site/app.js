/* ============================================================================
   SILICON RECON — public census site renderer
   Vanilla JS, no dependencies, no CDN. Fetches the k-anonymized aggregates
   written by `srecon publish` from data/*.json and renders:
     - summary stat strip
     - 30-day verdict-mix trend (hairline stacked-area SVG, cross-hatch fills)
     - frameworks table
     - ASN table
     - regions (geo) panel
     - hashcat-style status bar
   Degrades gracefully: a missing/unreadable data file renders a dim
   "no data yet — run srecon publish" placeholder instead of breaking.
   ========================================================================== */
(function () {
  'use strict';

  var FILES = {
    summary:    'data/summary.json',
    trend:      'data/trend.json',
    frameworks: 'data/frameworks.json',
    asns:       'data/asns.json',
    geo:        'data/geo.json',
    shodan:     'data/shodan_census.json'
  };

  var PLACEHOLDER_MSG = 'no data yet — run srecon publish';
  var TREND_DAYS = 30;

  /* ------------------------------------------------------------------ utils */

  function $(id) { return document.getElementById(id); }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function fmt(n) {
    if (n === undefined || n === null || n === '') return '—';
    var v = Number(n);
    if (isNaN(v)) return String(n);
    return v.toLocaleString('en-US');
  }

  function pct(ratio) {
    if (ratio === undefined || ratio === null || isNaN(Number(ratio))) return '—';
    return (Number(ratio) * 100).toFixed(1) + '%';
  }

  /* "2026-08-05T09:12:00+00:00" -> "2026-08-05 09:12" (UTC), else the raw string */
  function fmtStamp(iso, withTime) {
    if (!iso) return '—';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    var s = d.toISOString().slice(0, withTime ? 16 : 10);
    return withTime ? s.replace('T', ' ') + ' UTC' : s;
  }

  function load(name) {
    var url = FILES[name];
    return fetch(url).then(function (res) {
      if (!res.ok) throw new Error('HTTP ' + res.status + ' for ' + url);
      return res.json();
    }).catch(function (err) {
      /* Requirement: a clear console message when a fetch fails — incl. the
         classic file:// CORS case, where every fetch is blocked. */
      console.warn(
        '[srecon-site] failed to load ' + url + ': ' + err.message +
        '. If you opened index.html directly over file://, the browser blocks ' +
        'JSON fetches (CORS). Serve the directory instead, e.g. ' +
        '`python3 -m http.server 8000` from site/ and open ' +
        'http://127.0.0.1:8000/. The section will show a placeholder until ' +
        '`srecon publish` has written the data files.'
      );
      return null;
    });
  }

  function placeholderInto(container, msg) {
    container.textContent = '';
    var p = el('p', 'placeholder', msg || PLACEHOLDER_MSG);
    container.appendChild(p);
  }

  function stripEmpty(container) {
    container.textContent = '';
  }

  /* ------------------------------------------------------------- summary strip */

  function renderSummary(summary) {
    var has = summary && typeof summary === 'object';
    var ratio = has && summary.honeypot_ratio !== undefined
      ? summary.honeypot_ratio
      : (has && summary.live ? (summary.impostor || 0) / summary.live : null);

    setStat('stat-total', has ? summary.targets : null);
    setStat('stat-live', has ? summary.live : null, 'blue');
    setStat('stat-genuine', has ? summary.genuine : null);
    setStat('stat-impostor', has ? summary.impostor : null);
    setStat('stat-honeypot', ratio === null ? null : pct(ratio));

    function setStat(id, val, cls) {
      var node = $(id);
      if (!node) return;
      node.textContent = val === null || val === undefined ? '—' : fmt(val);
      node.classList.remove('blue', 'dim');
      if (cls) node.classList.add(cls);
    }

    /* status bar */
    $('sb-targets').textContent = 'TARGETS: ' + (has ? fmt(summary.targets) : '—');
    $('sb-live').textContent = 'LIVE: ' + (has ? fmt(summary.live) : '—');
    $('sb-sweep').textContent = 'LAST SWEEP: ' + (has ? fmtStamp(summary.last_scan_at, false) : '—');
    $('sb-generated').textContent = 'GENERATED: ' + (has ? fmtStamp(summary.generated_at, true) : '—');
    $('sb-ratio').textContent = 'HONEYPOT RATIO: ' +
      (ratio === null ? '—' : pct(ratio));
  }

  /* ------------------------------------------------------------------- trend */

  var VERDICT_SERIES = [
    { key: 'genuine',  label: 'Genuine',  color: '#1a2ee6', hatch: 'hatchBlue', density: 2 },
    { key: 'impostor', label: 'Impostor', color: '#1a1a18', hatch: 'hatchInk',  density: 3 },
    { key: 'unknown',  label: 'Unknown',  color: '#8a877c', hatch: 'hatchInk',  density: 5 },
    { key: 'dark',     label: 'Dark',     color: '#b9b4a4', hatch: 'hatchInk',  density: 8 },
    { key: 'error',    label: 'Error',    color: '#6b6a63', hatch: 'hatchInk',  density: 11 }
  ];

  function renderLegend(container, days) {
    container.textContent = '';
    var totals = { genuine: 0, impostor: 0, unknown: 0, dark: 0, error: 0 };
    days.forEach(function (d) {
      VERDICT_SERIES.forEach(function (s) { totals[s.key] += d[s.key] || 0; });
    });
    VERDICT_SERIES.forEach(function (s) {
      var item = el('span', 'legend-item');
      var swatch = el('span', 'legend-swatch');
      swatch.style.color = s.color;
      item.appendChild(swatch);
      item.appendChild(document.createTextNode(
        s.label + ' ' + fmt(totals[s.key])
      ));
      container.appendChild(item);
    });
  }

  function renderTrend(trend) {
    var panel = $('trend-chart');
    var days = trend && Array.isArray(trend.days) ? trend.days : [];
    var totalLive = days.reduce(function (a, d) { return a + (d.total || 0); }, 0);

    if (!days.length || totalLive === 0) {
      placeholderInto(panel, PLACEHOLDER_MSG);
      $('trend-legend').textContent = '';
      return;
    }

    /* keep the trailing window (schema already emits 30; be defensive) */
    days = days.slice(-TREND_DAYS);

    var W = 900, H = 250, PAD = { top: 14, right: 14, bottom: 22, left: 46 };
    var iw = W - PAD.left - PAD.right, ih = H - PAD.top - PAD.bottom;
    var maxY = 1;
    days.forEach(function (d) { if (d.total > maxY) maxY = d.total; });

    var xAt = function (i) { return PAD.left + (days.length === 1 ? iw / 2 : i * iw / (days.length - 1)); };
    var yAt = function (v) { return PAD.top + ih - (v / maxY) * ih; };

    var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'Stacked area chart of verdict mix over the last 30 days');

    var defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
    [
      { id: 'hatchBlue', w: 6, rot: 45, stroke: '#1a2ee6', width: 0.8, op: 0.5 },
      { id: 'hatchInk',  w: 7, rot: -45, stroke: '#1a1a18', width: 0.7, op: 0.35 }
    ].forEach(function (p) {
      var pat = document.createElementNS('http://www.w3.org/2000/svg', 'pattern');
      pat.setAttribute('id', p.id);
      pat.setAttribute('width', p.w); pat.setAttribute('height', p.w);
      pat.setAttribute('patternUnits', 'userSpaceOnUse');
      pat.setAttribute('patternTransform', 'rotate(' + p.rot + ')');
      var ln = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      ln.setAttribute('x1', 0); ln.setAttribute('y1', 0);
      ln.setAttribute('x2', 0); ln.setAttribute('y2', p.w);
      ln.setAttribute('stroke', p.stroke);
      ln.setAttribute('stroke-width', p.width);
      ln.setAttribute('opacity', p.op);
      pat.appendChild(ln);
      defs.appendChild(pat);
    });
    svg.appendChild(defs);

    /* grid hairlines + y labels */
    var gridVals = [0, 0.25, 0.5, 0.75, 1];
    gridVals.forEach(function (f) {
      var y = yAt(maxY * f);
      var g = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      g.setAttribute('x1', PAD.left); g.setAttribute('x2', W - PAD.right);
      g.setAttribute('y1', y); g.setAttribute('y2', y);
      g.setAttribute('stroke', '#1a1a18');
      g.setAttribute('stroke-width', f === 0 ? 1 : 0.5);
      g.setAttribute('opacity', f === 0 ? 0.6 : 0.22);
      svg.appendChild(g);
      var t = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      t.setAttribute('x', PAD.left - 8); t.setAttribute('y', y + 3.5);
      t.setAttribute('text-anchor', 'end');
      t.setAttribute('font-family', 'ui-monospace, Consolas, monospace');
      t.setAttribute('font-size', 9.5);
      t.setAttribute('fill', '#1a1a18');
      t.setAttribute('opacity', 0.6);
      t.textContent = fmt(Math.round(maxY * f));
      svg.appendChild(t);
    });

    /* stacked area bands (genuine at the bottom, error on top) */
    var cum = days.map(function () { return 0; });
    VERDICT_SERIES.forEach(function (s) {
      var top = days.map(function (d, i) {
        cum[i] += d[s.key] || 0;
        return xAt(i) + ',' + yAt(cum[i]);
      });
      var bot = days.map(function (d, i) {
        return xAt(i) + ',' + yAt(cum[i] - (d[s.key] || 0));
      }).reverse();
      var pts = top.concat(bot).join(' ');

      var poly = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
      poly.setAttribute('points', pts);
      poly.setAttribute('fill', 'url(#' + s.hatch + ')');
      poly.setAttribute('fill-opacity', s.density === 2 ? 0.85 : 0.55);
      poly.setAttribute('stroke', 'none');
      svg.appendChild(poly);

      /* hairline along each band's top edge */
      var line = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
      line.setAttribute('points', top.join(' '));
      line.setAttribute('fill', 'none');
      line.setAttribute('stroke', s.color);
      line.setAttribute('stroke-width', 1);
      line.setAttribute('opacity', s.key === 'genuine' ? 1 : 0.75);
      svg.appendChild(line);
    });

    /* ultramarine stroke along the total line */
    var totalLine = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
    totalLine.setAttribute('points', days.map(function (d, i) {
      return xAt(i) + ',' + yAt(d.total);
    }).join(' '));
    totalLine.setAttribute('fill', 'none');
    totalLine.setAttribute('stroke', '#1a2ee6');
    totalLine.setAttribute('stroke-width', 1.4);
    svg.appendChild(totalLine);

    /* hover targets: one invisible column per day, <title> tooltip per spec */
    var perCol = iw / Math.max(1, days.length);
    days.forEach(function (d, i) {
      var rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      rect.setAttribute('x', xAt(i) - perCol / 2);
      rect.setAttribute('y', PAD.top);
      rect.setAttribute('width', perCol);
      rect.setAttribute('height', ih);
      rect.setAttribute('fill', 'transparent');
      var title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
      title.textContent = d.day + ' — total ' + fmt(d.total) +
        ' · genuine ' + fmt(d.genuine) +
        ' · impostor ' + fmt(d.impostor) +
        ' · unknown ' + fmt(d.unknown) +
        ' · dark ' + fmt(d.dark) +
        ' · error ' + fmt(d.error);
      rect.appendChild(title);
      svg.appendChild(rect);
    });

    stripEmpty(panel);
    panel.appendChild(svg);
    renderLegend($('trend-legend'), days);
  }

  /* ----------------------------------------------------------- tables (shared) */

  function tableBody(tableId) {
    return $(tableId).querySelector('tbody');
  }

  function fillTable(tableId, headers, rows, emptyMsg) {
    var tbody = tableBody(tableId);
    tbody.textContent = '';
    if (!rows.length) {
      var tr = el('tr');
      var td = el('td', 'placeholder-cell', emptyMsg || PLACEHOLDER_MSG);
      td.colSpan = headers.length;
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    rows.forEach(function (cells) {
      var tr = el('tr');
      if (cells.dim) tr.className = 'dim';
      cells.values.forEach(function (c) {
        var td = el('td', c.cls || '');
        if (c.text !== undefined && c.text !== null) td.textContent = c.text;
        else td.appendChild(c.node);
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
  }

  /* ------------------------------------------------------------- frameworks */

  function renderFrameworks(data) {
    var fws = data && data.frameworks ? data.frameworks : null;
    if (!fws || !Object.keys(fws).length) {
      fillTable('frameworks-table', 5, [], PLACEHOLDER_MSG);
      return;
    }
    var rows = Object.keys(fws).map(function (name) {
      var f = fws[name] || {};
      var models = (f.models_top || []).slice(0, 4)
        .map(function (m) { return m.model + '×' + fmt(m.count); })
        .join(', ') || '—';
      var genuineCls = f.genuine_count ? 'genuine-ok' : '';
      return {
        values: [
          { text: name, cls: 'fw' },
          { text: fmt(f.count), cls: 'num' },
          { text: fmt(f.genuine_count), cls: 'num ' + genuineCls },
          { text: (f.avg_score === undefined ? '—' : Number(f.avg_score).toFixed(2)), cls: 'num' },
          { text: models, cls: 'model-cell' }
        ]
      };
    });
    fillTable('frameworks-table', 5, rows);
  }

  /* --------------------------------------------------------------------- ASN */

  function renderAsns(data) {
    var asns = data && Array.isArray(data.asns) ? data.asns : null;
    if (!asns || !asns.length) {
      fillTable('asn-table', 3, [], PLACEHOLDER_MSG);
      return;
    }
    var minBucket = data.min_bucket;
    var rows = asns.map(function (a) {
      var isOther = a.asn === 'other' || !a.asn;
      return {
        dim: isOther,
        values: [
          { text: isOther ? 'other' : a.asn, cls: 'fw' },
          {
            text: isOther
              ? (minBucket ? '(suppressed — buckets < ' + minBucket + ' merged)' : '(suppressed small buckets)')
              : (a.as_name || '—')
          },
          { text: fmt(a.count), cls: 'num' }
        ]
      };
    });
    fillTable('asn-table', 3, rows);
  }

  /* --------------------------------------------------------------------- geo */

  function renderGeo(data) {
    var panel = $('geo-panel');
    var ok = data && data.available && data.countries &&
      Object.keys(data.countries).length;
    if (!ok) {
      placeholderInto(panel, (data && data.note) ? 'geo: ' + data.note : PLACEHOLDER_MSG);
      return;
    }
    stripEmpty(panel);
    var chips = el('div', 'geo-chips');
    Object.keys(data.countries).forEach(function (cc) {
      var chip = el('span', 'geo-chip' + (cc === 'other' ? ' dim' : ''));
      var b = el('b', null, cc);
      chip.appendChild(b);
      chip.appendChild(document.createTextNode(' ' + fmt(data.countries[cc])));
      chips.appendChild(chip);
    });
    panel.appendChild(chips);
  }

  /* ------------------------------------------------------------------- boot */

  function renderShodan(data) {
    var panel = $('shodan-panel');
    if (!panel) return;
    if (!data || !data.counts || !Object.keys(data.counts).length) {
      panel.textContent = '';
      panel.appendChild(el('p', 'placeholder',
        'no shodan totals — run python3 -m srecon.census'));
      return;
    }
    panel.textContent = '';
    var table = el('table', 'census');
    var thead = el('thead');
    var hr = el('tr');
    ['FRAMEWORK', 'INDEX TOTAL', 'NOTE'].forEach(function (h) {
      hr.appendChild(el('th', null, h));
    });
    thead.appendChild(hr);
    table.appendChild(thead);
    var tbody = el('tbody');
    var entries = Object.keys(data.counts).map(function (k) {
      return [k, data.counts[k]];
    }).sort(function (a, b) { return (b[1] || 0) - (a[1] || 0); });
    entries.forEach(function (e) {
      var r = el('tr');
      r.appendChild(el('td', null, e[0]));
      r.appendChild(el('td', null, fmt(e[1])));
      r.appendChild(el('td', 'dim', e[1] === null || e[1] === undefined
        ? 'query failed' : 'index-wide'));
      tbody.appendChild(r);
    });
    table.appendChild(tbody);
    panel.appendChild(table);
    if (data.generated_at) {
      panel.appendChild(el('p', 'dim footnote',
        'fetched from Shodan host/count at ' + fmtStamp(data.generated_at, true) +
        ' — totals only, no raw hosts'));
    }
  }

  function boot() {
    renderSummary(null);          /* initial dim state; refined when data lands */
    renderTrend(null);
    renderFrameworks(null);
    renderAsns(null);
    renderGeo(null);
    renderShodan(null);

    Promise.all([
      load('summary').then(function (d) { if (d) renderSummary(d); }),
      load('trend').then(function (d) { if (d) renderTrend(d); }),
      load('frameworks').then(function (d) { if (d) renderFrameworks(d); }),
      load('asns').then(function (d) { if (d) renderAsns(d); }),
      load('geo').then(function (d) { if (d) renderGeo(d); }),
      load('shodan').then(function (d) { if (d) renderShodan(d); })
    ]);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
