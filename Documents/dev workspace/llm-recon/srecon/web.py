"""Auto-split from silicon_recon.py. Stdlib only."""
import argparse
import json
import resource
import threading
import time
import urllib.parse
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import PROBE_TIMEOUT, SCANS, HISTORY
from .engine import scan_events
from .targets import country_cidrs, bgpview_prefixes
from .packs import PACKS

PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SILICON RECON // LLM SERVER FINGERPRINT</title>
<style>
  :root {
    --phos: #33ff66; --phos-dim: #1a9933; --amber: #ffb000; --red: #ff3333;
    --bg: #050805; --panel: #0a120a; --line: #1c3a1c;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg); color: var(--phos);
    font-family: "Courier New", ui-monospace, monospace;
    font-size: 14px; line-height: 1.45; min-height: 100vh;
  }
  body::after {
    content: ""; position: fixed; inset: 0; pointer-events: none; z-index: 50;
    background: repeating-linear-gradient(0deg, rgba(0,0,0,.22) 0 1px, transparent 1px 3px);
  }
  .wrap { max-width: 1200px; margin: 0 auto; padding: 18px 20px 60px; }
  .classif {
    text-align: center; letter-spacing: .35em; font-weight: bold;
    color: var(--amber); border: 1px solid var(--amber);
    padding: 5px 0; margin-bottom: 4px; font-size: 12px;
  }
  .classif.bottom { margin: 4px 0 18px; }
  h1 {
    text-align: center; font-size: 26px; letter-spacing: .2em;
    margin: 22px 0 4px; text-shadow: 0 0 12px rgba(51,255,102,.6);
  }
  .sub { text-align: center; color: var(--phos-dim); letter-spacing: .3em; font-size: 11px; margin-bottom: 14px; }
  .panel { border: 1px solid var(--line); background: var(--panel); padding: 14px 16px; margin-bottom: 18px; }
  .panel h2 { font-size: 12px; letter-spacing: .25em; color: var(--amber); margin-bottom: 10px; }
  textarea {
    width: 100%; height: 100px; background: #000; color: var(--phos);
    border: 1px solid var(--line); font: inherit; padding: 10px; resize: vertical;
  }
  textarea:focus, input:focus, select:focus { outline: 1px solid var(--phos); }
  .hint { color: var(--phos-dim); font-size: 11px; margin-top: 6px; }
  button {
    background: transparent; color: var(--phos); border: 1px solid var(--phos);
    font: inherit; letter-spacing: .25em; padding: 10px 22px; cursor: pointer;
    margin-top: 12px; margin-right: 8px; text-transform: uppercase;
  }
  button:hover { background: var(--phos); color: #000; box-shadow: 0 0 14px rgba(51,255,102,.7); }
  button:disabled { opacity: .35; cursor: not-allowed; box-shadow: none; }
  button.danger { color: var(--red); border-color: var(--red); }
  button.danger:hover { background: var(--red); color: #000; box-shadow: 0 0 14px rgba(255,51,51,.7); }
  button.small { padding: 4px 12px; font-size: 11px; margin-top: 0; }
  button.active { background: var(--phos); color: #000; }
  #export, #exportcsv, #abort, #retarget { display: none; }
  .modebar { text-align: center; margin-bottom: 18px; }
  .modebar button { margin: 0 4px; }
  .adv-only { display: none; }
  body.adv .adv-only { display: block; }
  body.adv span.adv-only, body.adv label.adv-only { display: inline-block; }
  body:not(.adv) .simp-hide { display: none !important; }
  .preset-hint { color: var(--amber); font-size: 11px; letter-spacing: .05em; margin: 6px 0 8px; }
  .chip.preset { font-size: 12px; padding: 5px 16px; }
  .chip.pack { border-color: #432; color: var(--amber); }
  .chip.pack:hover { border-color: var(--amber); box-shadow: 0 0 6px rgba(255,176,0,.25); }
  .pack-row { margin: 4px 0 10px; }
  input[type=text], input[type=number], select {
    background: #000; color: var(--phos); border: 1px solid var(--line);
    font: inherit; padding: 5px 8px;
  }
  .opts { margin-top: 10px; font-size: 12px; color: var(--phos-dim); }
  .opts label { margin-right: 18px; }
  .opts input { width: 70px; }
  #log { height: 150px; overflow-y: auto; white-space: pre-wrap; font-size: 12px; color: var(--phos-dim); }
  #log .warn { color: var(--amber); }
  #log .bad { color: var(--red); }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  th, td { border: 1px solid var(--line); padding: 6px 8px; text-align: left; vertical-align: top; }
  th { color: var(--amber); letter-spacing: .15em; font-size: 11px; cursor: pointer; user-select: none; }
  th:hover { background: #102410; }
  tbody tr.d-row { cursor: pointer; }
  tbody tr.d-row:hover { background: #0d1f0d; }
  tr.detail td { background: #020502; font-size: 11.5px; color: var(--phos-dim); }
  .ep { display: inline-block; margin: 2px 10px 2px 0; }
  .stamp {
    display: inline-block; border: 2px solid; padding: 1px 8px; font-weight: bold;
    letter-spacing: .15em; transform: rotate(-2deg);
  }
  .GENUINE { color: var(--phos); border-color: var(--phos); }
  .IMPOSTOR { color: var(--red); border-color: var(--red); text-shadow: 0 0 8px rgba(255,51,51,.8); }
  .UNKNOWN { color: var(--amber); border-color: var(--amber); }
  .DARK, .ERROR { color: #555; border-color: #555; }
  .flag { color: var(--red); font-size: 11px; display: block; }
  .stat { display: inline-block; margin-right: 26px; }
  .stat b { color: var(--amber); }
  #bar-outer { border: 1px solid var(--line); height: 14px; background: #000; }
  #bar-inner {
    height: 100%; width: 0%; background: var(--phos);
    box-shadow: 0 0 10px rgba(51,255,102,.8); transition: width .2s;
  }
  #wire { height: 140px; overflow-y: auto; font-size: 11px; white-space: pre-wrap; color: var(--phos-dim); }
  #wire .w-ok { color: var(--phos); }
  #wire .w-err { color: #555; }
  .chips { margin-bottom: 10px; }
  .chip {
    display: inline-block; border: 1px solid var(--line); padding: 3px 12px;
    margin: 0 6px 6px 0; cursor: pointer; font-size: 11px; letter-spacing: .15em;
  }
  .chip:hover { border-color: var(--phos); }
  .chip.on { background: var(--phos); color: #000; border-color: var(--phos); font-weight: bold; }
  .charts { display: flex; flex-wrap: wrap; gap: 18px; }
  .chart-box { text-align: center; }
  .chart-box .lbl { font-size: 10px; letter-spacing: .2em; color: var(--phos-dim); margin-top: 4px; }
  canvas { background: #000; border: 1px solid var(--line); }
  .cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px; }
  .card { border: 1px solid var(--line); padding: 10px 12px; font-size: 12px; background: #020502; }
  .card .tgt { font-size: 14px; font-weight: bold; }
  .card .muted { color: var(--phos-dim); }
  .cap-note { color: var(--amber); font-size: 11px; margin-top: 8px; }
  .fltbox { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 10px; }
  .fltbox label { color: var(--phos-dim); font-size: 11px; letter-spacing: .1em; white-space: nowrap; }
  input[type=number].scoreflt { width: 64px; }
  .pager { display: flex; align-items: center; gap: 12px; margin: 4px 0 12px; }
  .pager button { margin-top: 0; }
  .xlink { cursor: pointer; color: var(--amber); text-decoration: underline; }
  .xlink:hover { color: var(--phos); }
  .snip { display: block; color: var(--phos-dim); font-size: 11px; white-space: pre-wrap; margin: 2px 0 6px 12px; }
</style>
</head>
<body class="adv">
<div class="wrap">
  <div class="classif">TOP SECRET // SILICON // NOFORN</div>
  <div class="classif bottom">PROJECT SILICON RECON &mdash; HANDLE VIA COMINT CHANNELS ONLY</div>

  <h1>&#9608; SILICON RECON &#9608;</h1>
  <div class="sub">LLM SERVER FINGERPRINTING CONSOLE &mdash; VLLM / SGLANG / LLAMA.CPP / OLLAMA / LM STUDIO / KOBOLDCPP / TEXTGEN-WEBUI / TGI / OPEN WEBUI</div>

  <div class="modebar">
    <button id="mode-simple" class="small">SIMPLE</button>
    <button id="mode-advanced" class="small active">ADVANCED</button>
  </div>

  <div class="panel">
    <h2>&#9656; TARGETING PACKAGE</h2>
    <div class="preset-hint">// SELECT SCAN PROFILE:</div>
    <div class="chips" id="presetchips">
      <span class="chip preset" data-preset="fast">FAST SWEEP</span>
      <span class="chip preset on" data-preset="standard">STANDARD</span>
      <span class="chip preset" data-preset="deep">DEEP SCAN</span>
    </div>
    <div class="preset-hint" style="margin-top:8px">// OR LOAD A TARGET PACK (fills range box):</div>
    <div class="chips pack-row" id="packchips">
      <span class="chip pack" data-pack="coreweave">COREWEAVE</span>
      <span class="chip pack" data-pack="lambda">LAMBDA</span>
      <span class="chip pack" data-pack="vultr">VULTR</span>
      <span class="chip pack" data-pack="hetzner">HETZNER</span>
      <span class="chip pack" data-pack="gcp">GOOGLE CLOUD</span>
      <span class="chip pack" data-pack="azure">AZURE</span>
      <span class="chip pack" data-pack="aws">AWS</span>
      <span class="chip pack" data-pack="allcloud">ALL CLOUDS</span>
    </div>
    <textarea id="targets" placeholder="one target per line:&#10;45.32.114.54:8000&#10;192.0.2.10        (default ports: all framework ports)&#10;203.0.113.0/28    (CIDR, capped at 4096 hosts)"></textarea>
    <div class="hint">// fingerprint only. no inference traffic. collection of open banners is authorized; use of foreign compute is not.</div>
    <div class="chips simp-hide" style="margin-top:10px" id="fwchips">
      <span style="color:var(--phos-dim);font-size:11px;margin-right:8px">FRAMEWORKS:</span>
      <span class="chip on" data-fw="vllm">VLLM</span>
      <span class="chip on" data-fw="llamacpp">LLAMA.CPP</span>
      <span class="chip on" data-fw="sglang">SGLANG</span>
      <span class="chip on" data-fw="ollama">OLLAMA</span>
      <span class="chip on" data-fw="lmstudio">LM STUDIO</span>
      <span class="chip on" data-fw="koboldcpp">KOBOLDCPP</span>
      <span class="chip on" data-fw="tgwui">TEXTGEN-WEBUI</span>
      <span class="chip on" data-fw="tgi">TGI</span>
      <span class="chip on" data-fw="openwebui">OPEN WEBUI</span>
    </div>
    <div class="opts adv-only">
      <label>WORKERS <input type="number" id="opt-workers" value="1000" min="1" max="5000"></label>
      <label>TIMEOUT(s) <input type="number" id="opt-timeout" value="3" min="0.5" max="10" step="0.5"></label>
      <label><input type="checkbox" id="opt-fast" checked> FAST PROFILE</label>
      <label><input type="checkbox" id="opt-enrich" checked> ASN ENRICHMENT</label>
      <label><input type="checkbox" id="opt-exclude-dod" checked> EXCLUDE DoD</label>
      <label><input type="checkbox" id="opt-lean-ports"> LEAN PORTS</label>
      <label><input type="checkbox" id="opt-fanout"> FAN-OUT ±2</label>
      <label><input type="checkbox" id="opt-dedup"> DEDUP (7d)</label>
      <label><input type="checkbox" id="opt-asn-prefilter"> ASN PREFILTER</label>
    </div>
    <div class="adv-only" style="margin-top:10px; border-top:1px dashed #143; padding-top:8px">
      <div class="hint">// SCAN STRATEGY (high-yield optimizations):</div>
      <label><input type="checkbox" id="opt-progressive" checked> PROGRESSIVE DEPTH</label>
      <label><input type="checkbox" id="opt-banner" checked> BANNER PREFILTER</label>
      <label><input type="checkbox" id="opt-adaptive" checked> ADAPTIVE TIMEOUT</label>
      <label><input type="checkbox" id="opt-contentdedup" checked> CONTENT DEDUP</label>
      <label><input type="checkbox" id="opt-diff"> DIFF MODE</label>
      <label><input type="checkbox" id="opt-ptr" checked> PTR ENRICH</label>
      <label><input type="checkbox" id="opt-ct"> CT SEED</label>
      <label><input type="checkbox" id="opt-shodan"> SHODAN SEED</label>
      <label><input type="checkbox" id="opt-sweep-all-ports" checked> SWEEP ALL LLM PORTS</label>
      <div class="hint">// progressive: TCP-sweep one port first, deep-probe only live hosts (up to 160x fewer probes on big ranges). banner: skip non-HTTP services (SSH/SMTP/RDP) on open ports. adaptive: shrink timeout to 3× P95 after first 200 probes. content-dedup: skip reclassifying ≥3 byte-identical responses (CDN/LB clusters). diff: only re-classify hosts whose fingerprint changed since last scan. ptr: reverse-DNS every live host, surfaces fleet hostnames. ct: pull pre-curated hosts from crt.sh (ollama/vllm/sglang certs). shodan: pull pre-curated open-port lists from Shodan API.</div>
    </div>
    <div class="adv-only" style="margin-top:10px">
      <div class="hint">EXCLUDE CIDRS (one per line, e.g. gov/mil ranges):</div>
      <textarea id="excludes" style="height:52px" placeholder="198.51.100.0/24"></textarea>
    </div>
    <button id="go">Initiate Scan</button>
    <button id="abort" class="danger">Abort Scan</button>
    <button id="export">Export JSONL</button>
    <button id="exportcsv">Export CSV</button>
    <button id="retarget" style="background:var(--amber);color:#000">⟳ Retarget Live</button>
  </div>

  <div class="panel simp-hide">
    <h2>&#9656; CIDR RANGE BUILDER</h2>
    <div>
      <input type="text" id="b-ip" value="45.32.114.0" style="width:150px">
      <span style="color:var(--phos-dim)">/</span>
      <input type="number" id="b-prefix" value="24" min="8" max="32" style="width:60px">
      <span id="b-info" class="hint" style="margin-left:10px"></span>
      <br>
      <button id="b-add" class="small">ADD RANGE TO TARGETS</button>
      <button id="b-next" class="small">NEXT SUBNET &raquo;</button>
    </div>
    <div style="margin-top:12px">
      <span style="font-size:11px;color:var(--phos-dim)">COUNTRY:</span>
      <input type="text" id="b-cc" value="US" maxlength="2" style="width:50px">
      <span style="font-size:11px;color:var(--phos-dim)">MAX RANGES:</span>
      <input type="number" id="b-limit" value="256" min="1" max="5000" style="width:80px">
      <button id="b-fetch" class="small">FETCH COUNTRY RANGES (RIR)</button>
      <div class="hint">// pulls real allocations from RIR delegated stats, appends to targeting package. hard cap: 100,000 targets per scan.</div>
    </div>
    <div style="margin-top:12px">
      <span style="font-size:11px;color:var(--phos-dim)">ASN:</span>
      <input type="text" id="b-asn" placeholder="20473" style="width:90px">
      <button id="b-asn-fetch" class="small">FETCH ASN RANGES</button>
      <button id="b-expand" class="small">EXPAND HITS TO /24</button>
      <div class="chips" id="asnchips" style="margin-top:8px">
        <span style="color:var(--phos-dim);font-size:11px;margin-right:8px">PRESETS:</span>
        <span class="chip" data-asn="20473">VULTR</span>
        <span class="chip" data-asn="14061">DIGITALOCEAN</span>
        <span class="chip" data-asn="24940">HETZNER</span>
        <span class="chip" data-asn="16276">OVH</span>
        <span class="chip" data-asn="51167">CONTABO</span>
        <span class="chip" data-asn="63949">LINODE</span>
        <span class="chip" data-asn="16509">AWS</span>
        <span class="chip" data-asn="396982">GCP</span>
        <span class="chip" data-asn="8075">AZURE</span>
        <span class="chip" data-asn="31898">ORACLE</span>
      </div>
      <div class="hint">// LLM servers live in VPS/GPU-cloud space, not residential. select presets or enter an ASN. EXPAND HITS re-targets the /24 of every live hit.</div>
    </div>
  </div>

  <div class="panel adv-only">
    <h2>&#9656; IMPORT SCAN RESULTS &mdash; MASSCAN / ZMAP</h2>
    <textarea id="import" style="height:64px" placeholder='masscan -oG: Host: 1.2.3.4 () Ports: 8000/open/tcp//http//&#10;masscan JSON: [{"ip":"1.2.3.4","ports":[{"port":8000,"status":"open"}]}]&#10;zmap CSV / plain: 1.2.3.4,8000 or 1.2.3.4:8000'></textarea>
    <input type="file" id="import-file" accept=".txt,.json,.csv,.log" style="margin-top:8px;font-size:11px;color:var(--phos-dim)">
    <br><button id="import-go" class="small">PARSE &amp; APPEND TO TARGETS</button>
    <span id="import-info" class="hint" style="margin-left:10px"></span>
  </div>

  <div class="panel">
    <h2>&#9656; SIGNAL PROGRESS</h2>
    <div id="bar-outer"><div id="bar-inner"></div></div>
    <div id="bar-text" class="hint">0 / 0 targets &mdash; 0 requests</div>
    <div class="chart-box" style="margin-top:10px">
      <canvas id="spark" width="1100" height="70"></canvas>
      <div class="lbl">REQUESTS / SECOND</div>
    </div>
  </div>

  <div class="panel adv-only">
    <h2>&#9656; ANALYSIS</h2>
    <div class="charts">
      <div class="chart-box"><canvas id="donut" width="180" height="180"></canvas><div class="lbl">VERDICT MIX</div></div>
      <div class="chart-box"><canvas id="ports" width="300" height="180"></canvas><div class="lbl">LIVE HITS BY PORT</div></div>
      <div class="chart-box"><canvas id="latency" width="300" height="180"></canvas><div class="lbl">LATENCY DISTRIBUTION (MS)</div></div>
      <div class="chart-box"><div id="asnagg" style="width:340px;height:180px;overflow-y:auto;text-align:left;font-size:11px;background:#000;border:1px solid var(--line);padding:6px 8px"></div><div class="lbl">TOP NETWORKS (I/G/U)</div></div>
    </div>
  </div>

  <div class="panel adv-only">
    <h2>&#9656; FLEET CLUSTERS &mdash; SHARED INVENTORY HASH</h2>
    <div id="fleets" class="hint">no fleets detected.</div>
  </div>

  <div class="panel simp-hide">
    <h2>&#9656; LIVE WIRE &mdash; EVERY REQUEST</h2>
    <div id="wire"></div>
  </div>

  <div class="panel">
    <h2>&#9656; FILTERS</h2>
    <div class="chips" id="chips">
      <span class="chip on" data-v="ALL">ALL</span>
      <span class="chip" data-v="GENUINE">GENUINE</span>
      <span class="chip" data-v="IMPOSTOR">IMPOSTOR</span>
      <span class="chip" data-v="UNKNOWN">UNKNOWN</span>
      <span class="chip" data-v="DARK">DARK</span>
    </div>
    <div class="fltbox">
      <input type="text" id="ftext" placeholder="search target / model / flag / PTR / ASN..." style="width:300px">
      <label>SCORE&ge; <input type="number" id="fscoremin" class="scoreflt" min="0" max="100" placeholder="min"></label>
      <label>SCORE&le; <input type="number" id="fscoremax" class="scoreflt" min="0" max="100" placeholder="max"></label>
      <select id="fflag"><option value="ALL">ALL FLAGS</option></select>
      <select id="fverify">
        <option value="ALL">ALL VERIFY</option>
        <option value="live">LIVE</option>
        <option value="auth-walled">AUTH-WALLED</option>
        <option value="honeypot">HONEYPOT</option>
        <option value="timeout">TIMEOUT</option>
        <option value="error">ERROR</option>
        <option value="none">UNVERIFIED</option>
      </select>
    </div>
    <div class="fltbox" style="margin-top:2px">
      <select id="fproduct" class="simp-hide"><option value="ALL">ALL PRODUCTS</option></select>
      <select id="fnet" class="simp-hide">
        <option value="ALL">ALL NET TYPES</option>
        <option value="DATACENTER">DATACENTER</option>
        <option value="RESIDENTIAL">RESIDENTIAL</option>
        <option value="UNKNOWN">UNKNOWN ASN</option>
      </select>
      <span id="fcount" class="hint" style="margin-left:4px"></span>
    </div>
  </div>

  <div class="panel">
    <h2>&#9656; OPERATIONS LOG</h2>
    <div id="log">[SYS] silicon recon console ready. awaiting targeting package.
</div>
  </div>

  <div class="panel">
    <h2>&#9656; COLLECTION SUMMARY</h2>
    <div id="stats"><span class="stat">PROBED: <b>0</b></span><span class="stat">GENUINE: <b>0</b></span><span class="stat">IMPOSTOR: <b>0</b></span><span class="stat">UNKNOWN: <b>0</b></span><span class="stat">DARK: <b>0</b></span></div>
  </div>

  <div class="panel adv-only">
    <h2>&#9656; ARCHIVE &mdash; LAST 10 SCANS</h2>
    <select id="hist" style="min-width:340px"></select>
    <button id="hist-load" class="small">Load</button>
    <button id="hist-refresh" class="small">Refresh List</button>
  </div>

  <div class="panel">
    <h2>&#9656; DOSSIERS</h2>
    <div id="dossiers">
      <div id="pager" class="pager">
        <button id="pg-prev" class="small" type="button">&#9664; PREV</button>
        <span id="pg-info" class="hint"></span>
        <button id="pg-next" class="small" type="button">NEXT &#9654;</button>
        <select id="pg-size">
          <option value="100">100 / page</option>
          <option value="500">500 / page</option>
          <option value="1000">1000 / page</option>
        </select>
      </div>
      <table id="dtable">
        <thead><tr>
          <th data-k="target">TARGET</th><th data-k="product">PRODUCT</th><th data-k="verdict">VERDICT</th>
          <th data-k="version">VERSION</th><th>MODEL / INVENTORY</th><th data-k="ptr">PTR</th><th>ASN</th><th data-k="score">SCORE</th><th>FLAGS</th><th data-k="latency_ms">MS</th>
        </tr></thead>
        <tbody id="rows"></tbody>
      </table>
      <div id="cards" class="cards" style="display:none"></div>
    </div>
    <div id="capnote" class="cap-note"></div>
  </div>

  <div class="classif">TOP SECRET // SILICON // NOFORN</div>
</div>
<script>
const PATHS = ["/","/props","/health","/version","/v1/models","/get_model_info","/get_server_info","/api/tags","/api/version","/api/v0/models","/api/extra/version","/api/v1/model","/v1/internal/model/info","/info","/api/config"];
const RENDER_CAP = 1000;
const S = {
  mode: 'advanced', results: [], total: 0, done: 0, reqs: 0,
  t0: 0, timer: null, scanId: null, ctrl: null,
  filter: {verdict: 'ALL', text: '', product: 'ALL', net: 'ALL',
           flag: 'ALL', verify: 'ALL', scoreMin: null, scoreMax: null},
  sortKey: null, sortAsc: true, rps: [], lastReqs: 0, chartsDirty: false,
  rowsDirty: false, byTarget: {},
  page: 0, pageSize: 100, flagSet: new Set(), _flagSig: '',
};

const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const log = (msg, cls) => {
  const el = $('log');
  const line = document.createElement('div');
  if (cls) line.className = cls;
  line.textContent = `[${new Date().toISOString().substr(11,8)}Z] ${msg}`;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
};

// ---------- mode ----------
function setMode(m) {
  S.mode = m;
  document.body.classList.toggle('adv', m === 'advanced');
  $('mode-simple').classList.toggle('active', m === 'simple');
  $('mode-advanced').classList.toggle('active', m === 'advanced');
  $('dtable').style.display = m === 'advanced' ? '' : 'none';
  $('cards').style.display = m === 'simple' ? '' : 'none';
  renderDossiers();
}
$('mode-simple').onclick = () => setMode('simple');
$('mode-advanced').onclick = () => setMode('advanced');

// ---------- scan presets ----------
const PRESETS = {
  fast:     {workers:2000, timeout:2,  fast:true,  enrich:false, progressive:true, banner:true,  adaptive:true,  contentdedup:true, ptr:false, dedup:true,  diff:false, dod:true,  lean:true, sweep:false},
  standard: {workers:1000, timeout:3,  fast:true,  enrich:true,  progressive:true, banner:true,  adaptive:true,  contentdedup:true, ptr:true,  dedup:false, diff:false, dod:true,  lean:false, sweep:true},
  deep:     {workers:500,  timeout:4.5, fast:false, enrich:true,  progressive:false, banner:true, adaptive:false, contentdedup:true, ptr:true,  dedup:false, diff:true,  dod:false, lean:false, sweep:false},
};
const PRESET_HINTS = {
  fast:     'FAST SWEEP — broad reach. lean ports, DoD excluded, progressive pre-sweep, 7-day dedup. best for big ranges.',
  standard: 'STANDARD — balanced fingerprinting. all 9 frameworks, full enrichment, every high-yield optimization. recommended.',
  deep:     'DEEP SCAN — thorough single-target audit. slow profile, long timeout, diff mode, no prefilter. best for one suspect host.',
};
function applyPreset(name) {
  const p = PRESETS[name]; if (!p) return;
  document.querySelectorAll('#presetchips .chip').forEach(c =>
    c.classList.toggle('on', c.dataset.preset === name));
  $('opt-workers').value = p.workers;
  $('opt-timeout').value = p.timeout;
  $('opt-fast').checked = p.fast;
  $('opt-enrich').checked = p.enrich;
  $('opt-exclude-dod').checked = p.dod;
  $('opt-lean-ports').checked = p.lean;
  $('opt-progressive').checked = p.progressive;
  $('opt-banner').checked = p.banner;
  $('opt-adaptive').checked = p.adaptive;
  $('opt-contentdedup').checked = p.contentdedup;
  $('opt-ptr').checked = p.ptr;
  $('opt-dedup').checked = p.dedup;
  $('opt-diff').checked = p.diff;
  $('opt-sweep-all-ports').checked = p.sweep;
  log(PRESET_HINTS[name], 'warn');
}
document.querySelectorAll('#presetchips .chip').forEach(ch => {
  ch.onclick = () => applyPreset(ch.dataset.preset);
});

// ---------- target packs (cloud providers → announced prefixes) ----------
// injected from srecon.packs at render time — single source of truth
const PACKS = __PACKS_JSON__;
async function loadPack(name) {
  const pk = PACKS[name]; if (!pk) return;
  const chip = document.querySelector(`#packchips .chip[data-pack="${name}"]`);
  log(`loading ${pk.label} target pack (${pk.asns.length} ASN${pk.asns.length>1?'s':''})...`, 'warn');
  if (chip) chip.style.opacity = '0.4';
  let added = 0;
  const errors = [];
  for (const asn of pk.asns) {
    try {
      const r = await fetch(`/api/asn-prefixes?asn=${asn}`);
      const d = await r.json();
      if (d.error) { errors.push(`AS${asn}: ${d.error}`); continue; }
      if (d.prefixes && d.prefixes.length) { appendTargets(d.prefixes); added += d.prefixes.length; }
    } catch (e) { errors.push(`AS${asn}: ${e}`); }
  }
  if (chip) chip.style.opacity = '';
  if (added) log(`${pk.label}: ${added} prefix(es) loaded into targeting package. ${pk.hint}`);
  else log(`${pk.label}: no prefixes returned.`, 'bad');
  errors.forEach(e => log(`  ${e}`, 'bad'));
}
document.querySelectorAll('#packchips .chip').forEach(ch => {
  ch.onclick = () => loadPack(ch.dataset.pack);
});

// ---------- filters ----------
document.querySelectorAll('#chips .chip').forEach(ch => {
  ch.onclick = () => {
    document.querySelectorAll('#chips .chip').forEach(c => c.classList.remove('on'));
    ch.classList.add('on');
    S.filter.verdict = ch.dataset.v;
    S.page = 0;
    renderDossiers();
  };
});
$('ftext').oninput = () => { S.filter.text = $('ftext').value.toLowerCase(); S.page = 0; renderDossiers(); };
$('fproduct').onchange = () => { S.filter.product = $('fproduct').value; S.page = 0; renderDossiers(); };
$('fnet').onchange = () => { S.filter.net = $('fnet').value; S.page = 0; renderDossiers(); };
$('fflag').onchange = () => { S.filter.flag = $('fflag').value; S.page = 0; renderDossiers(); };
$('fverify').onchange = () => { S.filter.verify = $('fverify').value; S.page = 0; renderDossiers(); };
$('fscoremin').oninput = () => {
  const v = parseFloat($('fscoremin').value);
  S.filter.scoreMin = Number.isFinite(v) ? v : null;
  S.page = 0; renderDossiers();
};
$('fscoremax').oninput = () => {
  const v = parseFloat($('fscoremax').value);
  S.filter.scoreMax = Number.isFinite(v) ? v : null;
  S.page = 0; renderDossiers();
};
function refreshFlagSelect() {
  const sel = $('fflag');
  const cur = sel.value;
  const flags = [...S.flagSet].sort();
  sel.innerHTML = '<option value="ALL">ALL FLAGS</option>' +
    flags.map(f => `<option value="${esc(f)}">${esc(f)}</option>`).join('');
  sel.value = flags.includes(cur) ? cur : 'ALL';
}
function syncFlagSet() {
  S.flagSet = new Set();
  for (const d of S.results) for (const f of (d.flags || [])) S.flagSet.add(f);
  const sig = [...S.flagSet].sort().join('\x00');
  if (sig !== S._flagSig) { S._flagSig = sig; refreshFlagSelect(); }
}
// click-to-filter: fleet hashes / ASNs in the intel panels feed the search box
function applyFilterChip(ev) {
  const t = ev.target.closest ? ev.target.closest('.xlink') : null;
  if (!t || !t.dataset.flt) return;
  const val = t.dataset.flt;
  $('ftext').value = val;
  S.filter.text = val.toLowerCase();
  S.page = 0;
  renderDossiers();
}
$('fleets').addEventListener('click', applyFilterChip);
$('asnagg').addEventListener('click', applyFilterChip);

// ---------- pagination ----------
$('pg-prev').onclick = () => { if (S.page > 0) { S.page--; renderDossiers(); } };
$('pg-next').onclick = () => { S.page++; renderDossiers(); };
$('pg-size').onchange = () => {
  S.pageSize = Math.min(RENDER_CAP, Math.max(1, +$('pg-size').value || 100));
  S.page = 0; renderDossiers();
};

// framework chips (multi-select toggle)
document.querySelectorAll('#fwchips .chip').forEach(ch => {
  ch.onclick = () => { ch.classList.toggle('on'); updateBuilder(); };
});
function selectedFrameworks() {
  return [...document.querySelectorAll('#fwchips .chip.on')].map(c => c.dataset.fw);
}

// ---------- CIDR builder ----------
const FW_PORTS = {vllm:[8000,8001], llamacpp:[8080], sglang:[30000], ollama:[11434], lmstudio:[1234], koboldcpp:[5001], tgwui:[5000], tgi:[80,3000], openwebui:[3000]};
const ipToInt = ip => ip.split('.').reduce((a, o) => (a << 8) + (+o), 0) >>> 0;
const intToIp = n => [(n>>>24)&255, (n>>>16)&255, (n>>>8)&255, n&255].join('.');

function builderPorts() {
  const fw = selectedFrameworks();
  const set = new Set();
  (fw.length ? fw : Object.keys(FW_PORTS)).forEach(f => FW_PORTS[f].forEach(p => set.add(p)));
  return [...set];
}
function updateBuilder() {
  const ip = $('b-ip').value.trim() || '0.0.0.0';
  const p = Math.min(32, Math.max(8, +$('b-prefix').value || 24));
  const hosts = p === 32 ? 1 : p === 31 ? 2 : Math.pow(2, 32 - p) - 2;
  const np = builderPorts().length;
  $('b-info').textContent =
    `${ip}/${p} — ${hosts.toLocaleString()} hosts — ~${(hosts * np).toLocaleString()} probes (${np} port(s))`;
}
function appendTargets(lines) {
  const ta = $('targets');
  const cur = ta.value.trim();
  ta.value = (cur ? cur + '\n' : '') + lines.join('\n');
}
$('b-ip').oninput = updateBuilder;
$('b-prefix').oninput = updateBuilder;
$('b-add').onclick = () => {
  const p = Math.min(32, Math.max(8, +$('b-prefix').value || 24));
  appendTargets([`${$('b-ip').value.trim()}/${p}`]);
  log(`range added: ${$('b-ip').value.trim()}/${p}`);
};
$('b-next').onclick = () => {
  const p = Math.min(32, Math.max(8, +$('b-prefix').value || 24));
  const block = Math.pow(2, 32 - p);
  try {
    $('b-ip').value = intToIp((ipToInt($('b-ip').value.trim()) + block) >>> 0);
  } catch (e) { log('bad base IP', 'bad'); }
  updateBuilder();
};
$('b-fetch').onclick = async () => {
  const cc = ($('b-cc').value.trim() || 'US').toUpperCase();
  const limit = Math.min(5000, Math.max(1, +$('b-limit').value || 256));
  log(`fetching ${cc} allocations from RIR delegated stats...`);
  try {
    const r = await fetch(`/api/country-cidrs?cc=${cc}&limit=${limit}`);
    const d = await r.json();
    if (d.error) { log('RIR FETCH FAILED: ' + d.error, 'bad'); return; }
    appendTargets(d.cidrs);
    log(`${d.cidrs.length} ${cc} range(s) appended (${d.total_ranges} total allocated${d.truncated ? ', truncated by limit' : ''}).`);
  } catch (e) { log('RIR FETCH FAILED: ' + e, 'bad'); }
};
updateBuilder();

// ---------- ASN targeting ----------
document.querySelectorAll('#asnchips .chip').forEach(ch => {
  ch.onclick = () => ch.classList.toggle('on');
});
$('b-asn-fetch').onclick = async () => {
  const asns = [...document.querySelectorAll('#asnchips .chip.on')].map(c => c.dataset.asn);
  const free = $('b-asn').value.trim().replace(/^AS/i, '');
  if (free && /^\d+$/.test(free)) asns.push(free);
  if (!asns.length) { log('no ASN selected.', 'warn'); return; }
  for (const asn of asns) {
    log(`fetching announced prefixes for AS${asn} (RIPEstat)...`);
    try {
      const r = await fetch(`/api/asn-prefixes?asn=${asn}`);
      const d = await r.json();
      if (d.error) { log(`AS${asn}: ${d.error}`, 'bad'); continue; }
      appendTargets(d.prefixes);
      log(`AS${asn} ${d.name}: ${d.prefixes.length} prefix(es) appended (${d.total} announced${d.truncated ? ', truncated' : ''}).`);
    } catch (e) { log(`AS${asn} fetch failed: ${e}`, 'bad'); }
  }
};
$('b-expand').onclick = () => {
  const nets = new Set();
  for (const d of S.results) {
    if (d.verdict === 'DARK' || d.verdict === 'ERROR') continue;
    const m = d.target.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}:/);
    if (m) nets.add(`${m[1]}.0/24`);
  }
  if (!nets.size) { log('no live hits to expand.', 'warn'); return; }
  appendTargets([...nets]);
  log(`neighbor expansion: ${nets.size} /24 range(s) appended from live hits.`);
};

// ---------- masscan / zmap import ----------
function parseImport(text) {
  const out = new Set();
  try {
    const j = JSON.parse(text);
    if (Array.isArray(j)) {
      for (const e of j) {
        const ip = e && (e.ip || e.address);
        for (const p of (e && e.ports) || []) {
          if (ip && p && p.port) out.add(`${ip}:${p.port}`);
        }
      }
      if (out.size) return [...out];
    }
  } catch (_) {}
  for (const line of text.split('\n')) {
    const l = line.trim();
    if (!l || l.startsWith('#')) continue;
    let m = l.match(/^Host:\s+(\S+)\s+\(\)\s+Ports:\s+(.*)$/);  // masscan -oG
    if (m) {
      for (const seg of m[2].split(',')) {
        const pm = seg.trim().match(/^(\d+)\/open/);
        if (pm) out.add(`${m[1]}:${pm[1]}`);
      }
      continue;
    }
    m = l.match(/(\d{1,3}(?:\.\d{1,3}){3})\s*[: ,]\s*(\d{1,5})/);  // ip:port | ip,port | ip port
    if (m && +m[2] <= 65535) out.add(`${m[1]}:${m[2]}`);
  }
  return [...out];
}
$('import-go').onclick = () => {
  const found = parseImport($('import').value);
  if (!found.length) { $('import-info').textContent = 'no targets recognized'; return; }
  appendTargets(found);
  $('import-info').textContent = `${found.length} endpoint(s) appended`;
  log(`import: ${found.length} endpoint(s) appended to targeting package.`);
};
$('import-file').onchange = ev => {
  const f = ev.target.files[0];
  if (!f) return;
  const r = new FileReader();
  r.onload = () => { $('import').value = r.result; };
  r.readAsText(f);
};

// ---------- fleet clusters + ASN aggregate ----------
function updateIntel() {
  const byHash = {};
  for (const d of S.results) {
    if (!d.inventory_hash || d.verdict === 'DARK' || d.verdict === 'ERROR') continue;
    (byHash[d.inventory_hash] = byHash[d.inventory_hash] || []).push(d);
  }
  const fleets = Object.entries(byHash)
    .filter(([, arr]) => new Set(arr.map(d => d.target)).size >= 2)
    .sort((a, b) => b[1].length - a[1].length);
  $('fleets').innerHTML = fleets.length ? fleets.slice(0, 20).map(([h, arr]) => {
    const asns = [...new Set(arr.map(d => d.asn).filter(Boolean))];
    const t = {};
    arr.forEach(d => t[d.verdict] = (t[d.verdict] || 0) + 1);
    return `<div style="margin-bottom:8px;border:1px solid var(--line);padding:6px 8px">` +
      `<b style="color:var(--amber)">FLEET #<span class="xlink" data-flt="${esc(h)}">${esc(h)}</span></b> — ${arr.length} host(s)` +
      ` — <span style="color:var(--red)">${t.IMPOSTOR || 0}I</span>/<span style="color:var(--phos)">${t.GENUINE || 0}G</span>/<span style="color:#777">${t.UNKNOWN || 0}U</span>` +
      (asns.length ? ` — AS ${asns.map(esc).join(', ')}` : '') +
      `<br><span style="color:var(--phos-dim)">${arr.slice(0, 8).map(d => esc(d.target)).join(', ')}${arr.length > 8 ? ' …' : ''}</span></div>`;
  }).join('') : 'no fleets detected.';
  const byAsn = {};
  for (const d of S.results) {
    if (!d.asn) continue;
    const k = `AS${d.asn} ${d.as_name || ''}`;
    const e = byAsn[k] = byAsn[k] || {I: 0, G: 0, U: 0, total: 0};
    e.total++;
    if (d.verdict === 'GENUINE') e.G++;
    else if (d.verdict === 'IMPOSTOR') e.I++;
    else e.U++;
  }
  const rows = Object.entries(byAsn).sort((a, b) => b[1].total - a[1].total).slice(0, 30);
  $('asnagg').innerHTML = rows.map(([k, e]) => {
    const tag = k.split(' ')[0];                 // e.g. "AS20473"
    const name = k.split(' ').slice(1).join(' ').slice(0, 32);
    return `<div><span class="xlink" data-flt="${esc(tag)}">${esc(tag)}</span>` +
      (name ? ` ${esc(name)}` : '') +
      ` — <span style="color:var(--red)">${e.I}I</span>/<span style="color:var(--phos)">${e.G}G</span>/<span style="color:#555">${e.U}U</span></div>`;
  }).join('') || '<span class="hint">no ASN data yet.</span>';
}

function matches(d) {
  if (S.filter.verdict !== 'ALL') {
    const v = d.verdict === 'ERROR' ? 'DARK' : d.verdict;
    if (v !== S.filter.verdict) return false;
  }
  if (S.filter.product !== 'ALL' && d.product !== S.filter.product) return false;
  if (S.filter.net !== 'ALL' && (d.net_type || 'UNKNOWN') !== S.filter.net) return false;
  if (S.filter.flag !== 'ALL' && !(d.flags || []).includes(S.filter.flag)) return false;
  if (S.filter.verify !== 'ALL') {
    const vr = d.verify_result || null;
    if (S.filter.verify === 'none') { if (vr) return false; }
    else if (vr !== S.filter.verify) return false;
  }
  if (S.filter.scoreMin != null && (d.score || 0) < S.filter.scoreMin) return false;
  if (S.filter.scoreMax != null && (d.score || 0) > S.filter.scoreMax) return false;
  if (S.filter.text) {
    const ms = Array.isArray(d.models_served)
      ? d.models_served.map(m => m && typeof m === 'object'
          ? (m.name || m.id || JSON.stringify(m)) : m).join(' ')
      : (d.models_served || '');
    const hay = (d.target + ' ' + d.product + ' ' + (d.model || '') + ' ' +
                 (d.version || '') + ' ' + (d.as_name || '') + ' ' +
                 (d.asn ? 'AS' + d.asn : '') + ' ' + (d.ptr || '') + ' ' +
                 (d.owned_by || '') + ' ' + (d.inventory_hash || '') + ' ' +
                 ms + ' ' + (d.flags || []).join(' ')).toLowerCase();
    if (!hay.includes(S.filter.text)) return false;
  }
  return true;
}

function refreshProductSelect() {
  const sel = $('fproduct');
  const cur = sel.value;
  const prods = [...new Set(S.results.map(r => r.product))].sort();
  sel.innerHTML = '<option value="ALL">ALL PRODUCTS</option>' +
    prods.map(p => `<option value="${esc(p)}">${esc(p)}</option>`).join('');
  sel.value = prods.includes(cur) ? cur : 'ALL';
}

// ---------- rendering ----------
function flagHtml(d) {
  return (d.flags || []).map(f => `<span class="flag">&#9888; ${esc(f)}</span>`).join('');
}
function invHtml(d) {
  if (d.models_served && d.models_served.length)
    return (d.model ? `<b>${esc(d.model)}</b><br>` : '') +
      `<span style="color:var(--phos-dim)">${d.models_served.length} model(s) listed</span>`;
  return esc(d.model || d.error || '\u2014');
}
function asnHtml(d) {
  if (!d.asn) return '<span style="color:#555">&mdash;</span>';
  const col = d.net_type === 'DATACENTER' ? 'var(--amber)'
            : d.net_type === 'RESIDENTIAL' ? 'var(--phos)' : '#555';
  return `<span style="color:${col}">AS${esc(d.asn)}</span><br>` +
    `<span style="color:var(--phos-dim);font-size:10.5px">${esc(d.as_name || '')}</span>`;
}
function sortedResults() {
  const items = S.results.filter(matches);
  if (S.sortKey) {
    const k = S.sortKey, dir = S.sortAsc ? 1 : -1;
    items.sort((a, b) => {
      const va = a[k] ?? '', vb = b[k] ?? '';
      return (typeof va === 'number' && typeof vb === 'number')
        ? (va - vb) * dir
        : String(va).localeCompare(String(vb)) * dir;
    });
  }
  return items;
}
function renderDossiers() {
  syncFlagSet();
  const items = sortedResults();
  const total = items.length;
  const pages = Math.max(1, Math.ceil(total / S.pageSize));
  if (S.page >= pages) S.page = pages - 1;
  if (S.page < 0) S.page = 0;
  const start = S.page * S.pageSize;
  const pageItems = items.slice(start, start + S.pageSize);
  $('fcount').textContent = `${total} match(es) / ${S.results.length} total`;
  $('pg-prev').disabled = S.page <= 0;
  $('pg-next').disabled = S.page >= pages - 1;
  $('pg-info').textContent = total
    ? `page ${S.page + 1}/${pages} — rows ${start + 1}–${Math.min(start + S.pageSize, total)} of ${total}`
    : 'no matches';
  $('capnote').textContent = (total > 0 && total > S.pageSize)
    ? `paginated: showing ${pageItems.length} of ${total} matched dossier(s). use PREV / NEXT to browse.` : '';
  if (S.mode === 'simple') {
    $('cards').innerHTML = pageItems.map(d =>
      `<div class="card"><div class="tgt">${esc(d.target)}</div>` +
      `<div class="muted">${esc(d.product)}${d.version ? ' ' + esc(d.version) : ''}</div>` +
      `<div style="margin:6px 0"><span class="stamp ${d.verdict}">${d.verdict}</span></div>` +
      `<div>${d.model ? esc(d.model) : '<span class="muted">&mdash;</span>'}</div>` +
      (d.asn ? `<div class="muted">AS${esc(d.asn)} ${esc(d.as_name || '')} [${esc(d.net_type || '?')}]</div>` : '') +
      (d.flags && d.flags.length ? `<div class="muted">${d.flags.length} flag(s)</div>` : '') +
      `</div>`).join('');
  } else {
    const tb = $('rows');
    tb.innerHTML = '';
    for (const d of pageItems) tb.appendChild(rowFor(d));
  }
}
function rowFor(d) {
  const tr = document.createElement('tr');
  tr.className = 'd-row';
  tr.innerHTML = `<td>${esc(d.target)}</td><td>${esc(d.product)}</td>` +
    `<td><span class="stamp ${d.verdict}">${d.verdict}</span></td>` +
    `<td>${esc(d.version || '\\u2014')}</td><td>${invHtml(d)}</td>` +
        `<td>${esc(d.ptr || '\\u2014')}</td>` +
        `<td>${asnHtml(d)}</td>` +
    `<td style="color:${d.score >= 40 ? 'var(--red)' : d.score > 0 ? 'var(--amber)' : '#555'}">${d.score || 0}</td>` +
    `<td>${flagHtml(d) || '\u2014'}</td><td>${d.latency_ms ?? '\u2014'}</td>`;
  tr.onclick = () => toggleDetail(tr, d);
  return tr;
}
function detailSnippets(d) {
  // consume only what the engine streams: endpoints = {path:{status,json,raw}}
  // where raw is a trimmed banner body (<=512 chars upstream). fall back to a
  // `snippets` map if a future engine emits it, otherwise 'not captured'.
  if (d.snippets && typeof d.snippets === 'object' && Object.keys(d.snippets).length) {
    return Object.entries(d.snippets).map(([p, sn]) =>
      `<div class="snip">[${esc(p)}] ${esc(String(sn ?? '').slice(0, 300))}</div>`).join('');
  }
  const eps = d.endpoints || {};
  const paths = Object.keys(eps).length ? Object.keys(eps) : PATHS;
  const out = [];
  for (const p of paths) {
    const raw = eps[p] && eps[p].raw;
    if (raw) {
      out.push(`<div class="snip">[${esc(p)}] ${esc(String(raw).trim().slice(0, 300))}</div>`);
    } else if (Object.keys(eps).length) {
      out.push(`<div class="snip" style="color:#888">[${esc(p)}] not captured</div>`);
    }
  }
  return out.join('') || '<span style="color:#888">response snippets not captured.</span>';
}
function toggleDetail(tr, d) {
  const next = tr.nextSibling;
  if (next && next.classList && next.classList.contains('detail')) { next.remove(); return; }
  const det = document.createElement('tr');
  det.className = 'detail';
  const eps = PATHS.map(p => {
    const e = (d.endpoints || {})[p];
    const st = e ? (e.status || (d.error || 'FAIL')) : '?';
    const cls = e && e.status && e.status < 400 ? 'w-ok' : 'w-err';
    return `<span class="ep ${cls}">${p}: ${st}</span>`;
  }).join('');
  let vline = '';
  if (d.verify_result) {
    const vcls = d.verify_result === 'live' ? 'w-ok' : 'w-err';
    vline = `<br><span class="${vcls}">verify: ${esc(d.verify_result)}${d.verify_detail ? ' — ' + esc(d.verify_detail) : ''}</span>`;
  }
  det.innerHTML = `<td colspan="10"><b>ENDPOINT MATRIX</b> &mdash; ${esc(d.target)}<br>${eps}` +
    (d.bgp_prefix ? `<br>BGP PREFIX: ${esc(d.bgp_prefix)} &mdash; AS${esc(d.asn)} ${esc(d.as_name || '')} [${esc(d.net_type || '?')}]` : '') +
    vline +
    `<br><b>RESPONSE SNIPPETS</b><br>${detailSnippets(d)}` +
    (d.error ? `<br><span class="w-err">error: ${esc(d.error)}</span>` : '') + `</td>`;
  tr.parentNode.insertBefore(det, tr.nextSibling);
}

// sorting
document.querySelectorAll('#dtable th[data-k]').forEach(th => {
  th.onclick = () => {
    const k = th.dataset.k;
    if (S.sortKey === k) S.sortAsc = !S.sortAsc;
    else { S.sortKey = k; S.sortAsc = true; }
    S.page = 0;
    renderDossiers();
  };
});

// ---------- progress / stats ----------
function updateProgress() {
  const pct = S.total ? Math.round(S.done / S.total * 100) : 0;
  $('bar-inner').style.width = pct + '%';
  $('bar-text').textContent = `${S.done} / ${S.total} targets — ${S.reqs} requests`;
}
function updateStats() {
  const t = {};
  for (const d of S.results) t[d.verdict] = (t[d.verdict] || 0) + 1;
  const g = k => t[k] || 0;
  $('stats').innerHTML =
    `<span class="stat">PROBED: <b>${S.results.length}</b></span>` +
    `<span class="stat">GENUINE: <b>${g('GENUINE')}</b></span>` +
    `<span class="stat">IMPOSTOR: <b>${g('IMPOSTOR')}</b></span>` +
    `<span class="stat">UNKNOWN: <b>${g('UNKNOWN')}</b></span>` +
    `<span class="stat">DARK: <b>${g('DARK') + g('ERROR')}</b></span>`;
}
function wireLine(ev) {
  const el = $('wire');
  const line = document.createElement('div');
  line.className = ev.status ? (ev.status < 400 ? 'w-ok' : '') : 'w-err';
  line.textContent = `${ev.target}  GET ${ev.path}  ->  ${ev.status || ev.err || 'FAIL'}`;
  el.appendChild(line);
  while (el.children.length > 60) el.removeChild(el.firstChild);
  el.scrollTop = el.scrollHeight;
}
function maybeWire(ev) {
  // on large scans, sample the wire so the DOM survives 100k+ events
  if (S.total > 2000 && S.reqs % Math.ceil(S.total / 2000) !== 0) return;
  wireLine(ev);
}

// ---------- charts ----------
function drawSpark() {
  const c = $('spark'), ctx = c.getContext('2d');
  ctx.clearRect(0, 0, c.width, c.height);
  if (S.rps.length < 2) return;
  const max = Math.max(...S.rps, 1);
  ctx.strokeStyle = '#33ff66'; ctx.lineWidth = 1.5; ctx.beginPath();
  S.rps.forEach((v, i) => {
    const x = i / (S.rps.length - 1) * c.width;
    const y = c.height - 4 - (v / max) * (c.height - 8);
    i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
  });
  ctx.stroke();
  ctx.fillStyle = '#1a9933'; ctx.font = '10px monospace';
  ctx.fillText(`peak ${max}/s`, 6, 12);
}
function drawDonut() {
  const c = $('donut'), ctx = c.getContext('2d');
  ctx.clearRect(0, 0, c.width, c.height);
  const t = {};
  for (const d of S.results) {
    const v = d.verdict === 'ERROR' ? 'DARK' : d.verdict;
    t[v] = (t[v] || 0) + 1;
  }
  const total = S.results.length || 1;
  const cols = {GENUINE: '#33ff66', IMPOSTOR: '#ff3333', UNKNOWN: '#ffb000', DARK: '#2a4a2a'};
  let a = -Math.PI / 2;
  const cx = c.width / 2, cy = c.height / 2, r = 70, ir = 42;
  for (const [k, col] of Object.entries(cols)) {
    const frac = (t[k] || 0) / total;
    if (frac <= 0) continue;
    ctx.beginPath(); ctx.fillStyle = col;
    ctx.arc(cx, cy, r, a, a + frac * 2 * Math.PI);
    ctx.arc(cx, cy, ir, a + frac * 2 * Math.PI, a, true);
    ctx.closePath(); ctx.fill();
    a += frac * 2 * Math.PI;
  }
  ctx.fillStyle = '#33ff66'; ctx.font = '11px monospace'; ctx.textAlign = 'center';
  ctx.fillText(String(S.results.length), cx, cy + 4); ctx.textAlign = 'left';
}
function drawPorts() {
  const c = $('ports'), ctx = c.getContext('2d');
  ctx.clearRect(0, 0, c.width, c.height);
  const hits = {};
  for (const d of S.results) {
    if (d.verdict === 'DARK' || d.verdict === 'ERROR') continue;
    const p = d.target.split(':').pop();
    hits[p] = (hits[p] || 0) + 1;
  }
  const keys = Object.keys(hits).sort();
  if (!keys.length) return;
  const max = Math.max(...Object.values(hits));
  keys.forEach((k, i) => {
    const y = 18 + i * 30;
    ctx.fillStyle = '#1a9933'; ctx.font = '11px monospace';
    ctx.fillText(k, 4, y + 11);
    ctx.fillStyle = '#33ff66';
    ctx.fillRect(60, y, (hits[k] / max) * (c.width - 110), 14);
    ctx.fillText(String(hits[k]), 66 + (hits[k] / max) * (c.width - 110), y + 11);
  });
}
function drawLatency() {
  const c = $('latency'), ctx = c.getContext('2d');
  ctx.clearRect(0, 0, c.width, c.height);
  const buckets = [0, 0, 0, 0, 0];
  const labels = ['<200', '200-500', '500-1k', '1k-3k', '>3k'];
  for (const d of S.results) {
    const ms = d.latency_ms;
    if (ms == null) continue;
    buckets[ms < 200 ? 0 : ms < 500 ? 1 : ms < 1000 ? 2 : ms < 3000 ? 3 : 4]++;
  }
  const max = Math.max(...buckets, 1);
  buckets.forEach((v, i) => {
    const x = 10 + i * 58;
    const h = (v / max) * 130;
    ctx.fillStyle = '#33ff66'; ctx.fillRect(x, 150 - h, 44, h);
    ctx.fillStyle = '#1a9933'; ctx.font = '10px monospace';
    ctx.fillText(labels[i], x, 164);
    ctx.fillText(String(v), x, 146 - h);
  });
}
function drawCharts() { drawSpark(); drawDonut(); drawPorts(); drawLatency(); }

function tick() {
  const el = (Date.now() - S.t0) / 1000;
  const eta = S.done ? Math.round(el / S.done * (S.total - S.done)) : 0;
  const rate = (S.reqs - S.lastReqs) * 2;
  S.lastReqs = S.reqs;
  S.rps.push(rate); if (S.rps.length > 200) S.rps.shift();
  $('bar-text').textContent =
    `${S.done} / ${S.total} targets — ${S.reqs} requests — ${Math.round(el)}s elapsed` +
    (S.done && S.done < S.total ? ` — ETA ${eta}s` : '');
  drawSpark();
  if (S.chartsDirty) { drawDonut(); drawPorts(); drawLatency(); updateIntel(); S.chartsDirty = false; }
  if (S.rowsDirty) { renderDossiers(); S.rowsDirty = false; }

  // Periodic signal feed update so console never sits silent
  const now = Date.now();
  if (!S.lastLogTime) S.lastLogTime = now;
  if (now - S.lastLogTime >= 3000) {
    S.lastLogTime = now;
    if (S.total > 0) {
      let genuine = 0, impostor = 0;
      for (const d of S.results) {
        if (d.verdict === 'GENUINE') genuine++;
        else if (d.verdict === 'IMPOSTOR') impostor++;
      }
      const dark = S.results.length - genuine - impostor;
      const pct = Math.round(S.done / S.total * 100);
      log(`FEED UPDATE: ${S.done.toLocaleString()} / ${S.total.toLocaleString()} targets (${pct}%) — ${rate} req/s — hits: ${genuine} genuine, ${impostor} impostor | dark/unknown: ${dark.toLocaleString()}`);
    } else {
      log(`AWAITING TARGETING PACKAGE... (${Math.round(el)}s elapsed, ${S.reqs} requests queued)`);
    }
  }
}

// ---------- scan control ----------
function setScanUI(scanning) {
  $('go').disabled = scanning;
  $('abort').style.display = scanning ? 'inline-block' : 'none';
}

$('go').onclick = async () => {
  const lines = $('targets').value.split('\n');
  S.results = []; S.total = 0; S.done = 0; S.reqs = 0; S.rps = []; S.lastReqs = 0;
  S.byTarget = {}; S.rowsDirty = false; S.lastLogTime = Date.now();
  S.page = 0; S._flagSig = '';
  $('rows').innerHTML = ''; $('cards').innerHTML = ''; $('wire').innerHTML = '';
  updateProgress(); updateStats(); renderDossiers(); drawCharts();
  setScanUI(true);
  S.t0 = Date.now();
  S.timer = setInterval(tick, 500);
  S.scanId = crypto.randomUUID();
  S.ctrl = new AbortController();
  log('scan initiated. opening signal feed...');
  try {
    const r = await fetch('/api/scan', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      signal: S.ctrl.signal,
      body: JSON.stringify({
        targets: lines, scan_id: S.scanId,
        workers: Math.min(5000, Math.max(1, +$('opt-workers').value || 1000)),
        timeout: Math.min(10, Math.max(0.5, +$('opt-timeout').value || 3)),
        frameworks: selectedFrameworks(),
        excludes: $('excludes').value.split('\n'),
        enrich: $('opt-enrich').checked,
        fast: $('opt-fast').checked,
        exclude_dod: $('opt-exclude-dod').checked,
        lean_ports: $('opt-lean-ports').checked,
        fanout: $('opt-fanout').checked,
        dedup: $('opt-dedup').checked,
        asn_prefilter: $('opt-asn-prefilter').checked,
        progressive: $('opt-progressive').checked,
        banner_prefilter: $('opt-banner').checked,
        adaptive_timeout: $('opt-adaptive').checked,
        content_dedup: $('opt-contentdedup').checked,
        diff_mode: $('opt-diff').checked,
        ptr_seed: $('opt-ptr').checked,
        ct_search_seed: $('opt-ct').checked,
        shodan_seed: $('opt-shodan').checked,
        sweep_all_ports: $('opt-sweep-all-ports').checked
      })
    });
    const reader = r.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    while (true) {
      const {value, done} = await reader.read();
      if (done) break;
      buf += dec.decode(value, {stream: true});
      let idx;
      while ((idx = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (!line) continue;
        const ev = JSON.parse(line);
        if (ev.type === 'log') {
          log(ev.message, ev.cls || 'warn');
        } else if (ev.type === 'start') {
          S.total = ev.total; updateProgress();
          log(`targeting package expanded: ${ev.total} target(s) — frameworks [${ev.frameworks}] ports [${ev.ports}] — engine ${ev.engine}/${ev.profile} @ ${ev.workers} workers${ev.fd_capped ? ' (FD-capped: raise ulimit -n for more)' : ''}.`);
          if (ev.dedup_skipped > 0) log(`DEDUP: skipped ${ev.dedup_skipped} recently scanned target(s).`);
          if (ev.prefiltered > 0) log(`ASN PREFILTER: dropped ${ev.prefiltered} residential target(s) before probing.`);
          if (ev.blocklisted > 0) log(`BLOCKLIST: ${ev.blocklisted} confirmed honeypot(s) excluded.`);
          if (ev.seeded > 0) log(`SEED: pulled ${ev.seeded} pre-curated host(s) from CT/Shodan.`);
          if (ev.progressive_dropped > 0) log(`PROGRESSIVE: TCP pre-sweep dropped ${ev.progressive_dropped} dead host(s) before deep-probe.`);
          if (ev.truncated) log('WARNING: target list hit the 500,000 cap and was TRUNCATED.', 'warn');
        } else if (ev.type === 'probes') {
          for (const p of ev.items) { S.reqs++; maybeWire(p); }
          updateProgress();
        } else if (ev.type === 'enrich') {
          const d = S.byTarget[ev.target];
          if (d) {
            d.asn = ev.asn; d.as_name = ev.as_name;
            d.bgp_prefix = ev.bgp_prefix; d.net_type = ev.net_type;
            S.rowsDirty = true; S.chartsDirty = true;
          }
        } else if (ev.type === 'ptr') {
          const d = S.byTarget[ev.target];
          if (d) { d.ptr = ev.ptr; S.rowsDirty = true; }
        } else if (ev.type === 'result') {
          S.done++; S.results.push(ev.data);
          S.byTarget[ev.data.target] = ev.data;
          updateStats(); updateProgress(); S.chartsDirty = true;
          if (ev.data.verdict === 'IMPOSTOR')
            log(`${ev.data.target}: IMPOSTOR - ${ev.data.flags.join('; ')}`, 'bad');
          else if (ev.data.verdict === 'GENUINE')
            log(`${ev.data.target}: genuine ${ev.data.product}${ev.data.version ? ' ' + ev.data.version : ''}`);
        } else if (ev.type === 'done') {
          log(`collection complete. ${S.results.length} dossier(s) filed in ${ev.elapsed_s}s (${ev.requests} requests, ${ev.hosts_per_s} hosts/s).`);
        } else if (ev.type === 'stopped') {
          log(`SCAN ABORTED BY OPERATOR. ${ev.done} dossier(s) filed before abort.`, 'warn');
        }
      }
    }
    refreshProductSelect(); renderDossiers(); drawCharts(); updateIntel();
    $('export').style.display = 'inline-block';
    $('exportcsv').style.display = 'inline-block';
    $('retarget').style.display = 'inline-block';
    refreshHistory();
  } catch (e) {
    if (e.name === 'AbortError') log('signal feed closed by operator.', 'warn');
    else log('SCAN FAILURE: ' + e, 'bad');
  }
  clearInterval(S.timer);
  setScanUI(false);
};

$('abort').onclick = async () => {
  try {
    await fetch('/api/stop', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({scan_id: S.scanId})
    });
  } catch (e) {}
  if (S.ctrl) S.ctrl.abort();
  log('abort order transmitted.', 'warn');
};

// ---------- export ----------
$('export').onclick = () => {
  const blob = new Blob([S.results.map(r => JSON.stringify(r)).join('\n') + '\n'],
    {type: 'application/x-ndjson'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'silicon_recon_' + new Date().toISOString().replace(/[:.]/g, '-') + '.jsonl';
  a.click();
  log('dossiers exported to JSONL.', 'warn');
};
$('exportcsv').onclick = () => {
  const q = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';
  const rows = [['target','product','verdict','version','model','asn','as_name','net_type','bgp_prefix','score','inventory_hash','flags','latency_ms'].join(',')];
  for (const d of S.results)
    rows.push([d.target, d.product, d.verdict, d.version, d.model,
               d.asn, d.as_name, d.net_type, d.bgp_prefix, d.score, d.inventory_hash,
               (d.flags||[]).join(' | '), d.latency_ms].map(q).join(','));
  const blob = new Blob([rows.join('\n') + '\n'], {type: 'text/csv'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'silicon_recon_' + new Date().toISOString().replace(/[:.]/g, '-') + '.csv';
  a.click();
  log('dossiers exported to CSV.', 'warn');
};

// ---------- retarget live responders ----------
// Take every non-DARK result from the last scan and load it back into the
// target list as an explicit host:port, so a fast sweep can feed a deeper
// follow-up scan on just the hosts that answered.
$('retarget').onclick = () => {
  const live = S.results.filter(d => d.verdict && d.verdict !== 'DARK');
  if (!live.length) { log('RETARGET: no live responders to reload (all DARK).', 'warn'); return; }
  const lines = [...new Set(live.map(d => d.target))].sort();
  const ta = $('targets');
  const existing = ta.value.trim();
  ta.value = existing ? existing + '\n' + lines.join('\n') : lines.join('\n');
  const tally = {};
  for (const d of live) tally[d.verdict] = (tally[d.verdict] || 0) + 1;
  const summary = Object.entries(tally).map(([v, n]) => `${n} ${v}`).join(', ');
  log(`RETARGET: ${lines.length} live host(s) loaded into target list (${summary}). switch profile and re-scan for deep probe.`, 'warn');
};

// ---------- history ----------
async function refreshHistory() {
  try {
    const r = await fetch('/api/history');
    const d = await r.json();
    $('hist').innerHTML = d.scans.map(s =>
      `<option value="${esc(s.id)}">${esc(s.when)} — ${s.total} dossiers (${s.impostor} impostor, ${s.genuine} genuine)</option>`
    ).join('') || '<option value="">(empty)</option>';
  } catch (e) {}
}
$('hist-refresh').onclick = refreshHistory;
$('hist-load').onclick = async () => {
  const id = $('hist').value;
  if (!id) return;
  const r = await fetch('/api/history?id=' + encodeURIComponent(id));
  const d = await r.json();
  S.results = d.results || [];
  S.total = S.done = S.results.length;
  S.page = 0; S._flagSig = '';
  S.byTarget = {};
  for (const r of S.results) S.byTarget[r.target] = r;
  updateProgress(); updateStats(); refreshProductSelect(); renderDossiers(); drawCharts(); updateIntel();
  $('export').style.display = 'inline-block';
  $('exportcsv').style.display = 'inline-block';
  $('retarget').style.display = 'inline-block';
  log(`archive loaded: ${S.results.length} dossier(s) from ${id}.`);
};
refreshHistory();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 - silence request logging
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            page = PAGE.replace("__PACKS_JSON__", json.dumps(PACKS))
            self._send(200, page, "text/html; charset=utf-8")
        elif self.path == "/api/history":
            scans = []
            for h in HISTORY:
                tally = {}
                for r in h["results"]:
                    tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1
                scans.append({
                    "id": h["id"], "when": h["when"], "total": len(h["results"]),
                    "genuine": tally.get("GENUINE", 0),
                    "impostor": tally.get("IMPOSTOR", 0),
                })
            self._send(200, json.dumps({"scans": scans}))
        elif self.path.startswith("/api/asn-prefixes"):
            try:
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                asn = qs.get("asn", [""])[0].strip().upper().removeprefix("AS")
                if not asn.isdigit():
                    return self._send(400, '{"error":"invalid ASN"}')
                limit = min(5000, max(1, int(qs.get("limit", ["5000"])[0])))
                name, prefixes, total = bgpview_prefixes(asn, limit)
                self._send(200, json.dumps({
                    "asn": asn, "name": name, "prefixes": prefixes,
                    "total": total, "truncated": total > limit,
                }))
            except Exception as e:
                self._send(502, json.dumps({"error": f"RIPEstat fetch failed: {e}"}))
        elif self.path.startswith("/api/country-cidrs"):
            try:
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                cc = (qs.get("cc", ["US"])[0] or "US")[:2]
                limit = min(5000, max(1, int(qs.get("limit", ["256"])[0])))
                cidrs, total = country_cidrs(cc, limit)
                self._send(200, json.dumps({
                    "cc": cc.upper(), "cidrs": cidrs, "total_ranges": total,
                    "truncated": total > limit,
                }))
            except Exception as e:
                self._send(502, json.dumps({"error": f"RIR fetch failed: {e}"}))
        elif self.path.startswith("/api/history?id="):
            sid = self.path.split("id=", 1)[1]
            for h in HISTORY:
                if h["id"] == sid:
                    return self._send(200, json.dumps({"results": h["results"]}))
            self._send(404, '{"error":"scan not found"}')
        else:
            self._send(404, '{"error":"not found"}')

    def do_POST(self):
        if self.path == "/api/stop":
            try:
                n = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(n) or b"{}")
                ev = SCANS.get(str(payload.get("scan_id", "")))
                if ev:
                    ev.set()
                self._send(200, '{"ok":true}')
            except Exception as e:
                self._send(400, json.dumps({"error": str(e)}))
            return
        if self.path != "/api/scan":
            return self._send(404, '{"error":"not found"}')
        try:
            n = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(n) or b"{}")
            lines = payload.get("targets", [])
            if not isinstance(lines, list):
                raise ValueError("targets must be a list")
            lines = [str(x) for x in lines]
            scan_id = str(payload.get("scan_id", ""))[:64] or f"scan-{int(time.time())}"
            workers = min(5000, max(1, int(payload.get("workers", 1000))))
            timeout = min(10.0, max(0.5, float(payload.get("timeout", PROBE_TIMEOUT))))
            frameworks = payload.get("frameworks")
            if not isinstance(frameworks, list):
                frameworks = None
            excludes = payload.get("excludes")
            if not isinstance(excludes, list):
                excludes = None
            enrich = bool(payload.get("enrich", True))
            fast = bool(payload.get("fast", True))
            lean_ports = bool(payload.get("lean_ports", False))
            exclude_dod = bool(payload.get("exclude_dod", True))
            dedup = bool(payload.get("dedup", False))
            asn_prefilter = bool(payload.get("asn_prefilter", False))
            fanout = bool(payload.get("fanout", False))
            progressive = bool(payload.get("progressive", False))
            banner_prefilter = bool(payload.get("banner_prefilter", False))
            adaptive_timeout = bool(payload.get("adaptive_timeout", False))
            content_dedup = bool(payload.get("content_dedup", False))
            diff_mode = bool(payload.get("diff_mode", False))
            ptr_seed = bool(payload.get("ptr_seed", False))
            ct_search_seed = bool(payload.get("ct_search_seed", False))
            shodan_seed = bool(payload.get("shodan_seed", False))
            sweep_all_ports = bool(payload.get("sweep_all_ports", False))
        except Exception as e:
            return self._send(400, json.dumps({"error": str(e)}))

        cancel = threading.Event()
        SCANS[scan_id] = cancel
        results = []
        # stream NDJSON events; connection-close delimits the body
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        try:
            probe_buf = []
            last_flush = time.time()
            for ev in scan_events(lines, workers, timeout, cancel,
                                  frameworks, excludes, enrich, fast,
                                  lean_ports=lean_ports, exclude_dod=exclude_dod,
                                  dedup=dedup, asn_prefilter=asn_prefilter,
                                  fanout=fanout, progressive=progressive,
                                  banner_prefilter=banner_prefilter,
                                  adaptive_timeout=adaptive_timeout,
                                  content_dedup=content_dedup,
                                  diff_mode=diff_mode, ptr_seed=ptr_seed,
                                  ct_search_seed=ct_search_seed,
                                  shodan_seed=shodan_seed,
                                  sweep_all_ports=sweep_all_ports):
                if ev["type"] == "probe":
                    # batch probe events: one JSON line per ~50 or per 200ms
                    probe_buf.append(ev)
                    if len(probe_buf) < 50 and time.time() - last_flush < 0.2:
                        continue
                    ev = {"type": "probes", "items": probe_buf}
                    probe_buf = []
                    last_flush = time.time()
                elif probe_buf:
                    self.wfile.write((json.dumps(
                        {"type": "probes", "items": probe_buf}) + "\n").encode())
                    probe_buf = []
                    last_flush = time.time()
                if ev["type"] == "result":
                    results.append(ev["data"])
                elif ev["type"] == "enrich":
                    for r in results:
                        if r["target"] == ev["target"]:
                            r["asn"] = ev["asn"]
                            r["as_name"] = ev["as_name"]
                            r["bgp_prefix"] = ev["bgp_prefix"]
                            r["net_type"] = ev["net_type"]
                            break
                self.wfile.write((json.dumps(ev) + "\n").encode())
                self.wfile.flush()
            if probe_buf:
                self.wfile.write((json.dumps(
                    {"type": "probes", "items": probe_buf}) + "\n").encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            cancel.set()
        finally:
            SCANS.pop(scan_id, None)
            if results:
                HISTORY.appendleft({
                    "id": scan_id,
                    "when": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
                    "results": results,
                })
