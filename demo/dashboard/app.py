"""
dashboard/app.py — живой дашборд для демонстрации проекта.

Показывает два потока данных рядом:
  1. "Кто заходил на сайт" — прикладной лог demo/logs/target_requests.log
     (пишет target_server/app.py на каждый HTTP-запрос).
  2. "Вердикты сетевого IDS" — лог ids-project/ids_events.log
     (пишет live_ids_watcher.py / predict_once.py по результатам анализа
     сетевых потоков через CICFlowMeter + ML-модель).

Страница каждые 1.5 сек опрашивает /api/* и перерисовывает таблицы —
никакого WebSocket, просто чтобы было просто и надёжно для демо.
"""

import json
import os
import re

from flask import Flask, jsonify

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REQUESTS_LOG = os.path.join(BASE_DIR, "..", "logs", "target_requests.log")
IDS_LOG = os.path.join(BASE_DIR, "..", "..", "ids-project", "ids_events.log")

app = Flask(__name__)

PAGE = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Digital Detective — дашборд</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 0; padding: 20px; background: #0b0f14; color: #e6e6e6; }
  h1 { font-size: 20px; margin-bottom: 4px; }
  .muted { color: #8a93a0; font-size: 13px; margin-bottom: 20px; }
  .cards { display: grid; grid-template-columns: repeat(4, minmax(120px, 1fr)); gap: 12px; margin-bottom: 16px; }
  .card { background: #121826; border: 1px solid #22304a; border-radius: 10px; padding: 12px 14px; }
  .card .label { color: #8a93a0; font-size: 12px; }
  .card .value { font-size: 24px; font-weight: 700; margin-top: 4px; }
  .controls { display: flex; gap: 8px; align-items: center; margin-bottom: 12px; }
  .controls input, .controls select, .controls button { padding: 7px 9px; border: 1px solid #22304a; border-radius: 6px; background: #121826; color: #e6e6e6; }
  .controls button { cursor: pointer; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  .grid-wide { grid-template-columns: 1fr; }
  .panel { background: #121826; border: 1px solid #22304a; border-radius: 10px; padding: 14px; }
  .panel h2 { font-size: 15px; margin: 0 0 10px; color: #9fb4d9; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th, td { text-align: left; padding: 4px 6px; border-bottom: 1px solid #1d2636; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 220px; }
  tr.attack { background: #2a1217; color: #ff8a8a; }
  tr.flood { background: #2a2312; color: #ffd37a; }
  .empty { color: #555; font-style: italic; }
  .dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px; }
  .dot.live { background:#2ecc71; box-shadow: 0 0 6px #2ecc71; }
</style>
</head>
<body>
<h1><span class="dot live"></span>Digital Detective — живой дашборд</h1>
<p class="muted">Обновляется каждые 1.5 сек. Слева — кто и как заходил на мок-сайт (HTTP). Справа — вердикты сетевого IDS по потокам трафика (CICFlowMeter + ML).</p>
<div class="cards">
  <div class="card"><div class="label">Всего потоков / verdicts</div><div class="value" id="totalEvents">0</div></div>
  <div class="card"><div class="label">Атаки</div><div class="value" id="attackEvents">0</div></div>
  <div class="card"><div class="label">BENIGN</div><div class="value" id="benignEvents">0</div></div>
  <div class="card"><div class="label">Заблокировано IP</div><div class="value" id="blockedIps">0</div></div>
</div>
<div class="controls">
  <input id="eventFilter" type="search" placeholder="Фильтр по IP, типу или тексту">
  <select id="eventType"><option value="">Все события</option><option value="attack">Атаки</option><option value="benign">BENIGN</option><option value="blocked">Блокировки</option></select>
  <button id="exportCsv" type="button">Экспорт CSV</button>
</div>
<div class="grid">
  <div class="panel">
    <h2>🌐 Лог веб-сервера (прикладной уровень)</h2>
    <table id="reqTable"><thead><tr><th>Время</th><th>IP</th><th>Метод</th><th>Путь</th><th>Тег</th></tr></thead><tbody></tbody></table>
    <div id="reqEmpty" class="empty" style="display:none">Пока нет запросов — открой мок-сайт.</div>
  </div>
  <div class="panel">
    <h2>🛰️ Сетевой IDS (CICFlowMeter + ML)</h2>
    <table id="idsTable"><thead><tr><th>Время</th><th>Событие</th></tr></thead><tbody></tbody></table>
    <div id="idsEmpty" class="empty" style="display:none">Пока нет событий — запусти capture_and_test.sh.</div>
  </div>
</div>
<div class="grid grid-wide" style="margin-top:20px">
  <div class="panel">
    <h2>Атаки по времени (последние 24 часа)</h2>
    <canvas id="attackChart" width="900" height="220" style="width:100%;height:220px"></canvas>
  </div>
</div>

<script>
let currentEvents = [];

function addCell(tr, value) {
  const td = document.createElement('td');
  td.textContent = value ?? '';
  tr.appendChild(td);
}

function eventType(line) {
  if (line.includes('АТАКА')) return 'attack';
  if (line.includes('ЗАБЛОКИРОВАН')) return 'blocked';
  if (line.includes('BENIGN')) return 'benign';
  return 'other';
}

function drawChart(events) {
  const canvas = document.querySelector('#attackChart');
  const ctx = canvas.getContext('2d');
  const width = canvas.width;
  const height = canvas.height;
  ctx.clearRect(0, 0, width, height);

  const bins = Array(24).fill(0);
  const now = new Date();
  for (const line of events) {
    if (!line.includes('АТАКА')) continue;
    const match = line.match(/^\\[(.*?)\\]/);
    if (!match) continue;
    const date = new Date(match[1]);
    if (Number.isNaN(date.getTime())) continue;
    const hoursAgo = Math.floor((now - date) / 3600000);
    if (hoursAgo >= 0 && hoursAgo < 24) bins[23 - hoursAgo]++;
  }

  ctx.strokeStyle = '#22304a';
  ctx.fillStyle = '#ff8a8a';
  ctx.font = '11px system-ui';
  const max = Math.max(1, ...bins);
  for (let i = 0; i < 24; i++) {
    const barWidth = width / 24 - 5;
    const barHeight = bins[i] / max * (height - 30);
    const x = i * (width / 24) + 2;
    const y = height - barHeight - 20;
    ctx.fillRect(x, y, barWidth, barHeight);
    if (i % 3 === 0) ctx.fillText(String(i), x, height - 5);
  }
}

async function refresh() {
  try {
    const reqs = await (await fetch('/api/requests')).json();
    const reqBody = document.querySelector('#reqTable tbody');
    reqBody.innerHTML = '';
    document.querySelector('#reqEmpty').style.display = reqs.length ? 'none' : 'block';
    for (const r of reqs.slice().reverse()) {
      const tr = document.createElement('tr');
      if (r.tag === 'flood_triggered') tr.className = 'flood';
      addCell(tr, r.ts); addCell(tr, r.ip); addCell(tr, r.method); addCell(tr, r.path); addCell(tr, r.tag);
      reqBody.appendChild(tr);
    }
  } catch (e) {}

  try {
    const events = await (await fetch('/api/ids_events')).json();
    const summary = await (await fetch('/api/summary')).json();
    currentEvents = events;
    document.querySelector('#totalEvents').textContent = summary.total;
    document.querySelector('#attackEvents').textContent = summary.attacks;
    document.querySelector('#benignEvents').textContent = summary.benign;
    document.querySelector('#blockedIps').textContent = summary.blocked_ips;
    drawChart(events);

    const textFilter = document.querySelector('#eventFilter').value.toLowerCase();
    const typeFilter = document.querySelector('#eventType').value;
    const idsBody = document.querySelector('#idsTable tbody');
    idsBody.innerHTML = '';
    let visible = events.filter(line =>
      (!typeFilter || eventType(line) === typeFilter) &&
      (!textFilter || line.toLowerCase().includes(textFilter))
    );
    document.querySelector('#idsEmpty').style.display = visible.length ? 'none' : 'block';
    for (const line of visible.slice().reverse()) {
      const tr = document.createElement('tr');
      if (eventType(line) === 'attack' || eventType(line) === 'blocked') tr.className = 'attack';
      const m = line.match(/^\\[(.*?)\\]\\s*(.*)$/);
      addCell(tr, m ? m[1] : '');
      addCell(tr, m ? m[2] : line);
      idsBody.appendChild(tr);
    }
  } catch (e) {}
}

function exportCsv() {
  const lines = [['time', 'event'], ...currentEvents.map(line => {
    const m = line.match(/^\\[(.*?)\\]\\s*(.*)$/);
    return [m ? m[1] : '', m ? m[2] : line];
  })];
  const csv = lines.map(row => row.map(value => {
    const text = String(value ?? '').replace(/"/g, '""');
    return `"${text}"`;
  }).join(',')).join('\\n');
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([csv], {type: 'text/csv;charset=utf-8'}));
  link.download = 'ids_events.csv';
  link.click();
  URL.revokeObjectURL(link.href);
}

document.querySelector('#eventFilter').addEventListener('input', refresh);
document.querySelector('#eventType').addEventListener('change', refresh);
document.querySelector('#exportCsv').addEventListener('click', exportCsv);
refresh();
setInterval(refresh, 1500);
</script>
</body>
</html>
"""


def _tail_jsonl(path: str, limit: int = 200):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()[-limit:]
    rows = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _tail_lines(path: str, limit: int = 200):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()[-limit:]
    return [l.rstrip("\n") for l in lines if l.strip()]


@app.route("/")
def index():
    return PAGE


@app.route("/api/requests")
def api_requests():
    return jsonify(_tail_jsonl(REQUESTS_LOG))


@app.route("/api/ids_events")
def api_ids_events():
    return jsonify(_tail_lines(IDS_LOG))


@app.route("/api/summary")
def api_summary():
    events = _tail_lines(IDS_LOG, limit=5000)
    verdict_lines = [
        line for line in events
        if "АТАКА:" in line or "BENIGN" in line
    ]
    attacks = sum("АТАКА:" in line for line in verdict_lines)
    benign = sum("BENIGN" in line for line in verdict_lines)

    blocked_ips = set()
    for line in events:
        match = re.search(r"ЗАБЛОКИРОВАН\s+([0-9A-Fa-f:.]+)", line)
        if match:
            blocked_ips.add(match.group(1))

    return jsonify({
        "total": len(verdict_lines),
        "attacks": attacks,
        "benign": benign,
        "blocked_ips": len(blocked_ips),
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=False)
