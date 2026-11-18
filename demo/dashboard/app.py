"""
dashboard/app.py — живой дашборд для демонстрации проекта.

Показывает два потока данных рядом:
  1. "Кто заходил на сайт" — прикладной лог demo/logs/target_requests.log
     (пишет target_server/app.py на каждый HTTP-запрос).
  2. "Вердикты сетевого IDS" — лог ids-project/ids_events.log, который теперь
     пишет live_capture_engine.py в формате JSONL: КАЖДЫЙ сетевой поток
     (не только атаки), с протоколом/портами/счётчиками и вердиктом модели.
     Старый текстовый формат (predict_once.py / live_ids_watcher.py,
     построчно "[время] сообщение") тоже поддержан для совместимости.

Плюс статус живого движка (ids-project/live_engine.status) — работает ли
сейчас захват трафика, с какого момента, сколько потоков/атак обработано.

Страница каждые 1.5 сек опрашивает /api/* и перерисовывает таблицы —
никакого WebSocket, просто чтобы было просто и надёжно для демо.
"""

import json
import os
import re

from flask import Flask, jsonify

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REQUESTS_LOG = os.path.join(BASE_DIR, "..", "logs", "target_requests.log")
IDS_DIR = os.path.join(BASE_DIR, "..", "..", "ids-project")
IDS_LOG = os.path.join(IDS_DIR, "ids_events.log")
ENGINE_STATUS_FILE = os.path.join(IDS_DIR, "live_engine.status")

app = Flask(__name__)

PAGE = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Digital Detective — дашборд</title>
<style>

<div class="grid">
  <div class="panel">
    <div class="panel-head">
      <h2>Лог веб-сервера (прикладной уровень)</h2>
      <span class="count" id="reqCount">0</span>
    </div>
    <div class="table-scroll">
      <table id="reqTable"><thead><tr><th>Время</th><th>IP</th><th>Метод</th><th>Путь</th><th>Тег</th></tr></thead><tbody></tbody></table>
    </div>
    <div id="reqEmpty" class="empty" style="display:none">Пока нет запросов — открой мок-сайт: <code>http://127.0.0.1:5000</code></div>
  </div>
  <div class="panel">
    <div class="panel-head">
      <h2>Сетевой IDS — вердикты по потокам</h2>
      <span class="count" id="idsCount">0</span>
    </div>
    <div class="table-scroll">
      <table id="idsTable"><thead><tr>
        <th>Время</th><th>Proto</th><th>Источник</th><th>Назначение</th>
        <th>Пак.</th><th>Байт</th><th>Длит., мс</th><th>Вердикт</th>
      </tr></thead><tbody></tbody></table>
    </div>
    <div id="idsEmpty" class="empty" style="display:none">Пока нет событий — запусти <code>live_capture_engine.py</code> (см. README).</div>
  </div>
</div>
<div class="grid grid-wide" style="margin-top:20px">
  <div class="panel">
    <h2>Атаки по времени (последние 24 часа)</h2>
    <canvas id="attackChart" width="900" height="220" style="width:100%;height:220px"></canvas>
  </div>
</div>

<footer>Источники: <code>demo/logs/target_requests.log</code> · <code>ids-project/ids_events.log</code> · <code>ids-project/live_engine.status</code></footer>

<script>
    }
    idsBody.appendChild(tr);
  }
}

async function refreshAlerts() {
  const alerts = await (await fetch('/api/rule_alerts')).json();
  const body = document.querySelector('#alertsTable tbody');
  body.innerHTML = '';
  document.querySelector('#alertsEmpty').style.display = alerts.length ? 'none' : 'block';
  document.querySelector('#alertsCount').textContent = alerts.length;
  for (const a of alerts.slice().reverse()) {
    const tr = document.createElement('tr');
    tr.className = 'row-attack';
    tr.innerHTML = `<td class="mono">${esc(a.ts)}</td><td class="ip">${esc(a.src_ip)}</td>` +
      `<td class="ip">${esc(a.dst_ip)}</td><td>${verdictBadge(a.verdict)}</td>`;
    body.appendChild(tr);
  }
}

async function refreshStatus() {
  const dot = document.querySelector('#statusDot');
  const text = document.querySelector('#statusText');
  try {
    }
    document.querySelector('#statFlows').textContent = s.flows_total ?? 0;
    document.querySelector('#statAttacks').textContent = s.attacks_total ?? 0;
  } catch (e) {
    dot.className = 'dot off';
    text.textContent = 'нет связи с движком';
  }
}

async function refresh() {
  document.querySelector('#statReq').textContent =
    document.querySelector('#reqCount').textContent || '0';
  await Promise.allSettled([refreshRequests(), refreshIds(), refreshAlerts(), refreshStatus()]);
  document.querySelector('#statReq').textContent = document.querySelector('#reqCount').textContent;
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


_LEGACY_LINE_RE = re.compile(r"^\[(.*?)\]\s*(.*)$")


def _tail_ids_events(path: str, limit: int = 300):
    """Читает ids_events.log: новый формат (JSONL от live_capture_engine.py)
    и старый текстовый ("[время] сообщение" от live_ids_watcher.py/predict_once.py)
    в одном списке, новый — как структурированный dict, старый — как {"raw": ...}."""
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
            continue
        except json.JSONDecodeError:
            pass
        m = _LEGACY_LINE_RE.match(line)
        if m:
            rows.append({"ts": m.group(1), "raw": m.group(2)})
        else:
            rows.append({"ts": "", "raw": line})
    return rows


def _engine_status():
    if not os.path.exists(ENGINE_STATUS_FILE):
        return {"known": False, "running": False}
    try:
        with open(ENGINE_STATUS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["known"] = True
        return data
    except (json.JSONDecodeError, OSError):
        return {"known": False, "running": False}


@app.route("/")
def index():
    return PAGE


@app.route("/api/requests")
def api_requests():
    return jsonify(_tail_jsonl(REQUESTS_LOG))


@app.route("/api/ids_events")
def api_ids_events():
    return jsonify(_tail_ids_events(IDS_LOG))


@app.route("/api/rule_alerts")
def api_rule_alerts():
    events = _tail_ids_events(IDS_LOG, limit=2000)
    alerts = [e for e in events if e.get("type") == "alert"]
    return jsonify(alerts[-100:])


@app.route("/api/engine_status")
def api_engine_status():
    return jsonify(_engine_status())


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
    app.run(host="0.0.0.0", port=5050, debug=False)
