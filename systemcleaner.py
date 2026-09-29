import os
import tempfile
import time
import socket
import threading
from datetime import datetime
from flask import Flask, render_template_string, jsonify, request
import psutil

app = Flask(__name__)

# --- ANLIK SİSTEM İZLEME MOTORU (BACKGROUND THREAD) ---
GLOBAL_CPU_PERCENT = 0.0
LAST_NET_IO = psutil.net_io_counters()
LAST_NET_TIME = time.time()

GLOBAL_UP_SPEED = "0 KB/s"
GLOBAL_DOWN_SPEED = "0 KB/s"
GLOBAL_RAW_DOWN_KB = 0.0

ACTION_LOGS = []
PROC_NET_STATS = {}
PREV_PROC_IO = {}
CUSTOM_WHITELIST = set()

def system_monitor_thread():
    """Arka planda CPU ve Network verilerini anlık hesaplayan izleyici"""
    global GLOBAL_CPU_PERCENT, LAST_NET_IO, LAST_NET_TIME
    global GLOBAL_UP_SPEED, GLOBAL_DOWN_SPEED, GLOBAL_RAW_DOWN_KB

    # CPU ölçümünü ısıtma çağrısı
    psutil.cpu_percent(interval=None)

    while True:
        time.sleep(1.0)
        
        # 1. Anlık Gerçek CPU Hesaplama
        GLOBAL_CPU_PERCENT = psutil.cpu_percent(interval=None)

        # 2. Anlık Gerçek Network Hızı Hesaplama
        now = time.time()
        elapsed = now - LAST_NET_TIME
        if elapsed <= 0: elapsed = 1.0

        current_net_io = psutil.net_io_counters()
        bytes_sent = current_net_io.bytes_sent - LAST_NET_IO.bytes_sent
        bytes_recv = current_net_io.bytes_recv - LAST_NET_IO.bytes_recv

        LAST_NET_IO = current_net_io
        LAST_NET_TIME = now

        GLOBAL_UP_SPEED = format_speed(bytes_sent / elapsed)
        GLOBAL_DOWN_SPEED = format_speed(bytes_recv / elapsed)
        GLOBAL_RAW_DOWN_KB = round(bytes_recv / elapsed / 1024, 1)

# Arka plan izleyici thread'i başlat
threading.Thread(target=system_monitor_thread, daemon=True).start()

CRITICAL_SAFE_LIST = {
    'explorer.exe', 'msmpeng.exe', 'svchost.exe', 'csrss.exe', 
    'wininit.exe', 'smss.exe', 'services.exe', 'lsass.exe', 
    'spoolsv.exe', 'taskmgr.exe', 'system', 'registry', 
    'fontdrvhost.exe', 'dwm.exe', 'winlogon.exe', 'searchapp.exe',
    'sihost.exe', 'taskhostw.exe', 'conhost.exe', 'ctfmon.exe',
    'audiodg.exe', 'rundll32.exe'
}

HIGH_RISK_LIST = {
    'cmd.exe', 'powershell.exe', 'onedrive.exe', 'shellexperiencehost.exe',
    'startmenuexperiencehost.exe', 'widgets.exe', 'wsl.exe', 'vmmem'
}

MEDIUM_RISK_LIST = {
    'chrome.exe', 'opera.exe', 'msedge.exe', 'firefox.exe', 'code.exe', 
    'devenv.exe', 'excel.exe', 'winword.exe', 'powerpnt.exe', 'photoshop.exe'
}

TEMP_DIRS = {
    tempfile.gettempdir().lower(),
    os.environ.get('TEMP', '').lower(),
    os.environ.get('TMP', '').lower()
}

UI_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Core Diagnostics & Safe System Manager Pro</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #090d16;
            --card-bg: rgba(22, 31, 48, 0.7);
            --card-border: rgba(255, 255, 255, 0.08);
            --accent-cyan: #38bdf8;
            --accent-green: #34d399;
            --accent-red: #f87171;
            --accent-amber: #fbbf24;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: radial-gradient(circle at top right, #111827, var(--bg));
            color: var(--text-main);
            margin: 0;
            padding: 28px;
            min-height: 100vh;
        }

        .container { max-width: 1240px; margin: 0 auto; }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
        }

        h1 { margin: 0; font-size: 24px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 10px; }
        .subtitle { color: var(--text-muted); font-size: 13px; margin-top: 4px; }

        .header-actions { display: flex; gap: 10px; }

        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            backdrop-filter: blur(12px);
            padding: 18px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.2);
        }

        .card-title { font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; letter-spacing: 0.5px; }
        .card-value { font-size: 22px; font-weight: 700; margin-top: 6px; }

        .toolbar {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            backdrop-filter: blur(12px);
            border-radius: 12px;
            padding: 16px 20px;
            margin-bottom: 20px;
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
            align-items: flex-end;
        }

        .field { display: flex; flex-direction: column; gap: 6px; flex: 1; min-width: 160px; }
        label { font-size: 12px; color: var(--text-muted); font-weight: 600; }

        input, select {
            background: rgba(9, 13, 22, 0.8);
            border: 1px solid var(--card-border);
            color: var(--text-main);
            padding: 10px 14px;
            border-radius: 8px;
            font-size: 13px;
            outline: none;
            transition: border 0.2s;
        }

        input:focus, select:focus { border-color: var(--accent-cyan); }

        .btn {
            background: var(--accent-cyan);
            color: #090d16;
            border: none;
            padding: 10px 18px;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.2s;
            height: 38px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .btn:hover { opacity: 0.9; transform: translateY(-1px); }
        .btn-green { background: var(--accent-green); color: #090d16; }
        .btn-danger { background: var(--accent-red); color: white; }
        .btn-danger:disabled { background: #374151; cursor: not-allowed; color: #6b7280; transform: none; }
        .btn-secondary { background: rgba(255,255,255,0.08); color: #fff; }
        .btn-secondary:hover { background: rgba(255,255,255,0.15); }

        .table-container {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            backdrop-filter: blur(12px);
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 24px;
        }

        table { width: 100%; border-collapse: collapse; text-align: left; }
        th { background: rgba(9, 13, 22, 0.6); color: var(--text-muted); padding: 14px 18px; font-size: 11px; text-transform: uppercase; font-weight: 600; border-bottom: 1px solid var(--card-border); }
        td { padding: 12px 18px; border-bottom: 1px solid var(--card-border); font-size: 13px; }
        tr:hover { background: rgba(255, 255, 255, 0.02); }

        .badge { padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; display: inline-block; }
        .badge-safe { background: rgba(52, 211, 153, 0.15); color: var(--accent-green); }
        .badge-caution { background: rgba(251, 191, 36, 0.15); color: var(--accent-amber); }
        .badge-danger { background: rgba(248, 113, 113, 0.15); color: var(--accent-red); }
        .badge-pinned { background: rgba(56, 189, 248, 0.15); color: var(--accent-cyan); }

        .logs-panel {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            backdrop-filter: blur(12px);
            border-radius: 12px;
            padding: 20px;
        }

        .logs-title { font-size: 14px; font-weight: 700; color: #fff; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; }
        .log-list { max-height: 150px; overflow-y: auto; font-family: monospace; font-size: 12px; color: var(--text-muted); }
        .log-item { padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.04); }

        .modal-overlay {
            position: fixed; top:0; left:0; width:100%; height:100%;
            background: rgba(0, 0, 0, 0.75);
            backdrop-filter: blur(6px);
            display: none;
            justify-content: center; align-items: center; z-index: 1000;
            opacity: 0;
            transition: opacity 0.25s ease;
        }

        .modal-overlay.active { display: flex; opacity: 1; }

        .modal {
            background: #111827;
            border: 1px solid var(--card-border);
            width: 90%; max-width: 520px;
            border-radius: 16px; padding: 24px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
            transform: translateY(15px);
            transition: transform 0.25s ease;
        }

        .modal-overlay.active .modal { transform: translateY(0); }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
        .modal-title { font-size: 18px; font-weight: 700; color: #fff; }
        .modal-body { font-size: 14px; line-height: 1.6; color: var(--text-muted); margin-bottom: 24px; }
        .modal-body strong { color: #fff; }
        .modal-footer { display: flex; justify-content: flex-end; gap: 12px; }

        input[type="checkbox"] { accent-color: var(--accent-cyan); transform: scale(1.1); cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>⚡ Deep Core System Diagnostics Pro</h1>
                <div class="subtitle">System Resource Monitoring, Safety Guard & Realtime Telemetry</div>
            </div>
            <div class="header-actions">
                <button class="btn btn-green" onclick="quickCleanRam()">🧹 Fast RAM Boost</button>
                <button class="btn btn-secondary" onclick="openFloatingHUD()">📌 Network HUD Pro</button>
                <button class="btn" onclick="fetchDiagnostics()">Refresh</button>
            </div>
        </header>

        <div class="dashboard-grid">
            <div class="card">
                <div class="card-title">Total CPU Load</div>
                <div class="card-value" id="cpuLoad" style="color: var(--accent-amber);">0%</div>
            </div>
            <div class="card">
                <div class="card-title">RAM Usage</div>
                <div class="card-value" id="ramUsage">0 / 0 GB</div>
            </div>
            <div class="card">
                <div class="card-title">Network Download</div>
                <div class="card-value" id="netDown" style="color: var(--accent-green);">0 KB/s</div>
            </div>
            <div class="card">
                <div class="card-title">Network Upload</div>
                <div class="card-value" id="netUp" style="color: var(--accent-cyan);">0 KB/s</div>
            </div>
            <div class="card">
                <div class="card-title">Active Processes</div>
                <div class="card-value" id="totalProcCount">0</div>
            </div>
        </div>

        <div class="toolbar">
            <div class="field">
                <label for="searchFilter">Search Name / PID</label>
                <input type="text" id="searchFilter" placeholder="e.g. chrome, opera, 8516" oninput="renderTable()">
            </div>
            <div class="field">
                <label for="riskFilter">Risk Level Filter</label>
                <select id="riskFilter" onchange="renderTable()">
                    <option value="all">All Safe-To-Review Processes</option>
                    <option value="suspicious">Suspicious / Anomalies Only</option>
                    <option value="high_risk">High Risk Only</option>
                    <option value="caution">Medium Risk (Browsers / Apps)</option>
                    <option value="low_risk">Low Risk (User Apps)</option>
                </select>
            </div>
            <div class="field">
                <label for="sortFilter">Sort By</label>
                <select id="sortFilter" onchange="renderTable()">
                    <option value="memory">RAM Usage (Highest First)</option>
                    <option value="cpu">CPU Usage (Highest First)</option>
                    <option value="name">Process Name</option>
                </select>
            </div>
            <button class="btn btn-danger" id="bulkKillBtn" onclick="promptBulkKill()" disabled>Close Selected (0)</button>
        </div>

        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th style="width: 40px;"><input type="checkbox" id="selectAll" onclick="toggleSelectAll(this)"></th>
                        <th>PID</th>
                        <th>Process Name</th>
                        <th>Risk Assessment</th>
                        <th>CPU %</th>
                        <th>RAM Usage</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="processTableBody">
                    <tr><td colspan="7" style="text-align: center; color: var(--text-muted);">Querying system processes...</td></tr>
                </tbody>
            </table>
        </div>

        <div class="logs-panel">
            <div class="logs-title">
                <span>📋 Action History Audit</span>
                <span style="font-size: 11px; color: var(--text-muted); font-weight: normal;">Session Log</span>
            </div>
            <div class="log-list" id="logList">
                <div class="log-item">System monitor initialized. Ready for operations.</div>
            </div>
        </div>
    </div>

    <div class="modal-overlay" id="modalOverlay">
        <div class="modal">
            <div class="modal-header">
                <div class="modal-title" id="modalTitle">Caution Notice</div>
            </div>
            <div class="modal-body" id="modalContent"></div>
            <div class="modal-footer" id="modalFooter">
                <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
                <button class="btn btn-danger" id="modalConfirmBtn">Proceed</button>
            </div>
        </div>
    </div>

    <script>
        let cachedProcesses = [];

        function openFloatingHUD() {
            window.open('/hud', 'NetworkHUD', 'width=620,height=520,top=20,left=20,resizable=yes,scrollbars=no,toolbar=no,menubar=no,location=no,status=no');
        }

        async function fetchDiagnostics() {
            try {
                const res = await fetch('/api/diagnostics');
                const data = await res.json();

                document.getElementById('cpuLoad').innerText = `${data.system.cpu_percent}%`;
                document.getElementById('ramUsage').innerText = `${data.system.ram_used_gb} / ${data.system.ram_total_gb} GB`;
                document.getElementById('netDown').innerText = data.network.down_speed;
                document.getElementById('netUp').innerText = data.network.up_speed;
                document.getElementById('totalProcCount').innerText = data.system.total_processes;

                cachedProcesses = data.processes;
                renderTable();
                updateLogs(data.logs);
            } catch (e) {
                console.error("Failed to load metrics", e);
            }
        }

        function updateLogs(logs) {
            if (!logs || logs.length === 0) return;
            const logList = document.getElementById('logList');
            logList.innerHTML = logs.map(l => `<div class="log-item">[${l.time}] ${l.message}</div>`).join('');
        }

        function renderTable() {
            const search = document.getElementById('searchFilter').value.toLowerCase();
            const riskFilter = document.getElementById('riskFilter').value;
            const sortBy = document.getElementById('sortFilter').value;
            const tbody = document.getElementById('processTableBody');

            let filtered = cachedProcesses.filter(p => {
                const matchesSearch = p.name.toLowerCase().includes(search) || p.pid.toString().includes(search);
                if (!matchesSearch) return false;

                if (riskFilter === 'suspicious') return p.is_suspicious;
                if (riskFilter === 'high_risk') return p.risk_level === 'HIGH';
                if (riskFilter === 'caution') return p.risk_level === 'MEDIUM';
                if (riskFilter === 'low_risk') return p.risk_level === 'LOW';
                return true;
            });

            filtered.sort((a, b) => {
                if (sortBy === 'memory') return b.memory_mb - a.memory_mb;
                if (sortBy === 'cpu') return b.cpu_percent - a.cpu_percent;
                if (sortBy === 'name') return a.name.localeCompare(b.name);
            });

            tbody.innerHTML = '';
            if (filtered.length === 0) {
                tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No matching processes found.</td></tr>`;
                updateBulkBtn();
                return;
            }

            filtered.forEach(p => {
                let badgeClass = 'badge-safe';
                if (p.is_pinned) badgeClass = 'badge-pinned';
                else if (p.risk_level === 'HIGH' || p.is_suspicious) badgeClass = 'badge-danger';
                else if (p.risk_level === 'MEDIUM') badgeClass = 'badge-caution';

                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><input type="checkbox" class="proc-cb" value="${p.pid}" data-risk="${p.risk_level}" data-name="${p.name}" onclick="updateBulkBtn()"></td>
                    <td style="color: var(--text-muted); font-family: monospace;">${p.pid}</td>
                    <td><strong>${p.name}</strong></td>
                    <td>
                        <span class="badge ${badgeClass}">${p.is_pinned ? 'PINNED' : p.risk_level + ' RISK'}</span>
                        <span style="font-size: 11px; color: var(--text-muted); margin-left: 6px;">${p.risk_reason}</span>
                    </td>
                    <td>${p.cpu_percent.toFixed(1)}%</td>
                    <td>${p.memory_mb.toFixed(1)} MB</td>
                    <td style="display: flex; gap: 6px;">
                        <button class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px; height: auto;" onclick="togglePin('${p.name}')">${p.is_pinned ? 'Unpin' : '📌 Pin'}</button>
                        <button class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px; height: auto;" onclick="inspectProcess(${p.pid})">Inspect</button>
                        <button class="btn btn-danger" style="padding: 4px 8px; font-size: 11px; height: auto;" onclick="promptSingleKill(${p.pid}, '${p.name}', '${p.risk_level}')">Close</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });

            updateBulkBtn();
        }

        async function togglePin(name) {
            await fetch('/api/toggle_pin', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ name: name })
            });
            fetchDiagnostics();
        }

        async function quickCleanRam() {
            openModal('Fast RAM Boost', 'Cleaning background non-pinned high RAM applications...');
            const res = await fetch('/api/quick_clean', { method: 'POST' });
            const data = await res.json();
            openModal('RAM Boost Complete', `Freed memory across <strong>${data.closed_count}</strong> apps.<br>Estimated RAM recovered: <strong>${data.freed_mb} MB</strong>`);
            fetchDiagnostics();
        }

        function toggleSelectAll(source) {
            document.querySelectorAll('.proc-cb').forEach(cb => cb.checked = source.checked);
            updateBulkBtn();
        }

        function updateBulkBtn() {
            const selected = document.querySelectorAll('.proc-cb:checked');
            const btn = document.getElementById('bulkKillBtn');
            btn.innerText = `Close Selected (${selected.length})`;
            btn.disabled = selected.length === 0;
        }

        function openModal(title, content, confirmAction = null) {
            document.getElementById('modalTitle').innerText = title;
            document.getElementById('modalContent').innerHTML = content;
            const confirmBtn = document.getElementById('modalConfirmBtn');

            if (confirmAction) {
                confirmBtn.style.display = 'inline-block';
                confirmBtn.onclick = async () => {
                    closeModal();
                    await confirmAction();
                };
            } else {
                confirmBtn.style.display = 'none';
            }

            document.getElementById('modalOverlay').classList.add('active');
        }

        function closeModal() {
            document.getElementById('modalOverlay').classList.remove('active');
        }

        function promptSingleKill(pid, name, risk) {
            let warningText = `Are you sure you want to force close <strong>${name}</strong> (PID: ${pid})?`;
            if (risk === 'HIGH') {
                warningText = `⚠️ <strong>HIGH RISK CAUTION:</strong><br><br><strong>${name}</strong> is a system component. Force closing it may cause temporary desktop glitches or shell restarts.<br><br>Do you want to proceed?`;
            } else if (risk === 'MEDIUM') {
                warningText = `⚠️ <strong>CAUTION:</strong><br><br>Force closing <strong>${name}</strong> will discard unsaved browser tabs or active document states.<br><br>Proceed?`;
            }

            openModal('Process Termination Caution', warningText, () => killPids([pid]));
        }

        function promptBulkKill() {
            const selectedBoxes = Array.from(document.querySelectorAll('.proc-cb:checked'));
            const pids = selectedBoxes.map(cb => parseInt(cb.value));
            const hasHighRisk = selectedBoxes.some(cb => cb.getAttribute('data-risk') === 'HIGH');

            let warningText = `Are you sure you want to force close <strong>${pids.length}</strong> selected applications?`;
            if (hasHighRisk) {
                warningText = `⚠️ <strong>HIGH RISK CAUTION:</strong><br><br>Your selection includes critical system utilities. Closing them could cause UI restarts or service drops.<br><br>Are you sure?`;
            }

            openModal('Bulk Termination Caution', warningText, () => killPids(pids));
        }

        async function killPids(pids) {
            try {
                const res = await fetch('/api/kill', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ pids: pids })
                });
                const result = await res.json();
                
                openModal('Action Result', `Terminated: <strong>${result.terminated.length}</strong> process(es)<br>Blocked/Failed: <strong>${result.failed.length}</strong>`);
                fetchDiagnostics();
            } catch (e) {
                openModal('Error', 'Failed to reach backend server.');
            }
        }

        async function inspectProcess(pid) {
            openModal(`Inspecting PID: ${pid}`, 'Fetching metadata & network connections...');

            try {
                const res = await fetch(`/api/inspect/${pid}`);
                const data = await res.json();

                if (data.error) {
                    document.getElementById('modalContent').innerHTML = `<span style="color: var(--accent-red);">${data.error}</span>`;
                    return;
                }

                document.getElementById('modalContent').innerHTML = `
                    <p><strong>Name:</strong> ${data.name}</p>
                    <p><strong>Executable Path:</strong> <code style="word-break: break-all; color: var(--accent-cyan);">${data.exe || 'N/A'}</code></p>
                    <p><strong>Parent PID:</strong> ${data.ppid}</p>
                    <p><strong>Active Threads:</strong> ${data.num_threads}</p>
                    <p><strong>Active Network Connections:</strong> ${data.net_connections}</p>
                    <p><strong>Start Time:</strong> ${data.create_time}</p>
                    <p><strong>Command Line:</strong> <code style="word-break: break-all; color: var(--accent-cyan);">${data.cmdline || 'N/A'}</code></p>
                `;
            } catch (e) {
                document.getElementById('modalContent').innerText = "Failed to load details.";
            }
        }

        setInterval(fetchDiagnostics, 2000);
        window.onload = fetchDiagnostics;
    </script>
</body>
</html>
"""

HUD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Network Intelligence HUD Pro</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            background-color: #090d16;
            color: #f3f4f6;
            font-family: 'Inter', sans-serif;
            margin: 0;
            padding: 12px;
            user-select: none;
        }
        .hud-card {
            background: rgba(22, 31, 48, 0.95);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 16px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.5);
        }
        .hud-header {
            font-size: 11px;
            text-transform: uppercase;
            color: #9ca3af;
            font-weight: 700;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            padding-bottom: 8px;
            margin-bottom: 12px;
        }
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 8px;
            margin-bottom: 12px;
        }
        .stat-box {
            background: rgba(9, 13, 22, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.05);
            padding: 8px;
            border-radius: 6px;
        }
        .stat-lbl { font-size: 9px; text-transform: uppercase; color: #9ca3af; }
        .val { font-size: 13px; font-weight: 700; font-family: monospace; margin-top: 2px; }
        .down { color: #34d399; }
        .up { color: #38bdf8; }
        .ping { color: #fbbf24; }

        .sparkline-container {
            background: rgba(9, 13, 22, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 6px;
            padding: 8px;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        canvas { width: 100%; height: 35px; }

        .tabs { display: flex; gap: 8px; margin-bottom: 8px; }
        .tab-btn {
            background: rgba(255,255,255,0.05); border: none; color: #9ca3af;
            padding: 4px 10px; border-radius: 4px; font-size: 10px; font-weight: bold; cursor: pointer;
        }
        .tab-btn.active { background: #38bdf8; color: #090d16; }

        .net-table-wrap {
            background: rgba(9, 13, 22, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 6px;
            height: 200px;
            overflow-y: auto;
            font-size: 11px;
        }

        table { width: 100%; border-collapse: collapse; text-align: left; }
        th { position: sticky; top: 0; background: #0f172a; padding: 6px 8px; font-size: 9px; color: #9ca3af; text-transform: uppercase; }
        td { padding: 6px 8px; border-bottom: 1px solid rgba(255,255,255,0.03); font-family: monospace; }
        
        .kill-btn {
            background: #f87171; color: #fff; border: none; border-radius: 3px;
            padding: 2px 6px; font-size: 9px; cursor: pointer; font-weight: bold;
        }
        .kill-btn:hover { background: #dc2626; }

        .ip-info {
            font-size: 10px;
            color: #9ca3af;
            margin-top: 10px;
            display: flex;
            justify-content: space-between;
        }
    </style>
</head>
<body>
    <div class="hud-card">
        <div class="hud-header">
            <span>📡 Network Intel HUD Pro</span>
            <span style="color:#34d399; font-size: 10px;">● REALTIME TELEMETRY</span>
        </div>

        <div class="stat-grid">
            <div class="stat-box">
                <div class="stat-lbl">Download</div>
                <div class="val down" id="hudDown">0 KB/s</div>
            </div>
            <div class="stat-box">
                <div class="stat-lbl">Upload</div>
                <div class="val up" id="hudUp">0 KB/s</div>
            </div>
            <div class="stat-box">
                <div class="stat-lbl">Ping (1.1.1.1)</div>
                <div class="val ping" id="hudPing">-- ms</div>
            </div>
            <div class="stat-box">
                <div class="stat-lbl">Active Sockets</div>
                <div class="val" id="hudSockets" style="color: #f3f4f6;">0</div>
            </div>
        </div>

        <div class="sparkline-container">
            <canvas id="speedCanvas"></canvas>
        </div>

        <div class="tabs">
            <button class="tab-btn active" id="btnDataTab" onclick="switchTab('data')">Per-App Data Usage</button>
            <button class="tab-btn" id="btnConnTab" onclick="switchTab('conns')">Remote Sockets Inspector</button>
        </div>

        <div class="net-table-wrap" id="dataTabContent">
            <table>
                <thead>
                    <tr>
                        <th>PID</th>
                        <th>App Name</th>
                        <th>Downloaded</th>
                        <th>Uploaded</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody id="appDataBody">
                    <tr><td colspan="5" style="text-align:center; color:#6b7280;">Measuring data stream...</td></tr>
                </tbody>
            </table>
        </div>

        <div class="net-table-wrap" id="connsTabContent" style="display: none;">
            <table>
                <thead>
                    <tr>
                        <th>App</th>
                        <th>Remote IP</th>
                        <th>Port</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="connsBody">
                    <tr><td colspan="4" style="text-align:center; color:#6b7280;">Querying sockets...</td></tr>
                </tbody>
            </table>
        </div>

        <div class="ip-info">
            <span>Local IP: <strong id="hudIp" style="color:#fff;">--</strong></span>
            <span>Adapter: <strong id="hudNicName" style="color:#fff;">--</strong></span>
        </div>
    </div>

    <script>
        let currentTab = 'data';
        let speedHistory = new Array(30).fill(0);

        function drawChart(val) {
            const canvas = document.getElementById('speedCanvas');
            const ctx = canvas.getContext('2d');
            canvas.width = canvas.offsetWidth;
            canvas.height = canvas.offsetHeight;

            speedHistory.push(val);
            speedHistory.shift();

            ctx.clearRect(0, 0, canvas.width, canvas.height);
            ctx.beginPath();
            ctx.strokeStyle = '#34d399';
            ctx.lineWidth = 2;

            const max = Math.max(...speedHistory, 100);
            const step = canvas.width / (speedHistory.length - 1);

            speedHistory.forEach((v, i) => {
                const x = i * step;
                const y = canvas.height - (v / max * canvas.height);
                if (i === 0) ctx.moveTo(x, y);
                else ctx.lineTo(x, y);
            });
            ctx.stroke();
        }

        function switchTab(tab) {
            currentTab = tab;
            document.getElementById('btnDataTab').classList.toggle('active', tab === 'data');
            document.getElementById('btnConnTab').classList.toggle('active', tab === 'conns');
            document.getElementById('dataTabContent').style.display = tab === 'data' ? 'block' : 'none';
            document.getElementById('connsTabContent').style.display = tab === 'conns' ? 'block' : 'none';
            updateHUD();
        }

        async function updateHUD() {
            try {
                const res = await fetch('/api/network_hud_pro');
                const data = await res.json();

                document.getElementById('hudDown').innerText = data.down_speed;
                document.getElementById('hudUp').innerText = data.up_speed;
                document.getElementById('hudPing').innerText = data.ping_ms;
                document.getElementById('hudSockets').innerText = data.active_sockets;
                document.getElementById('hudIp').innerText = data.local_ip;
                document.getElementById('hudNicName').innerText = data.active_adapter;

                drawChart(data.raw_down_kb);

                const appDataBody = document.getElementById('appDataBody');
                if (data.app_usage.length === 0) {
                    appDataBody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:#6b7280;">No active data stream</td></tr>';
                } else {
                    appDataBody.innerHTML = data.app_usage.map(a => `
                        <tr>
                            <td style="color:#6b7280;">${a.pid}</td>
                            <td><strong style="color:#fff;">${a.name}</strong></td>
                            <td style="color:#34d399;">${a.recv_mb} MB</td>
                            <td style="color:#38bdf8;">${a.sent_mb} MB</td>
                            <td><button class="kill-btn" onclick="killFromHUD(${a.pid}, '${a.name}')">Close</button></td>
                        </tr>
                    `).join('');
                }

                const connsBody = document.getElementById('connsBody');
                if (data.remote_sockets.length === 0) {
                    connsBody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#6b7280;">No remote socket connections</td></tr>';
                } else {
                    connsBody.innerHTML = data.remote_sockets.map(c => `
                        <tr>
                            <td><strong style="color:#fff;">${c.name}</strong></td>
                            <td style="color:#38bdf8;">${c.remote_ip}</td>
                            <td style="color:#fbbf24;">${c.remote_port}</td>
                            <td style="color:#34d399;">${c.status}</td>
                        </tr>
                    `).join('');
                }
            } catch (e) {}
        }

        async function killFromHUD(pid, name) {
            if (!confirm(`Close ${name} directly from HUD?`)) return;
            await fetch('/api/kill', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pids: [pid] })
            });
            updateHUD();
        }

        setInterval(updateHUD, 2000);
        window.onload = updateHUD;
    </script>
</body>
</html>
"""

def log_action(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    ACTION_LOGS.insert(0, {'time': timestamp, 'message': message})
    if len(ACTION_LOGS) > 30:
        ACTION_LOGS.pop()

def format_speed(bytes_per_sec):
    if bytes_per_sec > 1024 * 1024:
        return f"{bytes_per_sec / (1024 * 1024):.1f} MB/s"
    return f"{bytes_per_sec / 1024:.1f} KB/s"

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

@app.route('/')
def index():
    return render_template_string(UI_TEMPLATE)

@app.route('/hud')
def hud():
    return render_template_string(HUD_TEMPLATE)

@app.route('/api/toggle_pin', methods=['POST'])
def toggle_pin():
    name = request.json.get('name', '').lower()
    if name in CUSTOM_WHITELIST:
        CUSTOM_WHITELIST.remove(name)
        log_action(f"Unpinned app from safe whitelist: {name}")
    else:
        CUSTOM_WHITELIST.add(name)
        log_action(f"Pinned app to safe whitelist: {name}")
    return jsonify({'status': 'ok'})

@app.route('/api/quick_clean', methods=['POST'])
def quick_clean():
    closed_count = 0
    freed_mb = 0.0

    for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
        try:
            name = proc.info.get('name') or ''
            name_lower = name.lower()

            if name_lower in CRITICAL_SAFE_LIST or name_lower in CUSTOM_WHITELIST:
                continue

            mem_mb = (proc.info['memory_info'].rss / (1024 * 1024)) if proc.info.get('memory_info') else 0.0

            if mem_mb > 400 and name_lower not in HIGH_RISK_LIST:
                proc.terminate()
                closed_count += 1
                freed_mb += mem_mb
        except:
            pass

    log_action(f"Fast RAM Boost executed: Closed {closed_count} apps, freed {round(freed_mb, 1)} MB RAM.")
    return jsonify({'closed_count': closed_count, 'freed_mb': round(freed_mb, 1)})

@app.route('/api/network_hud_pro', methods=['GET'])
def get_network_hud_pro():
    global PREV_PROC_IO, PROC_NET_STATS

    ping_ms = "-- ms"
    try:
        t0 = time.time()
        s = socket.create_connection(("1.1.1.1", 53), timeout=0.8)
        s.close()
        ping_ms = f"{int((time.time() - t0) * 1000)} ms"
    except:
        pass

    app_usage_list = []
    remote_sockets = []
    total_sockets = 0

    try:
        for proc in psutil.process_iter(['pid', 'name', 'io_counters']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                if not name or name.lower() in CRITICAL_SAFE_LIST:
                    continue

                io = proc.info.get('io_counters')
                if io:
                    read_bytes = getattr(io, 'read_bytes', 0)
                    write_bytes = getattr(io, 'write_bytes', 0)

                    if pid in PREV_PROC_IO:
                        diff_read = max(0, read_bytes - PREV_PROC_IO[pid][0])
                        diff_write = max(0, write_bytes - PREV_PROC_IO[pid][1])

                        if pid not in PROC_NET_STATS:
                            PROC_NET_STATS[pid] = {'name': name, 'recv_bytes': 0, 'sent_bytes': 0}

                        PROC_NET_STATS[pid]['recv_bytes'] += diff_read
                        PROC_NET_STATS[pid]['sent_bytes'] += diff_write

                    PREV_PROC_IO[pid] = (read_bytes, write_bytes)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception:
        pass

    for pid, data in list(PROC_NET_STATS.items()):
        try:
            if psutil.pid_exists(pid):
                recv_mb = round(data['recv_bytes'] / (1024 * 1024), 2)
                sent_mb = round(data['sent_bytes'] / (1024 * 1024), 2)
                if recv_mb > 0 or sent_mb > 0:
                    app_usage_list.append({
                        'pid': pid,
                        'name': data['name'],
                        'recv_mb': recv_mb,
                        'sent_mb': sent_mb
                    })
        except:
            pass

    app_usage_list.sort(key=lambda x: (x['recv_mb'] + x['sent_mb']), reverse=True)

    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status in ['ESTABLISHED', 'LISTEN']:
                total_sockets += 1
                if conn.raddr and len(remote_sockets) < 15:
                    pname = "Unknown"
                    if conn.pid:
                        try: pname = psutil.Process(conn.pid).name()
                        except: pass

                    remote_sockets.append({
                        'name': pname,
                        'remote_ip': conn.raddr.ip,
                        'remote_port': conn.raddr.port,
                        'status': conn.status
                    })
    except (psutil.AccessDenied, PermissionError):
        pass

    active_adapter = "Ethernet/Wi-Fi"
    try:
        stats = psutil.net_if_stats()
        for nic, stat in stats.items():
            if stat.isup and stat.speed > 0:
                active_adapter = nic
                break
    except: pass

    return jsonify({
        'up_speed': GLOBAL_UP_SPEED,
        'down_speed': GLOBAL_DOWN_SPEED,
        'raw_down_kb': GLOBAL_RAW_DOWN_KB,
        'ping_ms': ping_ms,
        'active_sockets': total_sockets,
        'local_ip': get_local_ip(),
        'active_adapter': active_adapter,
        'app_usage': app_usage_list[:10],
        'remote_sockets': remote_sockets
    })

@app.route('/api/diagnostics', methods=['GET'])
def get_diagnostics():
    virtual_mem = psutil.virtual_memory()
    
    processes = []
    flagged_count = 0

    for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'cpu_percent', 'status', 'exe']):
        try:
            name = proc.info.get('name') or ''
            name_lower = name.lower()
            
            if not name or name_lower in CRITICAL_SAFE_LIST:
                continue

            pid = proc.info['pid']
            mem_mb = (proc.info['memory_info'].rss / (1024 * 1024)) if proc.info.get('memory_info') else 0.0
            cpu = proc.info.get('cpu_percent') or 0.0
            status = proc.info.get('status') or 'unknown'
            exe_path = proc.info.get('exe') or ''

            risk_level = "LOW"
            risk_reason = "Standard Application"
            is_suspicious = False

            if exe_path:
                exe_dir = os.path.dirname(exe_path).lower()
                if any(temp_dir in exe_dir for temp_dir in TEMP_DIRS if temp_dir):
                    is_suspicious = True
                    risk_level = "HIGH"
                    risk_reason = "Running from Temp Folder"

            if name_lower in HIGH_RISK_LIST:
                risk_level = "HIGH"
                risk_reason = "System Utility / Shell Component"
            elif name_lower in MEDIUM_RISK_LIST:
                risk_level = "MEDIUM"
                risk_reason = "Browser / Active Productivity Tool"

            if is_suspicious or mem_mb > 300 or cpu > 10:
                flagged_count += 1

            processes.append({
                'pid': pid,
                'name': name,
                'memory_mb': round(mem_mb, 2),
                'cpu_percent': round(cpu, 1),
                'status': status,
                'risk_level': risk_level,
                'risk_reason': risk_reason,
                'is_suspicious': is_suspicious,
                'is_pinned': name_lower in CUSTOM_WHITELIST
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return jsonify({
        'system': {
            'cpu_percent': round(GLOBAL_CPU_PERCENT, 1), # Arka planda anlık hesaplanan gerçek CPU
            'ram_total_gb': round(virtual_mem.total / (1024**3), 2),
            'ram_used_gb': round(virtual_mem.used / (1024**3), 2),
            'ram_percent': virtual_mem.percent,
            'total_processes': len(psutil.pids()),
            'flagged_processes': flagged_count
        },
        'network': {
            'up_speed': GLOBAL_UP_SPEED,
            'down_speed': GLOBAL_DOWN_SPEED
        },
        'processes': processes,
        'logs': ACTION_LOGS
    })

@app.route('/api/inspect/<int:pid>', methods=['GET'])
def inspect_process(pid):
    try:
        p = psutil.Process(pid)
        create_time = datetime.fromtimestamp(p.create_time()).strftime("%Y-%m-%d %H:%M:%S")
        cmdline = " ".join(p.cmdline()) if p.cmdline() else "N/A"
        
        net_conn_count = 0
        try:
            net_conn_count = len(p.net_connections())
        except (psutil.AccessDenied, AttributeError):
            net_conn_count = "Restricted / Unknown"

        return jsonify({
            'pid': pid,
            'name': p.name(),
            'exe': p.exe(),
            'ppid': p.ppid(),
            'num_threads': p.num_threads(),
            'net_connections': net_conn_count,
            'create_time': create_time,
            'cmdline': cmdline
        })
    except psutil.AccessDenied:
        return jsonify({'error': 'Access Denied by Operating System.'}), 403
    except psutil.NoSuchProcess:
        return jsonify({'error': 'Process no longer exists.'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/kill', methods=['POST'])
def kill_processes():
    pids = request.json.get('pids', [])
    terminated = []
    failed = []

    for pid in pids:
        try:
            p = psutil.Process(pid)
            name = p.name()
            name_lower = name.lower()
            
            if name_lower in CRITICAL_SAFE_LIST or name_lower in CUSTOM_WHITELIST:
                failed.append({'pid': pid, 'reason': 'Protected system file or Pinned app.'})
                log_action(f"BLOCKED termination attempt on protected file/pinned app: {name} (PID: {pid})")
                continue

            p.terminate()
            terminated.append(pid)
            log_action(f"Successfully force-closed application: {name} (PID: {pid})")
        except Exception as e:
            failed.append({'pid': pid, 'reason': str(e)})
            log_action(f"Failed to close PID {pid}: {str(e)}")

    return jsonify({'terminated': terminated, 'failed': failed})

if __name__ == '__main__':
    print("Starting Realtime Core Diagnostic Suite Pro...")
    print("Open http://127.0.0.1:5000 in your browser.")
    app.run(host='127.0.0.1', port=5000, debug=True)