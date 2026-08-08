'use strict';

const $ = s => document.querySelector(s);
const state = {
  results: [],     // 当前展示的结果 ["ip:port", ...]
  sortKey: '',
  sortDir: 'asc',
  running: false,
  curJob: null,
  lastJobId: null,  // 扫描完成后保留 job ID 供日志查询
  timer: null,
};

// ── 主题切换 ──────────────────────────────────────
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  try { localStorage.setItem('cfscan-theme', theme); } catch (_) {}
}
function initTheme() {
  let t = 'dark';
  try { t = localStorage.getItem('cfscan-theme') || 'dark'; } catch (_) {}
  applyTheme(t);
}
$('#btnTheme').addEventListener('click', () => {
  const cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  applyTheme(cur === 'light' ? 'dark' : 'light');
});
initTheme();

// ── 提示 ──────────────────────────────────────────
function toast(msg, kind) {
  const el = document.createElement('div');
  el.className = 'toast' + (kind ? ' ' + kind : '');
  el.textContent = msg;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), 3600);
}

async function api(path, opts) {
  const r = await fetch(path, opts);
  const text = await r.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (_) {}
  if (!r.ok) throw new Error((data && data.error) || text || ('HTTP ' + r.status));
  return data;
}

// ── 并发分段 ──────────────────────────────────────
function setConc(v) {
  document.querySelectorAll('#segConc button').forEach(b => {
    b.classList.toggle('on', b.dataset.conc === String(v));
  });
}
document.querySelectorAll('#segConc button').forEach(b => {
  b.onclick = () => setConc(parseInt(b.dataset.conc, 10));
});

// ── 结果表 ────────────────────────────────────────
function parseLine(line) {
  const hashIdx = line.indexOf('#');
  const addr = hashIdx >= 0 ? line.slice(0, hashIdx) : line;
  const tag = hashIdx >= 0 ? line.slice(hashIdx + 1) : '';
  const idx = addr.lastIndexOf(':');
  const ip = idx >= 0 ? addr.slice(0, idx) : addr;
  const port = idx >= 0 ? addr.slice(idx + 1) : '443';
  return { ip, port, tag, raw: line };
}

function visibleRows() {
  let rows = state.results.map(parseLine);
  if (state.sortKey) {
    const dir = state.sortDir === 'asc' ? 1 : -1;
    rows = rows.slice().sort((a, b) => {
      const x = a[state.sortKey], y = b[state.sortKey];
      if (typeof x === 'string') return x.localeCompare(y) * dir;
      return (parseInt(x, 10) - parseInt(y, 10)) * dir;
    });
  }
  return rows;
}

function renderTable() {
  const rows = visibleRows();
  $('#emptyBox').style.display = rows.length ? 'none' : '';
  $('#statResult').textContent = `结果 ${state.results.length}`;
  const tb = $('#tbody');
  tb.innerHTML = '';
  rows.forEach((r, i) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="c-idx">${i + 1}</td>
      <td class="c-ip mono">${r.ip}</td>
      <td class="c-num mono">${r.port}</td>
      <td class="c-tag">${r.tag}</td>
      <td class="c-act"><button class="copy" data-line="${r.raw}" title="复制">⧉</button></td>`;
    tr.querySelector('.copy').onclick = () => {
      navigator.clipboard.writeText(r.raw);
      toast('已复制 ' + r.raw, 'ok');
    };
    tb.appendChild(tr);
  });
}

document.querySelectorAll('#tbl thead th[data-sort]').forEach(th => {
  th.onclick = () => {
    const k = th.dataset.sort;
    if (state.sortKey === k) {
      state.sortDir = state.sortDir === 'asc' ? 'desc' : 'asc';
    } else {
      state.sortKey = k;
      state.sortDir = 'asc';
    }
    document.querySelectorAll('#tbl thead th').forEach(t => t.removeAttribute('data-dir'));
    th.setAttribute('data-dir', state.sortDir);
    renderTable();
  };
});

// ── 进度与状态 ────────────────────────────────────
const stageLabels = ['', '[1/3 第一阶段 TLS 探测]', '[2/3 第二阶段 HTTP 校验]', '[3/3 第三阶段自定义域名校验]'];

function setStatus(text, kind) {
  $('#statusText').textContent = text;
  const cls = 'dot' + (kind ? ' ' + kind : '');
  const d1 = $('#statusDot'), d2 = $('#statusDot2');
  if (d1) d1.className = cls;
  if (d2) d2.className = cls;
}

function setProgress(pct, indet) {
  const fill = $('#progressFill');
  fill.className = indet ? 'indet' : '';
  if (indet) return;
  fill.style.width = Math.max(0, Math.min(100, pct)) + '%';
}

// ── 扫描 ──────────────────────────────────────────
function startScan() {
  const target = $('#inTarget').value.trim();
  if (!target) { toast('请填写目标', 'err'); return; }

  const concEl = document.querySelector('#segConc button.on');
  const concurrency = concEl ? parseInt(concEl.dataset.conc, 10) : 500;

  state.running = true;
  state.curJob = null;
  state.results = [];
  renderTable();
  const topbar = $('#topbar');
  if (topbar) topbar.classList.add('run');
  $('#btnStart').classList.add('hidden');
  $('#btnStop').classList.remove('hidden');
  setStatus('正在启动扫描...', 'run');
  setProgress(0, true);
  const logPanel = $('#logPanel');
  if (logPanel && logPanel.classList.contains('hidden')) {
    logPanel.classList.remove('hidden');
    setLogOpen(true);
  }

  api('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target,
      ports: $('#inPorts').value.trim() || '443',
      domain: $('#inDomain').value.trim(),
      concurrency,
    }),
  }).then(d => {
    state.curJob = d.id;
    state.lastJobId = d.id;
    clearInterval(state.timer);
    state.timer = setInterval(pollStatus, 1200);
  }).catch(e => {
    toast('启动失败: ' + e.message, 'err');
    stopRun();
  });
}

function pollStatus() {
  if (!state.curJob) return;
  api('/api/status?id=' + state.curJob).then(d => {
    if (d.status === 'running') {
      const p = d.progress || {};
      const stage = p.stage || 1;
      const eta = p.eta ? ` | 预计剩余 ${p.eta}` : '';
      setStatus(`${stageLabels[stage]} ${p.done || 0}/${p.total || 0} | 当前通过 ${p.passed || 0}${eta}`);
      if (p.total) {
        let pct;
        if (stage === 1) {
          pct = (p.done / p.total) * 33;
        } else if (stage === 2) {
          pct = 33 + (p.done / p.total) * 33;
        } else {
          pct = 66 + (p.done / p.total) * 34;
        }
        setProgress(pct);
      }
      if (stage > 1 && d.stage1) $('#statResult').textContent = `结果 ${d.stage1}`;
      loadLogs();
    } else {
      clearInterval(state.timer);
      if (d.status === 'failed') {
        setStatus('扫描失败: ' + (d.error || '未知错误'), 'err');
        toast('扫描失败: ' + (d.error || '未知错误'), 'err');
      } else {
        setStatus(`扫描完成 | 阶段一 ${d.stage1} → 阶段二 ${d.stage2} → 最终 ${d.final}`);
        setProgress(100);
      }
      stopRun();
      loadResult(d.id);
      refreshHistory();
    }
  }).catch(e => {
    if (e.message === 'job 不存在' && state.running) {
      clearInterval(state.timer);
      stopRun();
    }
  });
}

function loadLogs(id) {
  const jobId = id || state.curJob || state.lastJobId;
  if (!jobId) return;
  api('/api/logs?id=' + jobId).then(d => {
    const logs = d.logs || [];
    const el = $('#logContent');
    el.textContent = logs.join('\n');
    el.scrollTop = el.scrollHeight;
  }).catch(() => {});
}

function loadResult(id) {
  fetch('/api/result?id=' + id).then(r => r.text()).then(text => {
    state.results = text.split('\n').map(l => l.trim()).filter(Boolean);
    renderTable();
  }).catch(() => {});
}

function stopRun() {
  state.running = false;
  state.curJob = null;
  clearInterval(state.timer);
  const topbar = $('#topbar');
  if (topbar) topbar.classList.remove('run');
  $('#btnStart').classList.remove('hidden');
  $('#btnStop').classList.add('hidden');
}

$('#btnStart').addEventListener('click', startScan);
$('#btnStop').addEventListener('click', stopRun);
let logOpen = false;
function setLogOpen(open) {
  logOpen = !!open;
  const btn = $('#btnLogToggle');
  if (btn) btn.classList.toggle('active', logOpen);
}
$('#btnLogToggle').addEventListener('click', () => {
  const panel = $('#logPanel');
  setLogOpen(!logOpen);
  panel.classList.toggle('hidden', !logOpen);
  if (logOpen) loadLogs();
});

// ── 复制全部 ──────────────────────────────────────
$('#btnCopyAll').addEventListener('click', () => {
  if (!state.results.length) { toast('没有可复制的结果', 'err'); return; }
  navigator.clipboard.writeText(state.results.join('\n') + '\n');
  toast('已复制 ' + state.results.length + ' 条结果', 'ok');
});

// ── 历史记录 ──────────────────────────────────────
function refreshHistory() {
  api('/api/history').then(list => {
    const box = $('#historyList');
    $('#historyHint').textContent = list.length ? '点击一条加载结果' : '';
    box.innerHTML = '';
    if (!list.length) {
      box.innerHTML = '<em class="note">暂无历史记录</em>';
      return;
    }
    list.sort((a, b) => b.id - a.id).slice(0, 30).forEach(it => {
      const el = document.createElement('div');
      el.className = 'hist-item';
      const tag = it.status === 'running' ? '进行中' : it.status === 'done' ? '完成' : '失败';
      const color = it.status === 'running' ? 'y' : it.status === 'done' ? 'g' : 'r';
      el.innerHTML = `<b class="${color}">${tag}</b><span>${it.target} · ${it.final || 0} 条</span>`;
      el.onclick = () => {
        $('#historyMask').classList.add('hidden');
        if (it.status === 'done') {
          state.results = [];
          renderTable();
          loadResult(it.id);
          setStatus(`历史结果: ${it.target} | ${it.final} 条`);
          state.curJob = it.id;
          loadLogs();
        } else if (it.status === 'failed') {
          setStatus('历史任务失败: ' + (it.error || '未知错误'), 'err');
        }
      };
      box.appendChild(el);
    });
  }).catch(() => {});
}

$('#btnHistory').addEventListener('click', () => {
  refreshHistory();
  $('#historyMask').classList.remove('hidden');
});
$('#btnHistClose').addEventListener('click', () => $('#historyMask').classList.add('hidden'));
$('#historyMask').addEventListener('click', e => { if (e.target === $('#historyMask')) $('#historyMask').classList.add('hidden'); });

refreshHistory();
