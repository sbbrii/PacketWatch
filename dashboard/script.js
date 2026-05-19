// ── State ─────────────────────────────────────────────────────────────────────
let alerts = [];
let blockedIPs = new Set();
let charts = {};

const colors = {
  green: '#8EC27B',
  orange: '#EBB15B',
  blue: '#6DB8D6',
  yellow: '#D8A543',
  red: '#D9534F',
  purple: '#B276B2',
  grey: '#9E9E9E'
};

const chartColors = [colors.green, colors.orange, colors.blue, colors.yellow, colors.red, colors.purple];

// ── Fetch ─────────────────────────────────────────────────────────────────────
async function fetchAlerts() {
  try {
    const res = await fetch('/alerts');
    if (!res.ok) return;
    alerts = await res.json();
    render();
  } catch (e) {
    console.error('Fetch failed:', e);
  }
}

// ── Render all ────────────────────────────────────────────────────────────────
function render() {
  updateBlockedIPs();
  
  renderAnalysis();
  renderTimeline();
  renderDonuts();
  renderTables();
  renderTrends();
  setTimeout(() => { if (window.lucide) window.lucide.createIcons(); }, 10);
}

function updateBlockedIPs() {
  blockedIPs = new Set(
    alerts
      .filter(a => a.block_status === 'permanent' || a.block_status === 'temporary')
      .map(a => a.src_ip)
  );
}

// ── Analysis Module ───────────────────────────────────────────────────────────
function renderAnalysis() {
  if (alerts.length === 0) return;
  
  // Traffic Analysis
  const total = alerts.length;
  const half = Math.floor(alerts.length / 2);
  const firstHalf = alerts.slice(0, half);
  const secondHalf = alerts.slice(half);
  
  let growth = 0;
  if (firstHalf.length > 0) {
    growth = ((secondHalf.length - firstHalf.length) / firstHalf.length) * 100;
  }
  
  document.getElementById('traffic-analysis-content').innerHTML = `
    <div style="margin-bottom: 4px;">Total Events: <strong style="color:var(--text-main);">${total}</strong></div>
    <div style="margin-bottom: 4px;">Event Growth: <strong style="color:${growth >= 0 ? colors.red : colors.green};">${growth > 0 ? '+' : ''}${growth.toFixed(1)}%</strong></div>
    <div>Time Span: <strong style="color:var(--text-main);">Last 24h</strong></div>
  `;
  
  // Security Analysis
  const attackCounts = {};
  alerts.forEach(a => {
    attackCounts[a.attack_type || 'Unknown'] = (attackCounts[a.attack_type || 'Unknown'] || 0) + 1;
  });
  let topAttack = '';
  let maxCount = 0;
  for (const [type, count] of Object.entries(attackCounts)) {
    if (count > maxCount) { maxCount = count; topAttack = type; }
  }
  
  document.getElementById('security-analysis-content').innerHTML = `
    <div style="margin-bottom: 4px;">Most Frequent: <strong style="color:var(--color-orange);">${topAttack} (${maxCount})</strong></div>
    <div style="margin-bottom: 4px;">Unique Sources: <strong style="color:var(--text-main);">${new Set(alerts.map(a=>a.src_ip)).size}</strong></div>
    <div>Unique Targets: <strong style="color:var(--text-main);">${new Set(alerts.map(a=>a.dst_ip)).size}</strong></div>
  `;
  
  // Performance Analysis
  const blockedCount = alerts.filter(a => a.block_status && a.block_status !== 'none' && a.block_status !== 'unblocked').length;
  const avgScore = alerts.reduce((sum, a) => sum + (a.anomaly_score || 0), 0) / (alerts.length || 1);
  
  document.getElementById('performance-analysis-content').innerHTML = `
    <div style="margin-bottom: 4px;">Total Blocked: <strong style="color:var(--color-red);">${blockedCount}</strong></div>
    <div style="margin-bottom: 4px;">Avg Anomaly Score: <strong style="color:var(--text-main);">${avgScore.toFixed(1)}</strong></div>
    <div>System Status: <strong style="color:var(--color-green);">Online</strong></div>
  `;

  // Behavioral Analysis
  const highRisk = alerts.filter(a => a.anomaly_score > 80).length;
  
  document.getElementById('behavioral-analysis-content').innerHTML = `
    <div style="margin-bottom: 4px;">High Risk Events: <strong style="color:var(--color-red);">${highRisk}</strong></div>
    <div style="margin-bottom: 4px;">Anomalous Patterns: <strong style="color:var(--text-main);">Detected</strong></div>
    <div>Activity: <strong style="color:var(--color-orange);">Spiking</strong></div>
  `;
  
  // Top Row Metrics
  document.getElementById('metric-total-alerts').textContent = total;
  
  const attacksCount = alerts.filter(a => {
    const t = (a.attack_type || '').toLowerCase();
    return t && t !== 'unknown' && t !== 'benign';
  }).length;
  document.getElementById('metric-attacks').textContent = attacksCount;
  
  document.getElementById('metric-blocked').textContent = blockedIPs.size;
  document.getElementById('metric-threat-score').textContent = avgScore.toFixed(1);
}

// ── Timeline chart ────────────────────────────────────────────────────────────
function renderTimeline() {
  const buckets = 30;
  const bucketMs = 5 * 60 * 1000; // 5 mins per bucket
  const now = Date.now();
  const labels = [];
  
  for (let i = buckets - 1; i >= 0; i--) {
    const t = new Date(now - i * bucketMs);
    labels.push(
      t.getHours().toString().padStart(2, '0') + ':' +
      t.getMinutes().toString().padStart(2, '0')
    );
  }

  const types = [...new Set(alerts.map(a => a.attack_type || 'Unknown'))];
  const datasets = types.map((type, idx) => {
    const data = Array(buckets).fill(0);
    alerts.forEach(a => {
      if ((a.attack_type || 'Unknown') !== type) return;
      if (!a.timestamp) return;
      const ts = new Date(a.timestamp).getTime();
      const ago = now - ts;
      if (ago < 0 || ago > buckets * bucketMs) return;
      const bucketIdx = buckets - 1 - Math.floor(ago / bucketMs);
      if (bucketIdx >= 0 && bucketIdx < buckets) data[bucketIdx]++;
    });
    return {
      label: type,
      data: data,
      borderColor: chartColors[idx % chartColors.length],
      backgroundColor: chartColors[idx % chartColors.length] + '33',
      borderWidth: 1.5,
      pointRadius: 0,
      tension: 0.2,
      fill: true
    };
  });

  const ctx = document.getElementById('chart-events-time').getContext('2d');
  
  if (charts.timeline) {
    charts.timeline.data.labels = labels;
    charts.timeline.data.datasets = datasets;
    charts.timeline.update('none');
    return;
  }
  
  Chart.defaults.color = '#9E9E9E';
  Chart.defaults.font.family = 'Inter';

  charts.timeline = new Chart(ctx, {
    type: 'line',
    data: { labels, datasets },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {
        legend: {
          display: true,
          position: 'top',
          labels: { boxWidth: 10, usePointStyle: true, color: '#E0E0E0' }
        },
        tooltip: { mode: 'index', intersect: false }
      },
      scales: {
        x: { grid: { color: '#3A3A40' }, ticks: { maxTicksLimit: 10 } },
        y: { beginAtZero: true, grid: { color: '#3A3A40' }, ticks: { stepSize: 1 } }
      }
    }
  });
}

// ── Donuts ────────────────────────────────────────────────────────────────────
function createDonut(id, labels, dataVals, bgColors) {
  const el = document.getElementById(id);
  if (!el) return;
  const ctx = el.getContext('2d');
  
  if (charts[id]) {
    charts[id].data.labels = labels;
    charts[id].data.datasets[0].data = dataVals;
    charts[id].update('none');
    return;
  }
  charts[id] = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: labels,
      datasets: [{
        data: dataVals,
        backgroundColor: bgColors || chartColors,
        borderWidth: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      cutout: '65%',
      plugins: {
        legend: {
          display: true,
          position: 'left',
          labels: { boxWidth: 10, usePointStyle: true, color: '#E0E0E0', font: {size: 11} }
        }
      }
    }
  });
}

function renderDonuts() {
  const attackCounts = {};
  alerts.forEach(a => {
    const type = a.attack_type || a.label || 'Unknown';
    attackCounts[type] = (attackCounts[type] || 0) + 1;
  });
  createDonut('chart-attacks', Object.keys(attackCounts), Object.values(attackCounts));

  const sevCounts = { 'Low (<40)': 0, 'Medium (40-70)': 0, 'High (>70)': 0 };
  alerts.forEach(a => {
    const s = a.anomaly_score || 0;
    if (s < 40) sevCounts['Low (<40)']++;
    else if (s < 70) sevCounts['Medium (40-70)']++;
    else sevCounts['High (>70)']++;
  });
  createDonut('chart-severity', Object.keys(sevCounts), Object.values(sevCounts), [colors.blue, colors.yellow, colors.red]);
}

// ── Tables & Trends ───────────────────────────────────────────────────────────
function renderTables() {
  const attackCounts = {};
  alerts.forEach(a => { attackCounts[a.attack_type || 'Unknown'] = (attackCounts[a.attack_type || 'Unknown'] || 0) + 1; });
  const sortedAttacks = Object.entries(attackCounts).sort((a,b)=>b[1]-a[1]);
  document.querySelector('#alerts-table tbody').innerHTML = sortedAttacks.map(k => 
    `<tr><td>${k[0]}</td><td>${k[1]}</td><td><button class="action-btn" title="Inspect"><i data-lucide="search" style="width:16px;height:16px;"></i></button> <button class="action-btn action-block" style="color:var(--color-red);" title="Block"><i data-lucide="shield-ban" style="width:16px;height:16px;"></i></button></td></tr>`
  ).join('');

  const srcIpCounts = {};
  alerts.forEach(a => { srcIpCounts[a.src_ip || 'Unknown'] = (srcIpCounts[a.src_ip || 'Unknown'] || 0) + 1; });
  const sortedSrcIps = Object.entries(srcIpCounts).sort((a,b)=>b[1]-a[1]).slice(0, 10);
  document.querySelector('#src-ips-table tbody').innerHTML = sortedSrcIps.map(k => {
    const ip = k[0];
    const isBlocked = blockedIPs.has(ip);
    const actionHtml = isBlocked ? `<button class="unblock-btn" onclick="unblockIP('${ip}')"><i data-lucide="unlock" style="width:14px;height:14px;"></i> UNBLOCK</button>` : `<button class="action-btn action-block" style="color:var(--color-red);" title="Block"><i data-lucide="shield-ban" style="width:16px;height:16px;"></i></button>`;
    return `<tr><td>${ip}</td><td>${k[1]}</td><td><button class="action-btn" title="Inspect"><i data-lucide="search" style="width:16px;height:16px;"></i></button> ${actionHtml}</td></tr>`;
  }).join('');
  
  const dstIpCounts = {};
  alerts.forEach(a => { dstIpCounts[a.dst_ip || 'Unknown'] = (dstIpCounts[a.dst_ip || 'Unknown'] || 0) + 1; });
  const sortedDstIps = Object.entries(dstIpCounts).sort((a,b)=>b[1]-a[1]).slice(0, 10);
  document.querySelector('#dst-ips-table tbody').innerHTML = sortedDstIps.map(k => {
    return `<tr><td>${k[0]}</td><td>${k[1]}</td><td><button class="action-btn" title="Inspect"><i data-lucide="search" style="width:16px;height:16px;"></i></button></td></tr>`;
  }).join('');
}

function renderTrends() {
  const trendsList = document.getElementById('trends-list');
  if (alerts.length < 2) {
    trendsList.innerHTML = '<li style="color:var(--text-muted);">Need more data...</li>';
    return;
  }
  
  const half = Math.floor(alerts.length / 2);
  const firstHalf = alerts.slice(0, half);
  const secondHalf = alerts.slice(half);
  
  function getTrend(filterFn) {
    const c1 = firstHalf.filter(filterFn).length;
    const c2 = secondHalf.filter(filterFn).length;
    if (c1 === 0 && c2 === 0) return { val: 0, text: '0.00%' };
    if (c1 === 0) return { val: 100, text: '+100.00%' };
    const pct = ((c2 - c1) / c1) * 100;
    return { val: pct, text: (pct > 0 ? '+' : '') + pct.toFixed(2) + '%' };
  }

  const ddosTrend = getTrend(a => (a.attack_type || '').includes('DDoS'));
  const scanTrend = getTrend(a => (a.attack_type || '').includes('Scan') || (a.label || '').includes('SCAN'));
  const webTrend = getTrend(a => (a.label || '').includes('WEB'));
  const totalTrend = getTrend(()=>true);

  const items = [
    { label: 'DDoS Activity', trend: ddosTrend, color: colors.orange },
    { label: 'Port Scans', trend: scanTrend, color: colors.blue },
    { label: 'Web Attacks', trend: webTrend, color: colors.red },
    { label: 'Total Volume', trend: totalTrend, color: colors.green }
  ];

  trendsList.innerHTML = items.map(item => {
    const isUp = item.trend.val > 0;
    const isDown = item.trend.val < 0;
    const cls = isUp ? 'trend-down' : (isDown ? 'trend-up' : '');
    const icon = isUp ? '<i data-lucide="trending-up" style="width:14px;height:14px;"></i>' : (isDown ? '<i data-lucide="trending-down" style="width:14px;height:14px;"></i>' : '<i data-lucide="minus" style="width:14px;height:14px;"></i>');
    return `<li style="display:flex; align-items:center; justify-content:space-between; margin-bottom: 12px;">
      <div style="display:flex; align-items:center; gap:8px;">
        <span class="trend-dot" style="background-color: ${item.color}"></span>
        <span style="color:var(--text-muted);">${item.label}</span>
      </div>
      <span class="${cls}" style="font-family:var(--font-mono); font-size:12px; display:flex; align-items:center; gap:4px;">${icon} <span>${item.trend.text}</span></span>
    </li>`;
  }).join('');
}


// ── Unblock ───────────────────────────────────────────────────────────────────
async function unblockIP(ip) {
  try {
    const res = await fetch('/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    });
    const data = await res.json();
    if (data.status === 'queued' || data.status === 'already_queued') {
      showToast(`UNBLOCK QUEUED → ${ip}`);
      blockedIPs.delete(ip);
      render();
    }
  } catch (e) {
    showToast('ERROR: Could not reach server');
  }
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3000);
}

// ── Init ──────────────────────────────────────────────────────────────────────
fetchAlerts();
setInterval(fetchAlerts, 5000);
