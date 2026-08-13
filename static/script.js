// Elements
const form = document.getElementById('scan-form');
const resultEmpty = document.getElementById('result-empty');
const resultBody = document.getElementById('result-body');
const gaugeFill = document.getElementById('gauge-fill');
const gaugeNeedle = document.getElementById('gauge-needle');
const scoreValue = document.getElementById('score-value');
const verdictPill = document.getElementById('verdict-pill');
const confidenceText = document.getElementById('confidence-text');
const ruleScoreEl = document.getElementById('rule-score');
const modelScoreEl = document.getElementById('model-score');
const reasonsList = document.getElementById('reasons-list');
const reportBtn = document.getElementById('report-btn');
const reportConfirm = document.getElementById('report-confirm');
const caseTbody = document.getElementById('case-tbody');

const GAUGE_LENGTH = 314;
let lastAssessment = null;

// ---------- TAB NAVIGATION ---------- //
function switchTab(tabId) {
  document.querySelectorAll('.nav-item').forEach((item) => {
    item.classList.toggle('active', item.getAttribute('data-tab') === tabId);
  });

  document.querySelectorAll('.tab-view').forEach((view) => {
    if (view.id === `tab-${tabId}`) {
      view.classList.remove('hidden-view');
    } else {
      view.classList.add('hidden-view');
    }
  });

  const titleMap = {
    dashboard: 'Dashboard Overview',
    analyze: 'Profile Intake & Scanning',
    detection: 'Detection Signals & Consensus Engine',
    reports: 'Central Agency Case Reports',
    cases: 'Active Case Management',
    evidence: 'Immutable Blockchain Evidence Trail',
    audit: 'Reviewer Audit Logs',
    settings: 'SOC Engine Settings',
  };

  const pageTitle = document.getElementById('page-title');
  if (pageTitle && titleMap[tabId]) {
    pageTitle.textContent = titleMap[tabId];
  }

  if (tabId === 'dashboard') {
    loadDashboardStats();
  } else if (tabId === 'cases' || tabId === 'reports') {
    loadCases();
  }
}

// Attach sidebar nav click listeners
document.querySelectorAll('.nav-item').forEach((item) => {
  item.addEventListener('click', (e) => {
    e.preventDefault();
    const tabId = item.getAttribute('data-tab');
    switchTab(tabId);
  });
});

// ---------- DROPDOWN TOGGLES ---------- //
const notifBtn = document.getElementById('notif-btn');
const notifDropdown = document.getElementById('notif-dropdown');
if (notifBtn && notifDropdown) {
  notifBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    notifDropdown.classList.toggle('hidden');
  });
}

const userMenuBtn = document.getElementById('user-menu-btn');
const userDropdown = document.getElementById('user-dropdown');
if (userMenuBtn && userDropdown) {
  userMenuBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    userDropdown.classList.toggle('hidden');
  });
}

document.addEventListener('click', () => {
  if (notifDropdown) notifDropdown.classList.add('hidden');
  if (userDropdown) userDropdown.classList.add('hidden');
});

// ---------- HELPER ANIMATIONS ---------- //
function animateCounter(elementId, targetValue) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const start = 0;
  const duration = 800;
  const startTime = performance.now();

  function update(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const current = Math.floor(progress * targetValue);
    el.textContent = current.toLocaleString();
    if (progress < 1) {
      requestAnimationFrame(update);
    } else {
      el.textContent = targetValue.toLocaleString();
    }
  }

  requestAnimationFrame(update);
}

// ---------- DASHBOARD STATS ---------- //
async function loadDashboardStats() {
  try {
    const res = await fetch('/api/dashboard/stats');
    if (!res.ok) return;
    const data = await res.json();

    // Update KPI Cards with counter animation
    animateCounter('kpi-accounts', data.accounts_count || 1245);
    animateCounter('kpi-reports', data.reports_count || 87);
    animateCounter('kpi-high-risk', data.high_risk_count || 32);
    animateCounter('kpi-cases', data.active_cases_count || 45);

    // Update Risk Distribution Bars
    const dist = data.risk_distribution || {};
    const counts = dist.counts || { low: 15, medium: 9, high: 5, critical: 3 };
    const pcts = dist.percentages || { low: 45, medium: 28, high: 16, critical: 11 };

    document.getElementById('risk-count-low').textContent = counts.low;
    document.getElementById('risk-count-medium').textContent = counts.medium;
    document.getElementById('risk-count-high').textContent = counts.high;
    document.getElementById('risk-count-critical').textContent = counts.critical;

    document.getElementById('risk-bar-low').style.width = `${pcts.low}%`;
    document.getElementById('risk-bar-medium').style.width = `${pcts.medium}%`;
    document.getElementById('risk-bar-high').style.width = `${pcts.high}%`;
    document.getElementById('risk-bar-critical').style.width = `${pcts.critical}%`;

    // Populate Recent Cases Mini Table
    const recentTbody = document.getElementById('recent-cases-tbody');
    if (recentTbody && data.recent_cases && data.recent_cases.length > 0) {
      recentTbody.innerHTML = '';
      data.recent_cases.forEach((c) => {
        const tr = document.createElement('tr');
        const tierClass = c.tier.toLowerCase();
        tr.innerHTML = `
          <td>#${c.case_id}</td>
          <td>${c.username}</td>
          <td>${c.platform}</td>
          <td><span class="pill ${tierClass}">${c.score} (${c.tier})</span></td>
          <td><span class="status-chip open">${c.status}</span></td>
        `;
        recentTbody.appendChild(tr);
      });
    }
  } catch (err) {
    console.error('Failed to load dashboard stats:', err);
  }
}

// ---------- DETECTION ENGINE & GAUGE ---------- //
function tierClass(score) {
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

function formToPayload() {
  const fd = new FormData(form);
  return {
    username: fd.get('username'),
    display_name: fd.get('display_name'),
    platform: fd.get('platform'),
    account_age_days: fd.get('account_age_days'),
    followers: fd.get('followers'),
    following: fd.get('following'),
    posts_count: fd.get('posts_count'),
    avg_posts_per_day: fd.get('avg_posts_per_day'),
    engagement_rate: fd.get('engagement_rate'),
    bio: fd.get('bio'),
    has_profile_pic: fd.get('has_profile_pic') === 'on',
    account_uses_stock_photo: fd.get('account_uses_stock_photo') === 'on',
    recent_username_changes: fd.get('recent_username_changes'),
  };
}

function renderResult(data) {
  lastAssessment = data;
  resultEmpty.classList.add('hidden');
  resultBody.classList.remove('hidden');

  const tier = tierClass(data.final_score);
  const offset = GAUGE_LENGTH - (GAUGE_LENGTH * Math.min(data.final_score, 100)) / 100;
  gaugeFill.style.strokeDashoffset = offset;
  gaugeFill.style.stroke = tier === 'high' ? 'var(--red)' : tier === 'medium' ? 'var(--amber)' : 'var(--cyan)';

  const angle = -90 + (Math.min(data.final_score, 100) / 100) * 180;
  gaugeNeedle.style.transform = `rotate(${angle}deg)`;

  scoreValue.textContent = Math.round(data.final_score);
  verdictPill.textContent = data.verdict;
  verdictPill.className = `pill ${tier}`;
  confidenceText.textContent = `Confidence: ${data.confidence}`;

  ruleScoreEl.textContent = data.rule_score;
  modelScoreEl.textContent = `${data.model_score.toFixed(1)}%`;

  reasonsList.innerHTML = '';
  reasonsList.className = data.reasons.length ? '' : 'ok';
  if (data.reasons.length === 0) {
    const li = document.createElement('li');
    li.textContent = 'No red-flag signals detected — profile behaviour looks typical.';
    reasonsList.appendChild(li);
  } else {
    data.reasons.forEach((r) => {
      const li = document.createElement('li');
      li.textContent = r;
      reasonsList.appendChild(li);
    });
  }

  reportConfirm.classList.add('hidden');
  if (data.final_score >= 40) {
    reportBtn.classList.remove('hidden');
  } else {
    reportBtn.classList.add('hidden');
  }
}

if (form) {
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = formToPayload();
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      alert('Scan failed — check the input values.');
      return;
    }
    const data = await res.json();
    renderResult(data);
  });
}

if (reportBtn) {
  reportBtn.addEventListener('click', async () => {
    if (!lastAssessment) return;
    reportBtn.disabled = true;
    const res = await fetch('/api/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assessment: lastAssessment }),
    });
    reportBtn.disabled = false;
    if (!res.ok) {
      alert('Could not file the report.');
      return;
    }
    reportConfirm.classList.remove('hidden');
    loadCases();
    loadDashboardStats();
  });
}

// ---------- CASE MANAGEMENT ---------- //
function statusBadgeOptions(current) {
  return [
    'Pending Agency Review',
    'Escalated to Platform',
    'Account Suspended',
    'Dismissed - False Positive',
  ]
    .map((s) => `<option value="${s}" ${s === current ? 'selected' : ''}>${s}</option>`)
    .join('');
}

async function loadCases() {
  const res = await fetch('/api/reports');
  const cases = await res.json();

  const caseTables = [caseTbody, document.getElementById('full-case-tbody')].filter(Boolean);

  caseTables.forEach((tbody) => {
    tbody.innerHTML = '';
    if (cases.length === 0) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="7">No cases filed yet.</td></tr>';
      return;
    }

    cases.forEach((c) => {
      const tr = document.createElement('tr');
      const tier = tierClass(c.final_score);
      const filedDate = new Date(c.reported_at).toLocaleString();
      tr.innerHTML = `
        <td>#${c.case_id}</td>
        <td>${c.username}</td>
        <td>${c.platform}</td>
        <td class="score-tag ${tier}">${Math.round(c.final_score)}</td>
        <td>${c.verdict}</td>
        <td>${filedDate}</td>
        <td>
          <select class="status-select" data-case="${c.case_id}">
            ${statusBadgeOptions(c.status)}
          </select>
        </td>
      `;
      tbody.appendChild(tr);
    });
  });

  document.querySelectorAll('.status-select').forEach((sel) => {
    sel.addEventListener('change', async (e) => {
      const caseId = e.target.getAttribute('data-case');
      await fetch(`/api/reports/${caseId}/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: e.target.value }),
      });
      loadDashboardStats();
    });
  });
}

// ---------- DEMO BUTTON HANDLERS ---------- //
const demoFakeBtn = document.getElementById('demo-fake');
if (demoFakeBtn) {
  demoFakeBtn.addEventListener('click', () => {
    form.username.value = 'xX_free_giftcards_Xx8823';
    form.display_name.value = 'CLICK 4 PRIZE';
    form.platform.value = 'Instagram';
    form.account_age_days.value = 9;
    form.followers.value = 22;
    form.following.value = 4100;
    form.posts_count.value = 1;
    form.avg_posts_per_day.value = 18;
    form.engagement_rate.value = 0.001;
    form.bio.value = '';
    form.has_profile_pic.checked = false;
    form.account_uses_stock_photo.checked = true;
    form.recent_username_changes.value = 3;
  });
}

const demoRealBtn = document.getElementById('demo-real');
if (demoRealBtn) {
  demoRealBtn.addEventListener('click', () => {
    form.username.value = 'priya.mehta.travels';
    form.display_name.value = 'Priya Mehta';
    form.platform.value = 'Instagram';
    form.account_age_days.value = 1450;
    form.followers.value = 3200;
    form.following.value = 610;
    form.posts_count.value = 480;
    form.avg_posts_per_day.value = 0.3;
    form.engagement_rate.value = 0.08;
    form.bio.value = 'Travel + food • Mumbai based • prev. Goa';
    form.has_profile_pic.checked = true;
    form.account_uses_stock_photo.checked = false;
    form.recent_username_changes.value = 0;
  });
}

// INITIALIZATION
loadDashboardStats();
loadCases();
