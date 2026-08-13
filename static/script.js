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

const GAUGE_LENGTH = 314; // approx arc length for the path used
let lastAssessment = null;

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

  // needle sweeps from -90deg (left) to +90deg (right) across the 0-100 range
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
});

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
  caseTbody.innerHTML = '';
  if (cases.length === 0) {
    caseTbody.innerHTML = '<tr class="empty-row"><td colspan="7">No cases filed yet.</td></tr>';
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
    caseTbody.appendChild(tr);
  });

  document.querySelectorAll('.status-select').forEach((sel) => {
    sel.addEventListener('change', async (e) => {
      const caseId = e.target.getAttribute('data-case');
      await fetch(`/api/reports/${caseId}/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: e.target.value }),
      });
    });
  });
}

document.getElementById('demo-fake').addEventListener('click', () => {
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

document.getElementById('demo-real').addEventListener('click', () => {
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

loadCases();
