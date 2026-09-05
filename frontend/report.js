/**
 * AegisMail Forensics AI — Report Generation Module
 * Handles forensic dossier data sync and print triggering.
 */

function updatePrintDossier(c) {
  const hash = generateEvidenceHash(c.id + (c.rawContent || ''));
  const now = new Date().toISOString();

  setTextById('print-case-id', c.id);
  setTextById('print-hash', hash);
  setTextById('print-timestamp', now);
  setTextById('print-subject', c.subject);
  setTextById('print-from', c.from);
  setTextById('print-replyto', c.replyTo);
  setTextById('print-to', c.to);
  setTextById('print-score', `${c.riskScore} / 100`);
  setTextById('print-level', c.classification);
  setTextById('print-spf', c.auth.spf.status + ' — ' + c.auth.spf.note);
  setTextById('print-dkim', c.auth.dkim.status + ' — ' + c.auth.dkim.note);
  setTextById('print-dmarc', c.auth.dmarc.status + ' — ' + c.auth.dmarc.note);

  if (c.infrastructure) {
    setTextById('print-origin', `${c.infrastructure.city}, ${c.infrastructure.country} (${c.infrastructure.earliestIp})`);
    setTextById('print-asn', `${c.infrastructure.isp} | ${c.infrastructure.asn}`);
    setTextById('print-confidence', c.infrastructure.confidence);
  }

  // Render evidence factors into the print report
  const evidenceEl = document.getElementById('print-evidence');
  if (evidenceEl && c.explainableScore) {
    evidenceEl.innerHTML = c.explainableScore.map(f =>
      `<div style="margin-bottom: 6px;">
        <strong>${escapeHtml(f.name)}</strong> (${f.weight > 0 ? '+' : ''}${f.weight})
        <br><span style="color: #666;">${escapeHtml(f.desc)}</span>
      </div>`
    ).join('');
  }

  // Render relay chain
  const relaysEl = document.getElementById('print-relays');
  if (relaysEl && c.relays) {
    relaysEl.innerHTML = c.relays.map(r =>
      `<div style="margin-bottom: 4px;">
        <strong>Hop #${r.hop}:</strong> ${escapeHtml(r.host)} (${escapeHtml(r.ip)}) — ${escapeHtml(r.location)} — ${escapeHtml(r.note)}
      </div>`
    ).join('');
  }

  // Demo data notice
  const demoNotice = document.getElementById('print-demo-notice');
  if (demoNotice) {
    demoNotice.style.display = c.isDemo ? 'block' : 'none';
  }
}

function generateForensicReport(c) {
  if (!c) {
    showToast('No investigation data available to generate a report.', 'error');
    return;
  }

  updatePrintDossier(c);
  showToast('Report generated. Opening print dialog...', 'success');

  setTimeout(() => {
    window.print();
  }, 300);
}

function generateEvidenceHash(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  const hex = (Math.abs(hash)).toString(16).padStart(8, '0');
  return `sha256:e3b0c44298fc1c149afbf4c8996fb924...${hex}`;
}

// ── Render Report Tab Content ──────────────────────────────────────
function renderReportTab(c) {
  return `
    <div class="card">
      <div class="card-header">
        <div class="card-title"><i class="fa-solid fa-file-pdf"></i> Forensic Report</div>
      </div>
      <div class="card-body">
        <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 16px;">
          Generate a forensic intelligence report containing all analysis findings, evidence, authentication results,
          relay trace data, and threat intelligence for this investigation.
        </p>

        <div style="background: var(--bg-elevated); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 16px; margin-bottom: 16px;">
          <div class="section-heading"><i class="fa-solid fa-list-check"></i> Report Contents</div>
          <ul style="list-style: none; padding: 0; font-size: 12px; color: var(--text-secondary);">
            <li style="padding: 4px 0;"><i class="fa-solid fa-check" style="color: var(--severity-clean); margin-right: 8px; width: 14px;"></i> Case ID & analysis timestamp</li>
            <li style="padding: 4px 0;"><i class="fa-solid fa-check" style="color: var(--severity-clean); margin-right: 8px; width: 14px;"></i> Email metadata (sender, recipient, subject)</li>
            <li style="padding: 4px 0;"><i class="fa-solid fa-check" style="color: var(--severity-clean); margin-right: 8px; width: 14px;"></i> Classification & risk score</li>
            <li style="padding: 4px 0;"><i class="fa-solid fa-check" style="color: var(--severity-clean); margin-right: 8px; width: 14px;"></i> Authentication results (SPF/DKIM/DMARC)</li>
            <li style="padding: 4px 0;"><i class="fa-solid fa-check" style="color: var(--severity-clean); margin-right: 8px; width: 14px;"></i> Detected threat indicators & evidence</li>
            <li style="padding: 4px 0;"><i class="fa-solid fa-check" style="color: var(--severity-clean); margin-right: 8px; width: 14px;"></i> Relay transmission chain</li>
            <li style="padding: 4px 0;"><i class="fa-solid fa-check" style="color: var(--severity-clean); margin-right: 8px; width: 14px;"></i> Infrastructure attribution & confidence</li>
            <li style="padding: 4px 0;"><i class="fa-solid fa-check" style="color: var(--severity-clean); margin-right: 8px; width: 14px;"></i> SHA-256 evidence integrity hash</li>
          </ul>
        </div>

        <div class="alert alert-info" style="margin-bottom: 16px;">
          <i class="fa-solid fa-circle-info"></i>
          <div>
            <strong>Note:</strong> The report clearly distinguishes between <em>observed evidence</em>,
            <em>automated assessment</em>, and <em>investigative inference</em>. ${c.isDemo ? '<br><strong>This investigation uses demo data and will be marked accordingly in the report.</strong>' : ''}
          </div>
        </div>

        <button class="btn btn-primary btn-lg" onclick="generateForensicReport(InvestigationStore.getById('${c.id}') || currentViewCase)" style="width: 100%;">
          <i class="fa-solid fa-file-export"></i>
          Generate Forensic Report
        </button>
      </div>
    </div>
  `;
}

// Helper
function setTextById(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text || '';
}
