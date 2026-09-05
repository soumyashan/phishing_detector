/**
 * AegisMail Forensics AI — Reusable UI Components
 * Pure render functions returning HTML strings.
 */

// ── Risk Score Card ────────────────────────────────────────────────
function renderRiskScoreCard(score, level, classification) {
  const levelClass = `level-${level}`;
  const badgeClass = level === 'critical' ? 'badge-critical' :
                     level === 'high' ? 'badge-high' :
                     level === 'medium' ? 'badge-medium' : 'badge-clean';
  const icon = level === 'critical' ? 'fa-skull-crossbones' :
               level === 'high' ? 'fa-triangle-exclamation' :
               level === 'medium' ? 'fa-circle-exclamation' : 'fa-circle-check';

  return `
    <div class="card">
      <div class="risk-score-hero">
        <div style="margin-bottom: 12px;">
          <span class="risk-score-number ${levelClass}">${score}</span>
          <span class="risk-score-denominator">/ 100</span>
        </div>
        <div class="risk-score-bar">
          <div class="risk-score-bar-fill ${levelClass}" style="width: ${score}%"></div>
        </div>
        <div style="margin-top: 14px;">
          <span class="badge ${badgeClass}" style="font-size: 12px; padding: 5px 14px;">
            <i class="fa-solid ${icon}"></i>
            ${classification}
          </span>
        </div>
      </div>
    </div>
  `;
}

// ── Threat Badge ───────────────────────────────────────────────────
function renderBadge(level, text, icon = null) {
  const cls = level === 'critical' ? 'badge-critical' :
              level === 'high' ? 'badge-high' :
              level === 'medium' ? 'badge-medium' :
              level === 'clean' ? 'badge-clean' :
              level === 'info' ? 'badge-info' :
              level === 'demo' ? 'badge-demo' : 'badge-unknown';

  let iconHtml = '';
  let displayText = text;

  if (icon) {
    iconHtml = `<i class="${escapeHtml(icon)}"></i> `;
  } else if (typeof text === 'string' && text.includes('<i class=')) {
    const match = text.match(/<i class="([^"]+)"><\/i>\s*(.*)/);
    if (match) {
      iconHtml = `<i class="${match[1]}"></i> `;
      displayText = match[2];
    }
  }

  return `<span class="badge ${cls}">${iconHtml}${escapeHtml(displayText)}</span>`;
}

// ── Confidence Badge ───────────────────────────────────────────────
function renderConfidenceBadge(confidence) {
  const c = (confidence || 'UNKNOWN').toUpperCase();
  const level = c.includes('HIGH') ? 'clean' :
                c.includes('MEDIUM') ? 'medium' :
                c.includes('LOW') ? 'high' : 'unknown';
  return renderBadge(level, `Confidence: ${c}`);
}

// ── Authentication Card ────────────────────────────────────────────
function renderAuthenticationCard(auth) {
  const items = [
    { key: 'SPF', label: 'Sender Policy Framework', data: auth.spf },
    { key: 'DKIM', label: 'Cryptographic Signature', data: auth.dkim },
    { key: 'DMARC', label: 'Domain Policy Alignment', data: auth.dmarc },
    { key: 'Alignment', label: 'From vs Reply-To', data: auth.alignment }
  ];

  const rows = items.map(item => {
    const status = item.data.status;
    const badgeLevel = (status === 'PASS' || status === 'MATCH' || status === 'ALIGNED') ? 'clean' :
                       (status === 'FAIL' || status === 'MISMATCH') ? 'critical' :
                       (status === 'SOFTFAIL') ? 'high' : 'medium';
    return `
      <div class="auth-row" onclick="this.classList.toggle('expanded')" style="cursor: pointer;" role="button" tabindex="0" aria-label="Toggle ${item.key} details">
        <div style="flex: 1; min-width: 0;">
          <div class="auth-row-label">${item.key} <span style="font-weight: 400; color: var(--text-tertiary); font-size: 11px;">— ${item.label}</span></div>
          <div class="auth-row-note">${escapeHtml(item.data.note)}</div>
          <div class="auth-row-explanation">
            <i class="fa-solid fa-circle-info" style="color: var(--brand-primary); margin-right: 4px;"></i>
            ${escapeHtml(item.data.explanation || '')}
          </div>
        </div>
        <div>
          ${renderBadge(badgeLevel, status)}
        </div>
      </div>
    `;
  }).join('');

  return `
    <div class="card">
      <div class="card-header">
        <div class="card-title"><i class="fa-solid fa-key"></i> Email Authentication</div>
        <span style="font-size: 11px; color: var(--text-muted);">Click to expand details</span>
      </div>
      <div class="card-body-compact space-y-3">${rows}</div>
    </div>
  `;
}

// ── Evidence List (Why this was flagged) ───────────────────────────
function renderEvidenceList(factors) {
  if (!factors || factors.length === 0) {
    return `<div class="card"><div class="card-body"><p class="text-muted text-sm">No specific risk indicators identified.</p></div></div>`;
  }

  const rows = factors.map(f => {
    const weightNum = parseInt(f.weight);
    const isPositive = weightNum > 0;
    const cls = isPositive ? 'positive' : 'negative';
    const prefix = isPositive ? '+' : '';
    return `
      <div class="evidence-row">
        <div class="evidence-row-content">
          <div class="evidence-row-name">${escapeHtml(f.name)}</div>
          <div class="evidence-row-desc">${escapeHtml(f.desc)}</div>
        </div>
        <div class="evidence-weight ${cls}">${prefix}${weightNum}</div>
      </div>
    `;
  }).join('');

  return `
    <div class="card">
      <div class="card-header">
        <div class="card-title"><i class="fa-solid fa-scale-balanced"></i> Why this email was flagged</div>
      </div>
      <div class="card-body-compact">${rows}</div>
    </div>
  `;
}

// ── Email Metadata Summary ─────────────────────────────────────────
function renderEmailMeta(c) {
  const items = [
    { label: 'From', value: c.from },
    { label: 'To', value: c.to },
    { label: 'Reply-To', value: c.replyTo, warn: c.auth?.alignment?.status === 'MISMATCH' },
    { label: 'Subject', value: c.subject },
    { label: 'Date', value: c.date },
    { label: 'Message-ID', value: c.messageId, mono: true },
  ];

  return items.map(item => `
    <div style="display: flex; justify-content: space-between; align-items: flex-start; padding: 6px 0; border-bottom: 1px solid var(--border-subtle);">
      <span style="font-size: 12px; color: var(--text-tertiary); flex-shrink: 0; width: 80px;">${item.label}</span>
      <span style="font-size: 12px; color: ${item.warn ? 'var(--severity-critical-text)' : 'var(--text-primary)'}; text-align: right; word-break: break-all; ${item.mono ? "font-family: 'JetBrains Mono', monospace; font-size: 11px;" : ''}">${escapeHtml(item.value)}</span>
    </div>
  `).join('');
}

// ── Email Body Preview (Safe) ──────────────────────────────────────
function renderEmailPreview(emailBody, urls) {
  const safeBody = escapeHtml(emailBody || 'Email body not available.');
  let urlWarnings = '';
  if (urls && urls.length > 0) {
    const urlItems = urls.filter(u => u.status !== 'SAFE').map(u => `
      <div class="url-warning">
        <i class="fa-solid fa-triangle-exclamation"></i>
        <span>Suspicious URL detected: </span>
        <span class="url-display">${escapeHtml(u.url)}</span>
      </div>
    `).join('');
    if (urlItems) {
      urlWarnings = `<div style="margin-top: 12px;">${urlItems}</div>`;
    }
  }

  return `
    <div class="email-body-preview">${safeBody}</div>
    ${urlWarnings}
  `;
}

// ── NLP Triggers Section ───────────────────────────────────────────
function renderNLPSection(nlp) {
  const tokenHtml = nlp.triggers.length > 0
    ? nlp.triggers.map(t => {
        const cls = t.type === 'critical' ? 'nlp-token-critical' :
                    t.type === 'warning' ? 'nlp-token-warning' : 'nlp-token-info';
        return `<span class="nlp-token ${cls}">${escapeHtml(t.text)}</span>`;
      }).join('')
    : '<span class="text-muted text-sm" style="font-style: italic;">No urgency triggers detected</span>';

  const flagsHtml = nlp.socialEngineeringFlags.map(f =>
    `<li style="display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text-secondary); padding: 3px 0;">
      <i class="fa-solid fa-circle" style="font-size: 5px; color: var(--brand-primary);"></i>
      ${escapeHtml(f)}
    </li>`
  ).join('');

  return `
    <div class="card">
      <div class="card-header">
        <div class="card-title"><i class="fa-solid fa-brain" style="color: var(--accent-purple);"></i> Language & Social Engineering Analysis</div>
      </div>
      <div class="card-body">
        <div class="section-heading" style="margin-bottom: 8px;">
          <i class="fa-solid fa-tags"></i> Detected Trigger Phrases
        </div>
        <div style="display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 16px;">
          ${tokenHtml}
        </div>
        <hr class="divider">
        <div class="section-heading" style="margin-bottom: 8px;">
          <i class="fa-solid fa-user-secret"></i> Social Engineering Indicators
        </div>
        <ul style="list-style: none; padding: 0;">${flagsHtml}</ul>
      </div>
    </div>
  `;
}

// ── URL / Threat Intelligence Cards ────────────────────────────────
function renderURLIntelCards(urls) {
  if (!urls || urls.length === 0) {
    return `
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fa-solid fa-link"></i> URL & Domain Intelligence</div>
        </div>
        <div class="card-body">
          <p class="text-muted text-sm">No URLs were detected in the email body.</p>
        </div>
      </div>
    `;
  }

  const cards = urls.map(u => {
    const statusBadge = u.status === 'MALICIOUS' ? renderBadge('critical', 'MALICIOUS') :
                        u.status === 'SUSPICIOUS' ? renderBadge('medium', 'SUSPICIOUS') :
                        renderBadge('clean', 'SAFE');
    return `
      <div style="padding: 14px; background: var(--bg-elevated); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); margin-bottom: 10px;">
        <div style="display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; margin-bottom: 10px;">
          <div class="url-display" style="flex: 1; min-width: 0;">${escapeHtml(u.url)}</div>
          ${statusBadge}
        </div>
        <div class="meta-grid" style="gap: 8px;">
          <div class="meta-item">
            <div class="meta-label">Domain</div>
            <div class="meta-value mono">${escapeHtml(u.domain)}</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">Domain Age</div>
            <div class="meta-value">${escapeHtml(u.age || 'Unknown')}</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">Hosting IP</div>
            <div class="meta-value mono">${escapeHtml(u.ip || 'Unknown')}</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">Threat Intel</div>
            <div class="meta-value">${escapeHtml(u.vtHits || 'Unavailable')}</div>
          </div>
        </div>
      </div>
    `;
  }).join('');

  return `
    <div class="card">
      <div class="card-header">
        <div class="card-title"><i class="fa-solid fa-link"></i> URL & Domain Intelligence</div>
      </div>
      <div class="card-body-compact">${cards}</div>
    </div>
  `;
}

// ── Infrastructure / Geolocation Card ──────────────────────────────
function renderInfrastructureCard(infra) {
  if (!infra || infra.earliestIp === 'Unknown') {
    return `
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fa-solid fa-server"></i> Infrastructure Attribution</div>
        </div>
        <div class="card-body">
          <p class="text-muted text-sm">No reliable originating IP could be identified.</p>
        </div>
      </div>
    `;
  }

  return `
    <div class="card">
      <div class="card-header">
        <div class="card-title"><i class="fa-solid fa-server"></i> Probable Source Infrastructure</div>
        ${renderConfidenceBadge(infra.confidence)}
      </div>
      <div class="card-body">
        <div class="meta-grid">
          <div class="meta-item">
            <div class="meta-label">Location</div>
            <div class="meta-value"><i class="fa-solid fa-location-dot" style="color: var(--severity-critical); margin-right: 4px;"></i>${escapeHtml(infra.city)}, ${escapeHtml(infra.country)}</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">Earliest Source IP</div>
            <div class="meta-value mono">${escapeHtml(infra.earliestIp)}</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">Hosting / ISP</div>
            <div class="meta-value">${escapeHtml(infra.isp)}</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">Autonomous System</div>
            <div class="meta-value mono">${escapeHtml(infra.asn)}</div>
          </div>
        </div>
        <div class="alert alert-warning" style="margin-top: 14px;">
          <i class="fa-solid fa-triangle-exclamation"></i>
          <div>
            <strong>Forensic Attribution Note:</strong>
            ${escapeHtml(infra.caveat)}
          </div>
        </div>
      </div>
    </div>
  `;
}

// ── Campaign Summary Card ──────────────────────────────────────────
function renderCampaignSummary(campaign) {
  if (!campaign || campaign.relatedEmailsCount === 0) {
    return `
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fa-solid fa-diagram-project" style="color: var(--accent-purple);"></i> Campaign Correlation</div>
        </div>
        <div class="card-body">
          <p class="text-muted text-sm">No related campaign activity detected. Campaign correlation requires multiple analyzed emails sharing common infrastructure.</p>
        </div>
      </div>
    `;
  }

  const domainsHtml = campaign.relatedDomains.map(d =>
    `<span class="badge badge-info" style="margin: 2px;">${escapeHtml(d)}</span>`
  ).join('');

  return `
    <div class="card">
      <div class="card-header">
        <div class="card-title"><i class="fa-solid fa-diagram-project" style="color: var(--accent-purple);"></i> Potentially Related Campaign</div>
        <span class="badge badge-demo" style="font-size: 10px;">${escapeHtml(campaign.clusterId)}</span>
      </div>
      <div class="card-body">
        <div class="meta-grid" style="margin-bottom: 14px;">
          <div class="meta-item">
            <div class="meta-label">Campaign Name</div>
            <div class="meta-value">${escapeHtml(campaign.name)}</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">Related Emails</div>
            <div class="meta-value">${campaign.relatedEmailsCount}</div>
          </div>
          <div class="meta-item">
            <div class="meta-label">Threat Actor Pattern</div>
            <div class="meta-value">${escapeHtml(campaign.threatActorType)}</div>
          </div>
        </div>
        <div style="margin-bottom: 10px;">
          <div class="meta-label" style="margin-bottom: 6px;">Related Domains</div>
          <div style="display: flex; flex-wrap: wrap; gap: 4px;">${domainsHtml}</div>
        </div>
        ${campaign.groupingReason ? `
          <div class="alert alert-info" style="margin-top: 10px;">
            <i class="fa-solid fa-circle-info"></i>
            <div><strong>Grouping Reason:</strong> ${escapeHtml(campaign.groupingReason)}</div>
          </div>
        ` : ''}
      </div>
    </div>
  `;
}

// ── Investigation Table Row ────────────────────────────────────────
function renderInvestigationRow(inv) {
  const badgeLevel = inv.riskLevel === 'critical' ? 'critical' :
                     inv.riskLevel === 'high' ? 'high' :
                     inv.riskLevel === 'medium' ? 'medium' : 'clean';
  const icon = inv.riskLevel === 'critical' ? 'fa-skull-crossbones' :
               inv.riskLevel === 'high' ? 'fa-triangle-exclamation' :
               inv.riskLevel === 'medium' ? 'fa-circle-exclamation' : 'fa-circle-check';

  return `
    <tr onclick="navigateTo('investigation/${inv.id}')" role="link" tabindex="0" aria-label="View investigation ${inv.id}">
      <td class="mono" style="font-size: 11px; color: var(--text-muted);">${escapeHtml(inv.id)}</td>
      <td class="text-primary truncate">${escapeHtml(inv.from)}</td>
      <td class="truncate">${escapeHtml(inv.subject)}</td>
      <td>${renderBadge(badgeLevel, '<i class="fa-solid ' + icon + '"></i> ' + inv.classification)}</td>
      <td class="mono" style="font-weight: 700;">${inv.riskScore}</td>
      <td style="font-size: 12px; color: var(--text-muted);">${formatDate(inv.date)}</td>
      ${inv.isDemo ? '<td>' + renderBadge('demo', 'DEMO') + '</td>' : '<td></td>'}
    </tr>
  `;
}

// ── Empty State ────────────────────────────────────────────────────
function renderEmptyState(icon, title, description, actionText, actionRoute) {
  const actionBtn = actionText && actionRoute
    ? `<button class="btn btn-primary" onclick="navigateTo('${actionRoute}')"><i class="fa-solid fa-plus"></i> ${escapeHtml(actionText)}</button>`
    : '';
  return `
    <div class="empty-state">
      <div class="empty-state-icon"><i class="fa-solid ${icon}"></i></div>
      <div class="empty-state-title">${escapeHtml(title)}</div>
      <div class="empty-state-desc">${escapeHtml(description)}</div>
      ${actionBtn}
    </div>
  `;
}

// ── Error State ────────────────────────────────────────────────────
function renderErrorState(title, description, retryAction) {
  const retryBtn = retryAction
    ? `<button class="btn btn-secondary" onclick="${retryAction}"><i class="fa-solid fa-rotate-right"></i> Try Again</button>`
    : '';
  return `
    <div class="empty-state">
      <div class="empty-state-icon" style="color: var(--severity-critical);"><i class="fa-solid fa-circle-xmark"></i></div>
      <div class="empty-state-title">${escapeHtml(title)}</div>
      <div class="empty-state-desc">${escapeHtml(description)}</div>
      ${retryBtn}
    </div>
  `;
}

// ── Warning Banner ─────────────────────────────────────────────────
function renderWarnings(warnings) {
  if (!warnings || warnings.length === 0) return '';
  return warnings.map(w => `
    <div class="alert alert-warning" style="margin-bottom: 8px;">
      <i class="fa-solid fa-triangle-exclamation"></i>
      <span>${escapeHtml(w)}</span>
    </div>
  `).join('');
}

// ── Helpers ─────────────────────────────────────────────────────────
function formatDate(dateStr) {
  if (!dateStr) return '—';
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr;
    return d.toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' });
  } catch {
    return dateStr;
  }
}

function getRiskLabel(level) {
  switch(level) {
    case 'critical': return 'CRITICAL';
    case 'high': return 'HIGH RISK';
    case 'medium': return 'SUSPICIOUS';
    case 'clean': return 'LOW RISK';
    default: return 'UNKNOWN';
  }
}

function getRiskIcon(level) {
  switch(level) {
    case 'critical': return 'fa-skull-crossbones';
    case 'high': return 'fa-triangle-exclamation';
    case 'medium': return 'fa-circle-exclamation';
    case 'clean': return 'fa-circle-check';
    default: return 'fa-question';
  }
}
