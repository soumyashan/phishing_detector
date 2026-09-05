/**
 * AegisMail Forensics AI — Page Renderers
 * Each function renders a full page into #app-content.
 */

let currentViewCase = null; // Currently viewed investigation

// ── Dashboard ──────────────────────────────────────────────────────
function renderDashboard() {
  const stats = InvestigationStore.getStats();
  const investigations = InvestigationStore.getAll();

  let tableContent;
  if (investigations.length === 0) {
    tableContent = renderEmptyState(
      'fa-magnifying-glass-chart',
      'No investigations yet',
      'Upload a suspicious email to start your first investigation.',
      'Analyze Email',
      'analyze'
    );
  } else {
    const rows = investigations.slice(0, 10).map(inv => renderInvestigationRow(inv)).join('');
    tableContent = `
      <div class="table-wrapper">
        <table class="data-table">
          <thead>
            <tr>
              <th>Case ID</th>
              <th>Sender</th>
              <th>Subject</th>
              <th>Classification</th>
              <th>Score</th>
              <th>Date</th>
              <th></th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      ${investigations.length > 10 ? `
        <div class="card-footer" style="text-align: center;">
          <button class="btn btn-ghost btn-sm" onclick="navigateTo('investigations')">View All Investigations</button>
        </div>
      ` : ''}
    `;
  }

  return `
    <div class="animate-fade-in">
      <!-- Hero / Value Proposition -->
      <div style="margin-bottom: 28px;">
        <h2 style="font-size: 22px; font-weight: 700; color: var(--text-primary); margin-bottom: 4px;">
          Investigate Suspicious Emails
        </h2>
        <p style="font-size: 14px; color: var(--text-tertiary); max-width: 560px;">
          AI-powered threat detection, header forensics, infrastructure tracing, and campaign correlation — in one platform.
        </p>
      </div>

      <!-- Quick Action -->
      <div style="margin-bottom: 24px;">
        <button class="btn btn-primary btn-lg" onclick="navigateTo('analyze')">
          <i class="fa-solid fa-plus"></i> Analyze an Email
        </button>
      </div>

      <!-- Stats -->
      <div class="stat-grid" style="margin-bottom: 24px;">
        <div class="stat-card">
          <div class="stat-card-label">Emails Analyzed</div>
          <div class="stat-card-value">${stats.total}</div>
        </div>
        <div class="stat-card">
          <div class="stat-card-label">Critical / High Risk</div>
          <div class="stat-card-value" style="color: var(--severity-critical);">${stats.critical + stats.high}</div>
        </div>
        <div class="stat-card">
          <div class="stat-card-label">Suspicious</div>
          <div class="stat-card-value" style="color: var(--severity-medium);">${stats.suspicious}</div>
        </div>
        <div class="stat-card">
          <div class="stat-card-label">Clean / Legitimate</div>
          <div class="stat-card-value" style="color: var(--severity-clean);">${stats.clean}</div>
        </div>
      </div>

      <!-- Workflow -->
      <div class="card" style="margin-bottom: 24px;">
        <div class="card-body" style="display: flex; align-items: center; justify-content: center; gap: 12px; flex-wrap: wrap; padding: 16px 20px;">
          ${['Detect', 'Analyze', 'Trace', 'Correlate', 'Report'].map((step, i) => `
            <span style="font-size: 12px; font-weight: 600; color: var(--brand-primary); background: var(--brand-primary-muted); padding: 5px 14px; border-radius: var(--radius-full);">
              ${step}
            </span>
            ${i < 4 ? '<i class="fa-solid fa-arrow-right" style="color: var(--text-muted); font-size: 10px;"></i>' : ''}
          `).join('')}
        </div>
      </div>

      <!-- Recent Investigations -->
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fa-solid fa-clock-rotate-left"></i> Recent Investigations</div>
          ${investigations.length > 0 ? `<button class="btn btn-ghost btn-sm" onclick="navigateTo('investigations')">View All</button>` : ''}
        </div>
        ${tableContent}
      </div>
    </div>
  `;
}

// ── Analyze Email Page ─────────────────────────────────────────────
function renderAnalyzePage() {
  const presetCards = Object.entries(PRESET_SAMPLES).map(([key, sample]) => {
    const badgeLevel = sample.riskLevel === 'critical' ? 'critical' :
                       sample.riskLevel === 'high' ? 'high' :
                       sample.riskLevel === 'medium' ? 'medium' : 'clean';
    return `
      <button class="preset-card" onclick="loadPresetSample('${key}')" aria-label="Load ${escapeHtml(sample.title)} sample">
        <div class="preset-card-header">
          <span class="preset-card-name">${escapeHtml(sample.title)}</span>
          ${renderBadge(badgeLevel, sample.riskScore + '/100')}
        </div>
        <div class="preset-card-desc">${escapeHtml(sample.classification)}</div>
      </button>
    `;
  }).join('');

  return `
    <div class="animate-fade-in">
      <div style="margin-bottom: 24px;">
        <h2 style="font-size: 20px; font-weight: 700; color: var(--text-primary); margin-bottom: 4px;">
          Analyze Email
        </h2>
        <p style="font-size: 13px; color: var(--text-tertiary);">
          Upload a suspicious email to analyze its content, headers, authentication, links, and transmission path.
        </p>
      </div>

      <!-- Upload Area -->
      <div class="card" style="margin-bottom: 20px;">
        <div class="card-body">
          <div id="upload-zone" class="upload-zone" role="button" tabindex="0" aria-label="Upload email file">
            <div class="upload-zone-icon"><i class="fa-solid fa-cloud-arrow-up"></i></div>
            <div class="upload-zone-title">
              Drag & drop an email file here, or <span style="color: var(--brand-primary);">browse files</span>
            </div>
            <div class="upload-zone-sub">Supported formats: .eml, .txt</div>
            <div class="upload-zone-hint">Maximum file size: 10 MB</div>
            <input type="file" id="eml-file-input" accept=".eml,.txt" style="display: none;">
          </div>

          <div style="display: flex; align-items: center; gap: 16px; margin: 16px 0;">
            <hr style="flex: 1; border: none; border-top: 1px solid var(--border-subtle);">
            <span style="font-size: 12px; color: var(--text-muted); font-weight: 500;">OR</span>
            <hr style="flex: 1; border: none; border-top: 1px solid var(--border-subtle);">
          </div>

          <div>
            <label style="font-size: 13px; font-weight: 500; color: var(--text-secondary); display: block; margin-bottom: 6px;">
              Paste raw email headers & content
            </label>
            <textarea id="raw-eml-textarea" class="form-input" rows="6"
              placeholder="Paste full RFC-822 email headers here..."></textarea>
          </div>

          <div style="margin-top: 14px; display: flex; gap: 10px;">
            <button id="analyze-btn" class="btn btn-primary">
              <i class="fa-solid fa-magnifying-glass-chart"></i> Analyze Email
            </button>
            <button id="clear-btn" class="btn btn-secondary" onclick="document.getElementById('raw-eml-textarea').value=''; document.getElementById('eml-file-input').value='';">
              <i class="fa-solid fa-eraser"></i> Clear
            </button>
          </div>

          <div id="upload-error" style="margin-top: 12px; display: none;"></div>
        </div>
      </div>

      <!-- Demo Samples -->
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fa-solid fa-flask-vial"></i> Demo Test Cases</div>
          ${renderBadge('demo', 'DEMO DATA')}
        </div>
        <div class="card-body">
          <p style="font-size: 12px; color: var(--text-tertiary); margin-bottom: 12px;">
            Select a pre-loaded sample to see the platform in action. Demo data is clearly labeled in results.
          </p>
          <div class="preset-grid">${presetCards}</div>
        </div>
      </div>
    </div>
  `;
}

// ── Analysis Results Page (Tabbed Investigation Detail) ────────────
function renderAnalysisResults(caseId) {
  const c = InvestigationStore.getById(caseId);
  if (!c) {
    return renderErrorState(
      'Investigation not found',
      "The requested investigation couldn't be loaded. It may have been removed or the ID is invalid.",
      "navigateTo('investigations')"
    );
  }

  currentViewCase = c;
  const activeTab = AppState.currentResultTab || 'overview';

  const tabs = [
    { id: 'overview', label: 'Overview', icon: 'fa-gauge-high' },
    { id: 'email', label: 'Email', icon: 'fa-envelope' },
    { id: 'headers', label: 'Headers', icon: 'fa-key' },
    { id: 'trace', label: 'Trace & Map', icon: 'fa-route' },
    { id: 'intelligence', label: 'Intelligence', icon: 'fa-shield-halved' },
    { id: 'campaign', label: 'Campaign', icon: 'fa-diagram-project' },
    { id: 'report', label: 'Report', icon: 'fa-file-pdf' },
  ];

  const tabButtons = tabs.map(t => `
    <button class="tab-btn ${activeTab === t.id ? 'active' : ''}"
      onclick="switchResultTab('${t.id}', '${caseId}')"
      aria-label="${t.label}" role="tab" aria-selected="${activeTab === t.id}">
      <i class="fa-solid ${t.icon}" style="margin-right: 4px; font-size: 12px;"></i>
      ${t.label}
    </button>
  `).join('');

  let tabContent = '';
  switch (activeTab) {
    case 'overview': tabContent = renderOverviewTab(c); break;
    case 'email': tabContent = renderEmailTab(c); break;
    case 'headers': tabContent = renderHeadersTab(c); break;
    case 'trace': tabContent = renderTraceTab(c); break;
    case 'intelligence': tabContent = renderIntelligenceTab(c); break;
    case 'campaign': tabContent = renderCampaignTab(c); break;
    case 'report': tabContent = renderReportTab(c); break;
    default: tabContent = renderOverviewTab(c);
  }

  return `
    <div class="animate-fade-in">
      <!-- Investigation Header -->
      <div style="display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; margin-bottom: 16px; flex-wrap: wrap;">
        <div>
          <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 4px;">
            <button class="btn btn-ghost btn-sm" onclick="navigateTo('investigations')" style="padding: 4px 8px;">
              <i class="fa-solid fa-arrow-left"></i>
            </button>
            <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary);">
              Investigation ${escapeHtml(c.id)}
            </h2>
            ${c.isDemo ? renderBadge('demo', 'DEMO DATA') : ''}
          </div>
          <p style="font-size: 12px; color: var(--text-tertiary); margin-left: 40px;" class="truncate">
            ${escapeHtml(c.subject)}
          </p>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
          ${renderBadge(c.riskLevel, '<i class="fa-solid ' + getRiskIcon(c.riskLevel) + '"></i> ' + c.classification + ' — ' + c.riskScore + '/100')}
        </div>
      </div>

      ${renderWarnings(c.warnings)}

      <!-- Tabs -->
      <div class="tabs" style="margin-bottom: 20px;" role="tablist">
        ${tabButtons}
      </div>

      <!-- Tab Content -->
      <div role="tabpanel">
        ${tabContent}
      </div>
    </div>
  `;
}

// ── Overview Tab ───────────────────────────────────────────────────
function renderOverviewTab(c) {
  return `
    <div class="grid-sidebar">
      <div class="space-y-4">
        ${renderRiskScoreCard(c.riskScore, c.riskLevel, c.classification)}
        ${renderAIAnalysisCard(c.aiAnalysis)}

        <div class="card">
          <div class="card-header">
            <div class="card-title">
              <i class="fa-solid fa-envelope-open-text"></i>
              Email Details
            </div>
          </div>
          <div class="card-body-compact">
            ${renderEmailMeta(c)}
          </div>
        </div>
      </div>

      <div class="space-y-4">
        ${renderEvidenceList(c.explainableScore)}
        ${renderNLPSection(c.nlp)}
      </div>
    </div>
  `;
}
// ── Email Tab ──────────────────────────────────────────────────────
function renderEmailTab(c) {
  return `
    <div class="space-y-4">
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fa-solid fa-envelope"></i> Email Content</div>
          <span style="font-size: 11px; color: var(--text-muted);">Content rendered as plain text for safety</span>
        </div>
        <div class="card-body">
          ${renderEmailPreview(c.emailBody, c.urls)}
        </div>
      </div>
      ${renderURLIntelCards(c.urls)}
    </div>
  `;
}

// ── Headers Tab ────────────────────────────────────────────────────
function renderHeadersTab(c) {
  return `
    <div class="space-y-4">
      ${renderAuthenticationCard(c.auth)}
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fa-solid fa-code"></i> Raw Email Headers</div>
          <button class="btn btn-ghost btn-sm" onclick="copyRawHeaders()">
            <i class="fa-solid fa-copy"></i> Copy
          </button>
        </div>
        <div class="card-body-compact">
          <div class="raw-headers-view" id="raw-headers-content">${escapeHtml(c.rawContent || 'Raw headers not available.')}</div>
        </div>
      </div>
    </div>
  `;
}

// ── Trace Tab ──────────────────────────────────────────────────────
function renderTraceTab(c) {
  const hasRelays = c.relays && c.relays.length > 0;
  const hasGeoData = hasRelays && c.relays.some(r => r.lat && r.lng && (r.lat !== 0 || r.lng !== 0));

  const hopsHtml = hasRelays ? `
    <div class="hop-timeline">
      ${c.relays.map((hop, idx) => `
        <div class="hop-item">
          <div class="hop-dot"></div>
          <div class="hop-content">
            <div class="hop-header">
              <span class="hop-host">Hop #${hop.hop}: ${escapeHtml(hop.host)}</span>
              <span class="hop-ip">${escapeHtml(hop.ip)}</span>
            </div>
            <div class="hop-details">
              <div class="hop-detail-item"><strong>Location:</strong> ${escapeHtml(hop.location)}</div>
              <div class="hop-detail-item"><strong>ISP:</strong> ${escapeHtml(hop.isp)}</div>
              <div class="hop-detail-item"><strong>Role:</strong> ${escapeHtml(hop.note)}</div>
            </div>
          </div>
        </div>
      `).join('')}
    </div>
  ` : '<p class="text-muted text-sm">No relay hops could be extracted from the email headers.</p>';

  return `
    <div class="space-y-4">
      ${renderInfrastructureCard(c.infrastructure)}

      <div class="${hasGeoData ? 'grid-2' : ''}" style="gap: 20px;">
        ${hasGeoData ? `
          <div class="card">
            <div class="card-header">
              <div class="card-title"><i class="fa-solid fa-earth-americas"></i> Transmission Route Map</div>
            </div>
            <div class="card-body-compact">
              <div id="geolocation-map" class="map-container"></div>
            </div>
          </div>
        ` : ''}
        <div class="card">
          <div class="card-header">
            <div class="card-title"><i class="fa-solid fa-server"></i> Relay Hop Chain</div>
            <span style="font-size: 11px; color: var(--text-muted);">Earliest → Recipient</span>
          </div>
          <div class="card-body">
            ${hopsHtml}
          </div>
        </div>
      </div>
    </div>
  `;
}

// ── Intelligence Tab ───────────────────────────────────────────────
function renderIntelligenceTab(c) {
  return `
    <div class="space-y-4">
      ${renderURLIntelCards(c.urls)}
      ${renderInfrastructureCard(c.infrastructure)}
      ${renderNLPSection(c.nlp)}
    </div>
  `;
}

// ── Campaign Tab ───────────────────────────────────────────────────
function renderCampaignTab(c) {
  const hasGraph = c.campaign && c.campaign.relatedEmailsCount > 0;

  return `
    <div class="space-y-4">
      ${renderCampaignSummary(c.campaign)}
      ${hasGraph ? `
        <div class="card">
          <div class="card-header">
            <div class="card-title"><i class="fa-solid fa-diagram-project" style="color: var(--accent-purple);"></i> Infrastructure Relationship Graph</div>
          </div>
          <div class="card-body-compact">
            <div class="graph-container">
              <canvas id="campaign-graph-canvas"></canvas>
              <div class="graph-legend">
                <div class="graph-legend-item"><div class="graph-legend-dot" style="background: #3B82F6;"></div> IP Address</div>
                <div class="graph-legend-item"><div class="graph-legend-dot" style="background: #10B981;"></div> Linked Domains</div>
                <div class="graph-legend-item"><div class="graph-legend-dot" style="background: #F59E0B;"></div> Email Telemetry</div>
                <div class="graph-legend-item"><div class="graph-legend-dot" style="background: #EC4899;"></div> Campaign Cluster</div>
              </div>
            </div>
          </div>
        </div>
      ` : ''}
    </div>
  `;
}

// ── Investigations List Page ───────────────────────────────────────
function renderInvestigationsPage() {
  const investigations = InvestigationStore.getAll();

  if (investigations.length === 0) {
    return `
      <div class="animate-fade-in">
        <h2 style="font-size: 20px; font-weight: 700; color: var(--text-primary); margin-bottom: 20px;">Investigations</h2>
        <div class="card">
          ${renderEmptyState(
            'fa-folder-open',
            'No investigations yet',
            'Upload a suspicious email to start your first investigation.',
            'Analyze Email',
            'analyze'
          )}
        </div>
      </div>
    `;
  }

  const rows = investigations.map(inv => renderInvestigationRow(inv)).join('');

  return `
    <div class="animate-fade-in">
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; flex-wrap: wrap; gap: 12px;">
        <h2 style="font-size: 20px; font-weight: 700; color: var(--text-primary);">Investigations</h2>
        <button class="btn btn-primary" onclick="navigateTo('analyze')">
          <i class="fa-solid fa-plus"></i> New Analysis
        </button>
      </div>

      <div class="card" style="margin-bottom: 16px;">
        <div class="card-body-compact">
          <div class="search-input-wrapper">
            <i class="fa-solid fa-magnifying-glass"></i>
            <input type="text" class="form-input" placeholder="Search by sender, domain, IP, subject, or case ID..."
              id="investigation-search" oninput="filterInvestigations(this.value)">
          </div>
        </div>
      </div>

      <div class="filter-bar">
        <button class="filter-chip active" onclick="filterByLevel('all', this)">All (${investigations.length})</button>
        <button class="filter-chip" onclick="filterByLevel('critical', this)">Critical</button>
        <button class="filter-chip" onclick="filterByLevel('high', this)">High Risk</button>
        <button class="filter-chip" onclick="filterByLevel('medium', this)">Suspicious</button>
        <button class="filter-chip" onclick="filterByLevel('clean', this)">Clean</button>
      </div>

      <div class="card">
        <div class="table-wrapper" id="investigations-table">
          <table class="data-table">
            <thead>
              <tr>
                <th>Case ID</th>
                <th>Sender</th>
                <th>Subject</th>
                <th>Classification</th>
                <th>Score</th>
                <th>Date</th>
                <th></th>
              </tr>
            </thead>
            <tbody id="investigations-tbody">${rows}</tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

// ── Campaigns Page ─────────────────────────────────────────────────
function renderCampaignsPage() {
  const investigations = InvestigationStore.getAll();
  const campaigns = {};

  investigations.forEach(inv => {
    if (inv.campaign && inv.campaign.clusterId && inv.campaign.clusterId !== 'N/A') {
      if (!campaigns[inv.campaign.clusterId]) {
        campaigns[inv.campaign.clusterId] = {
          ...inv.campaign,
          investigations: []
        };
      }
      campaigns[inv.campaign.clusterId].investigations.push(inv);
    }
  });

  const campaignList = Object.values(campaigns);

  if (campaignList.length === 0) {
    return `
      <div class="animate-fade-in">
        <h2 style="font-size: 20px; font-weight: 700; color: var(--text-primary); margin-bottom: 20px;">Campaigns</h2>
        <div class="card">
          ${renderEmptyState(
            'fa-diagram-project',
            'No campaigns detected',
            'Campaign correlation discovers shared infrastructure across multiple analyzed emails. Analyze more emails to detect patterns.',
            'Analyze Email',
            'analyze'
          )}
        </div>
      </div>
    `;
  }

  const cards = campaignList.map(camp => `
    <div class="card" style="margin-bottom: 12px;">
      <div class="card-body">
        <div style="display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; margin-bottom: 8px;">
          <div>
            <div style="font-size: 14px; font-weight: 600; color: var(--text-primary);">${escapeHtml(camp.name)}</div>
            <div style="font-size: 11px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">${escapeHtml(camp.clusterId)}</div>
          </div>
          ${renderBadge('info', camp.investigations.length + ' related email(s)')}
        </div>
        <div style="font-size: 12px; color: var(--text-tertiary);">${escapeHtml(camp.threatActorType)}</div>
      </div>
    </div>
  `).join('');

  return `
    <div class="animate-fade-in">
      <h2 style="font-size: 20px; font-weight: 700; color: var(--text-primary); margin-bottom: 20px;">Campaigns</h2>
      ${cards}
    </div>
  `;
}

// ── Threat Intelligence Page ───────────────────────────────────────
function renderIntelligencePage() {
  return `
    <div class="animate-fade-in">
      <h2 style="font-size: 20px; font-weight: 700; color: var(--text-primary); margin-bottom: 20px;">Threat Intelligence</h2>
      <div class="card">
        <div class="coming-soon">
          <i class="fa-solid fa-shield-halved"></i>
          <h3>Threat Intelligence Search</h3>
          <p>Search and inspect IP addresses, domains, and other indicators of compromise. This feature will integrate with AbuseIPDB, VirusTotal, and PhishTank APIs.</p>
          <div style="margin-top: 16px;">
            ${renderBadge('info', 'Coming Soon')}
          </div>
        </div>
      </div>
    </div>
  `;
}

// ── Reports Page ───────────────────────────────────────────────────
function renderReportsPage() {
  const investigations = InvestigationStore.getAll();

  if (investigations.length === 0) {
    return `
      <div class="animate-fade-in">
        <h2 style="font-size: 20px; font-weight: 700; color: var(--text-primary); margin-bottom: 20px;">Reports</h2>
        <div class="card">
          ${renderEmptyState(
            'fa-file-pdf',
            'No reports available',
            'Analyze an email first, then generate a forensic report from the investigation detail view.',
            'Analyze Email',
            'analyze'
          )}
        </div>
      </div>
    `;
  }

  const rows = investigations.map(inv => `
    <tr>
      <td class="mono" style="font-size: 11px;">${escapeHtml(inv.id)}</td>
      <td class="text-primary truncate">${escapeHtml(inv.subject)}</td>
      <td>${renderBadge(inv.riskLevel, inv.classification)}</td>
      <td style="font-size: 12px; color: var(--text-muted);">${formatDate(inv.date)}</td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="navigateTo('investigation/${inv.id}'); setTimeout(()=>switchResultTab('report','${inv.id}'),100);">
          <i class="fa-solid fa-file-export"></i> Generate
        </button>
      </td>
    </tr>
  `).join('');

  return `
    <div class="animate-fade-in">
      <h2 style="font-size: 20px; font-weight: 700; color: var(--text-primary); margin-bottom: 20px;">Reports</h2>
      <div class="card">
        <div class="table-wrapper">
          <table class="data-table">
            <thead>
              <tr>
                <th>Case ID</th>
                <th>Subject</th>
                <th>Classification</th>
                <th>Date</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

// ── Settings Page ──────────────────────────────────────────────────
function renderSettingsPage() {
  return `
    <div class="animate-fade-in">
      <h2 style="font-size: 20px; font-weight: 700; color: var(--text-primary); margin-bottom: 20px;">Settings</h2>

      <div class="card" style="margin-bottom: 16px;">
        <div class="card-header">
          <div class="card-title"><i class="fa-solid fa-shield-halved"></i> Privacy & Data Handling</div>
        </div>
        <div class="card-body">
          <div class="alert alert-info">
            <i class="fa-solid fa-circle-info"></i>
            <div>
              Uploaded email data is processed locally in your browser. No email content is transmitted to external servers unless
              explicitly configured with threat intelligence API integrations.
            </div>
          </div>
        </div>
      </div>

      <div class="card" style="margin-bottom: 16px;">
        <div class="card-header">
          <div class="card-title"><i class="fa-solid fa-plug-circle-bolt"></i> API Configuration</div>
        </div>
        <div class="card-body">
          <div class="coming-soon" style="padding: 32px;">
            <i class="fa-solid fa-gear"></i>
            <h3>API Integration Settings</h3>
            <p>Configure connections to AbuseIPDB, VirusTotal, PhishTank, and other threat intelligence feeds.</p>
            <div style="margin-top: 12px;">${renderBadge('info', 'Coming Soon')}</div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fa-solid fa-circle-info"></i> About</div>
        </div>
        <div class="card-body">
          <div style="font-size: 13px; color: var(--text-secondary); line-height: 1.7;">
            <strong>AegisMail Forensics AI</strong> — AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform<br>
            <span style="color: var(--text-tertiary);">Smart India Hackathon 2026 · Problem Statement 26106</span>
          </div>
        </div>
      </div>
    </div>
  `;
}

// ── Helper: Filter investigations ──────────────────────────────────
function filterInvestigations(query) {
  const results = query ? InvestigationStore.search(query) : InvestigationStore.getAll();
  const tbody = document.getElementById('investigations-tbody');
  if (tbody) {
    tbody.innerHTML = results.length > 0
      ? results.map(inv => renderInvestigationRow(inv)).join('')
      : `<tr><td colspan="7" style="text-align: center; padding: 32px; color: var(--text-muted);">No investigations match your search.</td></tr>`;
  }
}

function filterByLevel(level, btn) {
  // Update active chip
  document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
  if (btn) btn.classList.add('active');

  const results = InvestigationStore.filterByLevel(level);
  const tbody = document.getElementById('investigations-tbody');
  if (tbody) {
    tbody.innerHTML = results.length > 0
      ? results.map(inv => renderInvestigationRow(inv)).join('')
      : `<tr><td colspan="7" style="text-align: center; padding: 32px; color: var(--text-muted);">No investigations in this category.</td></tr>`;
  }
}

function copyRawHeaders() {
  const el = document.getElementById('raw-headers-content');
  if (el) {
    navigator.clipboard.writeText(el.textContent).then(() => {
      showToast('Raw headers copied to clipboard.', 'success');
    });
  }
}

