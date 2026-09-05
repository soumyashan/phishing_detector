/**
 * AegisMail Forensics AI — Application Core
 * Router, state management, event handlers, and initialization.
 */

// ── Page Title Map ─────────────────────────────────────────────────
const PAGE_TITLES = {
  dashboard: 'Dashboard',
  analyze: 'Analyze Email',
  investigations: 'Investigations',
  campaigns: 'Campaigns',
  intelligence: 'Threat Intelligence',
  reports: 'Reports',
  settings: 'Settings',
};

// ── Router ─────────────────────────────────────────────────────────
function navigateTo(route) {
  window.location.hash = '#/' + route;
}

function handleRoute() {
  const hash = window.location.hash.replace('#/', '') || 'dashboard';
  const parts = hash.split('/');
  const page = parts[0];
  const param = parts[1] || null;

  AppState.currentPage = page;
  const content = document.getElementById('app-content');
  if (!content) return;

  // Destroy map before re-rendering
  destroyMap();

  let html = '';
  let pageTitle = PAGE_TITLES[page] || 'AegisMail';

  switch (page) {
    case 'dashboard':
      html = renderDashboard();
      break;
    case 'analyze':
      html = renderAnalyzePage();
      break;
    case 'investigation':
      if (param) {
        AppState.currentInvestigationId = param;
        html = renderAnalysisResults(param);
        const inv = InvestigationStore.getById(param);
        pageTitle = inv ? `Investigation ${inv.id}` : 'Investigation';
      } else {
        html = renderInvestigationsPage();
      }
      break;
    case 'investigations':
      html = renderInvestigationsPage();
      break;
    case 'campaigns':
      html = renderCampaignsPage();
      break;
    case 'intelligence':
      html = renderIntelligencePage();
      break;
    case 'reports':
      html = renderReportsPage();
      break;
    case 'settings':
      html = renderSettingsPage();
      break;
    default:
      html = renderDashboard();
      pageTitle = 'Dashboard';
  }

  content.innerHTML = html;

  // Update topbar title
  const titleEl = document.getElementById('topbar-page-title');
  if (titleEl) titleEl.textContent = pageTitle;

  // Update active sidebar link
  updateSidebarActive(page);

  // Post-render hooks
  if (page === 'analyze') {
    initUploadHandlers();
  }

  if (page === 'investigation' && param) {
    const activeTab = AppState.currentResultTab || 'overview';
    postRenderTabHooks(activeTab, param);
  }

  // Close mobile sidebar
  closeSidebar();

  // Scroll to top
  window.scrollTo(0, 0);
}

// ── Tab Switching ──────────────────────────────────────────────────
function switchResultTab(tabId, caseId) {
  AppState.currentResultTab = tabId;
  // Re-render the investigation page with the new tab
  const content = document.getElementById('app-content');
  if (content) {
    destroyMap();
    content.innerHTML = renderAnalysisResults(caseId);
    postRenderTabHooks(tabId, caseId);
  }
}

function postRenderTabHooks(tabId, caseId) {
  const c = InvestigationStore.getById(caseId);
  if (!c) return;

  if (tabId === 'trace') {
    const hasGeoData = c.relays && c.relays.some(r => r.lat && r.lng && (r.lat !== 0 || r.lng !== 0));
    if (hasGeoData) {
      setTimeout(() => {
        initMap('geolocation-map');
        updateMapMarkers(c.relays);
      }, 100);
    }
  }

  if (tabId === 'campaign') {
    setTimeout(() => {
      initCampaignGraph('campaign-graph-canvas');
      updateGraphData(c);
    }, 100);
  }
}

// ── Sidebar ────────────────────────────────────────────────────────
function updateSidebarActive(page) {
  document.querySelectorAll('.sidebar-link').forEach(link => {
    link.classList.remove('active');
    if (link.dataset.page === page || (page === 'investigation' && link.dataset.page === 'investigations')) {
      link.classList.add('active');
    }
  });

  // Update badge count
  const stats = InvestigationStore.getStats();
  const critBadge = document.getElementById('sidebar-crit-count');
  if (critBadge) {
    const critCount = stats.critical + stats.high;
    critBadge.textContent = critCount;
    critBadge.style.display = critCount > 0 ? 'inline' : 'none';
  }
}

function toggleSidebar() {
  const sidebar = document.querySelector('.sidebar');
  const overlay = document.querySelector('.sidebar-overlay');
  if (sidebar) {
    sidebar.classList.toggle('open');
    AppState.sidebarOpen = sidebar.classList.contains('open');
  }
  if (overlay) {
    overlay.classList.toggle('visible', AppState.sidebarOpen);
  }
}

function closeSidebar() {
  const sidebar = document.querySelector('.sidebar');
  const overlay = document.querySelector('.sidebar-overlay');
  if (sidebar) sidebar.classList.remove('open');
  if (overlay) overlay.classList.remove('visible');
  AppState.sidebarOpen = false;
}

// ── Upload Handlers ────────────────────────────────────────────────
function initUploadHandlers() {
  const dropZone = document.getElementById('upload-zone');
  const fileInput = document.getElementById('eml-file-input');
  const analyzeBtn = document.getElementById('analyze-btn');
  const textarea = document.getElementById('raw-eml-textarea');

  if (dropZone && fileInput) {
    dropZone.addEventListener('click', () => fileInput.click());

    dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropZone.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', () => {
      dropZone.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropZone.classList.remove('drag-over');
      if (e.dataTransfer.files.length > 0) {
        handleFileUpload(e.dataTransfer.files[0]);
      }
    });

    fileInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        handleFileUpload(e.target.files[0]);
      }
    });
  }

  if (analyzeBtn) {
    analyzeBtn.addEventListener('click', () => {
      const text = textarea ? textarea.value.trim() : '';
      if (!text) {
        showUploadError('Please paste raw email headers or upload a file to continue.');
        return;
      }
      analyzeEmailContent(text, 'pasted_email.eml');
    });
  }
}

function handleFileUpload(file) {
  const validation = validateEmailFile(file);
  if (!validation.valid) {
    showUploadError(validation.message);
    return;
  }

  const reader = new FileReader();
  reader.onload = (e) => {
    const content = e.target.result;
    const textarea = document.getElementById('raw-eml-textarea');
    if (textarea) textarea.value = content;
    analyzeEmailContent(content, file.name);
  };
  reader.onerror = () => {
    showUploadError("We couldn't read this file. The file may be corrupted or incomplete.");
  };
  reader.readAsText(file);
}

function showUploadError(message) {
  const errorEl = document.getElementById('upload-error');
  if (errorEl) {
    errorEl.style.display = 'block';
    errorEl.innerHTML = `
      <div class="alert alert-error">
        <i class="fa-solid fa-circle-xmark"></i>
        <span>${escapeHtml(message)}</span>
      </div>
    `;
  }
}

// ── Preset Sample Loader ───────────────────────────────────────────
function loadPresetSample(key) {
  const sample = PRESET_SAMPLES[key];
  if (!sample) return;

  triggerScan(sample);
}

// ── Email Analysis Pipeline ────────────────────────────────────────
function analyzeEmailContent(content, fileName) {
  const result = parseEmailContent(content, fileName);

  if (result.error) {
    showUploadError(result.message);
    return;
  }

  triggerScan(result);
}

// ── Scan Animation ─────────────────────────────────────────────────
function triggerScan(caseData) {
  if (AppState.isScanning) return;
  AppState.isScanning = true;

  const overlay = document.getElementById('scan-overlay');
  if (!overlay) {
    finishScan(caseData);
    return;
  }

  overlay.classList.add('visible');

  const steps = [
    { text: 'Parsing email headers & envelope...', id: 'scan-s1' },
    { text: 'Validating SPF, DKIM & DMARC...', id: 'scan-s2' },
    { text: 'Reconstructing relay transmission path...', id: 'scan-s3' },
    { text: 'Running content & language analysis...', id: 'scan-s4' },
    { text: 'Querying threat intelligence feeds...', id: 'scan-s5' },
    { text: 'Synthesizing risk assessment...', id: 'scan-s6' },
  ];

  const progressFill = document.getElementById('scan-progress-fill');
  let currentStep = 0;

  function advanceStep() {
    if (currentStep < steps.length) {
      // Mark previous as done
      if (currentStep > 0) {
        const prevEl = document.getElementById(steps[currentStep - 1].id);
        if (prevEl) {
          prevEl.classList.remove('active');
          prevEl.classList.add('done');
          prevEl.querySelector('i').className = 'fa-solid fa-circle-check';
        }
      }

      // Mark current as active
      const curEl = document.getElementById(steps[currentStep].id);
      if (curEl) {
        curEl.classList.add('active');
        curEl.querySelector('i').className = 'fa-solid fa-spinner fa-spin';
      }

      // Update progress bar
      const pct = ((currentStep + 1) / steps.length) * 100;
      if (progressFill) progressFill.style.width = pct + '%';

      currentStep++;
      setTimeout(advanceStep, 180 + Math.random() * 120);
    } else {
      // Mark last as done
      const lastEl = document.getElementById(steps[steps.length - 1].id);
      if (lastEl) {
        lastEl.classList.remove('active');
        lastEl.classList.add('done');
        lastEl.querySelector('i').className = 'fa-solid fa-circle-check';
      }

      setTimeout(() => {
        overlay.classList.remove('visible');
        // Reset step states
        steps.forEach(s => {
          const el = document.getElementById(s.id);
          if (el) {
            el.classList.remove('active', 'done');
            el.querySelector('i').className = 'fa-regular fa-circle';
          }
        });
        if (progressFill) progressFill.style.width = '0%';

        finishScan(caseData);
      }, 400);
    }
  }

  advanceStep();
}

function finishScan(caseData) {
  AppState.isScanning = false;

  // Store investigation
  InvestigationStore.add(caseData);

  // Navigate to results
  AppState.currentResultTab = 'overview';
  navigateTo('investigation/' + caseData.id);

  showToast('Analysis complete — ' + caseData.classification, caseData.riskLevel === 'clean' ? 'success' : 'info');
}

// ── Toast Notifications ────────────────────────────────────────────
function showToast(message, type) {
  type = type || 'info';
  const container = document.getElementById('toast-container');
  if (!container) return;

  const icon = type === 'error' ? 'fa-circle-xmark' :
               type === 'success' ? 'fa-circle-check' : 'fa-circle-info';
  const colorStyle = type === 'error' ? 'color: var(--severity-critical-text);' :
                     type === 'success' ? 'color: var(--severity-clean-text);' :
                     'color: var(--brand-primary);';

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <i class="fa-solid ${icon}" style="${colorStyle}"></i>
    <span>${escapeHtml(message)}</span>
  `;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// ── Initialization ─────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Set up hash-based routing
  window.addEventListener('hashchange', handleRoute);

  // Initial route
  handleRoute();

  // Sidebar navigation clicks
  document.querySelectorAll('.sidebar-link').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const page = link.dataset.page;
      if (page) navigateTo(page);
    });
  });

  // Hamburger toggle
  const hamburger = document.getElementById('hamburger-btn');
  if (hamburger) {
    hamburger.addEventListener('click', toggleSidebar);
  }

  // Close sidebar on overlay click
  const sidebarOverlay = document.querySelector('.sidebar-overlay');
  if (sidebarOverlay) {
    sidebarOverlay.addEventListener('click', closeSidebar);
  }

  // Keyboard navigation for sidebar
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && AppState.sidebarOpen) {
      closeSidebar();
    }
  });
});
