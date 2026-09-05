/**
 * AegisMail Forensics AI — Campaign Correlation Graph Module
 * Canvas-based hierarchical correlation visualization directly implementing
 * the modern reference diagram architecture:
 * IP Address (Blue) → Domains (Green) → Emails (Amber) → Campaign (Pink)
 */

let graphCanvas = null;
let graphCtx = null;
let currentGraphCase = null;

function initCampaignGraph(containerId) {
  graphCanvas = document.getElementById(containerId || 'campaign-graph-canvas');
  if (!graphCanvas) return;
  graphCtx = graphCanvas.getContext('2d');
  resizeCampaignGraph();
}

function resizeCampaignGraph() {
  if (!graphCanvas || !graphCanvas.parentElement) return;
  graphCanvas.width = graphCanvas.parentElement.clientWidth;
  graphCanvas.height = 380;
  drawCampaignGraph();
}

function updateGraphData(c) {
  currentGraphCase = c;
  drawCampaignGraph();
}

function drawRoundedRect(ctx, x, y, width, height, radius) {
  ctx.beginPath();
  ctx.moveTo(x + radius, y);
  ctx.lineTo(x + width - radius, y);
  ctx.quadraticCurveTo(x + width, y, x + width, y + radius);
  ctx.lineTo(x + width, y + height - radius);
  ctx.quadraticCurveTo(x + width, y + height, x + width - radius, y + height);
  ctx.lineTo(x + radius, y + height);
  ctx.quadraticCurveTo(x, y + height, x, y + height - radius);
  ctx.lineTo(x, y + radius);
  ctx.quadraticCurveTo(x, y, x + radius, y);
  ctx.closePath();
}

function drawArrow(ctx, fromX, fromY, toX, toY, color = '#475569') {
  const headLen = 9;
  const angle = Math.atan2(toY - fromY, toX - fromX);

  ctx.beginPath();
  ctx.moveTo(fromX, fromY);
  ctx.lineTo(toX, toY);
  ctx.strokeStyle = color;
  ctx.lineWidth = 2.2;
  ctx.stroke();

  // Arrow head
  ctx.beginPath();
  ctx.moveTo(toX, toY);
  ctx.lineTo(toX - headLen * Math.cos(angle - Math.PI / 6.5), toY - headLen * Math.sin(angle - Math.PI / 6.5));
  ctx.lineTo(toX - headLen * Math.cos(angle + Math.PI / 6.5), toY - headLen * Math.sin(angle + Math.PI / 6.5));
  ctx.closePath();
  ctx.fillStyle = color;
  ctx.fill();
}

function drawCampaignGraph() {
  if (!graphCtx || !graphCanvas) return;

  const ctx = graphCtx;
  const w = graphCanvas.width;
  const h = graphCanvas.height;

  ctx.clearRect(0, 0, w, h);

  // Clean soft grid background
  ctx.fillStyle = '#F8FAFC';
  ctx.fillRect(0, 0, w, h);

  ctx.strokeStyle = '#E2E8F0';
  ctx.lineWidth = 1;
  for (let x = 0; x < w; x += 32) {
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
  }
  for (let y = 0; y < h; y += 32) {
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }

  const c = currentGraphCase;
  if (!c) {
    ctx.font = "600 14px 'Inter', sans-serif";
    ctx.fillStyle = '#64748B';
    ctx.textAlign = 'center';
    ctx.fillText('Select or analyze an investigation to render correlation architecture.', w / 2, h / 2);
    return;
  }

  // 4-Tier Reference Architecture
  const ipLabel = c.infrastructure?.earliestIp ? `IP: ${c.infrastructure.earliestIp}` : 'IP Address';
  const domains = c.campaign?.relatedDomains?.length > 0
    ? c.campaign.relatedDomains.slice(0, 3)
    : ['Domain A', 'Domain B', 'Domain C'];

  // Ensure 3 domains for visual balance
  while (domains.length < 3) {
    domains.push(`Domain ${String.fromCharCode(65 + domains.length)}`);
  }

  const emails = [
    c.id || 'Email 1',
    'Case Telemetry #2',
    'Case Telemetry #3'
  ];

  const campaignLabel = c.campaign?.name || 'Same Campaign';

  // Node dimensions & vertical layout coordinates
  const nodeHeight = 44;
  const radius = 12;

  const y1 = 28;                 // Tier 1: IP Address
  const y2 = 115;                // Tier 2: Domains
  const y3 = 205;                // Tier 3: Emails
  const y4 = 298;                // Tier 4: Campaign

  // Tier 1: IP Address Node (Top, Blue)
  const topWidth = Math.min(220, w * 0.4);
  const topX = (w - topWidth) / 2;
  const topCenter = { x: w / 2, y: y1 + nodeHeight };

  // Tier 2: 3 Domain Nodes (Green)
  const margin = Math.max(12, w * 0.03);
  const colWidth = Math.min(180, (w - margin * 4) / 3);
  const totalColsW = colWidth * 3 + margin * 2;
  const startX = (w - totalColsW) / 2;

  const domainNodes = domains.map((dom, i) => {
    const x = startX + i * (colWidth + margin);
    return {
      x,
      y: y2,
      w: colWidth,
      h: nodeHeight,
      label: dom,
      topCenter: { x: x + colWidth / 2, y: y2 },
      bottomCenter: { x: x + colWidth / 2, y: y2 + nodeHeight }
    };
  });

  // Tier 3: 3 Email Nodes (Amber)
  const emailNodes = emails.map((eml, i) => {
    const x = startX + i * (colWidth + margin);
    return {
      x,
      y: y3,
      w: colWidth,
      h: nodeHeight,
      label: eml,
      topCenter: { x: x + colWidth / 2, y: y3 },
      bottomCenter: { x: x + colWidth / 2, y: y3 + nodeHeight }
    };
  });

  // Tier 4: Campaign Node (Bottom, Pink)
  const bottomWidth = Math.min(280, w * 0.5);
  const bottomX = (w - bottomWidth) / 2;
  const bottomCenter = { x: w / 2, y: y4 };

  // ── Draw Arrows ──────────────────────────────────────────
  const arrowColor = '#475569';

  // 1. IP -> Domains
  domainNodes.forEach(dNode => {
    drawArrow(ctx, topCenter.x, topCenter.y, dNode.topCenter.x, dNode.topCenter.y, arrowColor);
  });

  // 2. Domains -> Emails (direct vertical arrows)
  for (let i = 0; i < 3; i++) {
    drawArrow(ctx, domainNodes[i].bottomCenter.x, domainNodes[i].bottomCenter.y, emailNodes[i].topCenter.x, emailNodes[i].topCenter.y, arrowColor);
  }

  // 3. Emails -> Campaign
  emailNodes.forEach(eNode => {
    drawArrow(ctx, eNode.bottomCenter.x, eNode.bottomCenter.y, bottomCenter.x, bottomCenter.y, arrowColor);
  });

  // ── Draw Nodes ───────────────────────────────────────────

  // Helper for drawing a pill card
  function renderPill(x, y, width, height, text, bg, border, textColor, iconClass) {
    // Drop shadow
    ctx.save();
    ctx.shadowColor = 'rgba(15, 23, 42, 0.08)';
    ctx.shadowBlur = 6;
    ctx.shadowOffsetY = 2;

    drawRoundedRect(ctx, x, y, width, height, radius);
    ctx.fillStyle = bg;
    ctx.fill();
    ctx.restore();

    // 2px solid border
    ctx.lineWidth = 2.2;
    ctx.strokeStyle = border;
    ctx.stroke();

    // Text
    ctx.font = "bold 13px 'Inter', sans-serif";
    ctx.fillStyle = textColor;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';

    const maxTextWidth = width - 20;
    let displayText = text;
    if (ctx.measureText(displayText).width > maxTextWidth) {
      while (displayText.length > 4 && ctx.measureText(displayText + '…').width > maxTextWidth) {
        displayText = displayText.slice(0, -1);
      }
      displayText += '…';
    }

    ctx.fillText(displayText, x + width / 2, y + height / 2);
  }

  // 1. Tier 1: IP Address (Blue Pill)
  renderPill(topX, y1, topWidth, nodeHeight, ipLabel, '#DBEAFE', '#3B82F6', '#1E40AF');

  // 2. Tier 2: Domains (Green Pills)
  domainNodes.forEach(node => {
    renderPill(node.x, node.y, node.w, node.h, node.label, '#DCFCE7', '#10B981', '#065F46');
  });

  // 3. Tier 3: Emails (Amber Pills)
  emailNodes.forEach(node => {
    renderPill(node.x, node.y, node.w, node.h, node.label, '#FEF3C7', '#F59E0B', '#92400E');
  });

  // 4. Tier 4: Same Campaign (Pink Pill)
  renderPill(bottomX, y4, bottomWidth, nodeHeight, campaignLabel, '#FCE7F3', '#EC4899', '#9D174D');
}

// Auto-resize on window resize
window.addEventListener('resize', function() {
  if (graphCanvas && graphCanvas.offsetParent !== null) {
    resizeCampaignGraph();
  }
});
