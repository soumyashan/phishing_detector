/**
 * AegisMail Forensics AI — Email Parser
 * Client-side .eml parsing, validation, and header extraction.
 */

// ── File Validation ────────────────────────────────────────────────
const SUPPORTED_EXTENSIONS = ['.eml', '.txt'];
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

function validateEmailFile(file) {
  if (!file) {
    return { valid: false, error: 'no-file', message: 'Please select an email file to continue.' };
  }

  const ext = '.' + file.name.split('.').pop().toLowerCase();
  if (!SUPPORTED_EXTENSIONS.includes(ext)) {
    return { valid: false, error: 'unsupported', message: 'Unsupported file type. Please upload a .eml or .txt email file.' };
  }

  if (file.size > MAX_FILE_SIZE) {
    return { valid: false, error: 'too-large', message: 'This file is too large to analyze. Please upload a smaller email file (max 10 MB).' };
  }

  if (file.size === 0) {
    return { valid: false, error: 'empty', message: 'This email file is empty and cannot be analyzed.' };
  }

  return { valid: true };
}

// ── Private IP Detection ───────────────────────────────────────────
function isPrivateIP(ip) {
  if (!ip) return false;
  // 10.x.x.x
  if (/^10\./.test(ip)) return true;
  // 172.16.x.x – 172.31.x.x
  if (/^172\.(1[6-9]|2[0-9]|3[01])\./.test(ip)) return true;
  // 192.168.x.x
  if (/^192\.168\./.test(ip)) return true;
  // 127.x.x.x (loopback)
  if (/^127\./.test(ip)) return true;
  // IPv6 loopback
  if (ip === '::1') return true;
  return false;
}

function isIPv6(ip) {
  return ip && ip.includes(':');
}

// ── Received Header Hop Extraction ─────────────────────────────────
function parseReceivedHops(content) {
  const lines = content.split(/\r?\n/);
  const receivedBlocks = [];
  let currentBlock = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (/^Received:/i.test(line)) {
      if (currentBlock) receivedBlocks.push(currentBlock);
      currentBlock = line;
    } else if (currentBlock && /^\s+/.test(line)) {
      // Continuation of multi-line Received header
      currentBlock += ' ' + line.trim();
    } else if (currentBlock) {
      receivedBlocks.push(currentBlock);
      currentBlock = null;
    }
  }
  if (currentBlock) receivedBlocks.push(currentBlock);

  // Parse IPs from each Received block
  const ipRegex = /\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?/g;
  const hops = [];

  // Received headers are in reverse order (most recent first)
  const reversed = receivedBlocks.reverse();

  reversed.forEach((block, idx) => {
    const ips = [];
    let match;
    while ((match = ipRegex.exec(block)) !== null) {
      const ip = match[1];
      if (!ips.includes(ip)) ips.push(ip);
    }

    // Extract hostname from "from <hostname>" pattern
    const hostMatch = block.match(/from\s+([^\s(]+)/i);
    const hostname = hostMatch ? hostMatch[1] : 'unknown';

    if (ips.length > 0) {
      hops.push({
        hop: idx,
        ip: ips[0],
        allIps: ips,
        host: hostname,
        isPrivate: isPrivateIP(ips[0]),
        raw: block
      });
    }
  });

  return hops;
}

// ── Main Email Parser ──────────────────────────────────────────────
function parseEmailContent(content, fileName) {
  if (!content || content.trim().length === 0) {
    return { error: true, errorType: 'empty', message: "This email doesn't contain enough information for analysis." };
  }

  fileName = fileName || 'custom_email.eml';
  const lines = content.split(/\r?\n/);
  const warnings = [];

  // ── Header Extraction ──
  let subject = '';
  let from = '';
  let replyTo = '';
  let to = '';
  let date = '';
  let messageId = '';
  let authResults = '';

  // Track which headers we found
  const foundHeaders = { subject: false, from: false, to: false, date: false };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Stop at blank line (header/body separator)
    if (line.trim() === '' && (foundHeaders.from || foundHeaders.subject)) {
      break;
    }

    if (/^Subject:/i.test(line)) {
      subject = line.replace(/^Subject:\s*/i, '').trim();
      foundHeaders.subject = true;
    }
    if (/^From:/i.test(line)) {
      from = line.replace(/^From:\s*/i, '').trim();
      foundHeaders.from = true;
    }
    if (/^Reply-To:/i.test(line)) {
      replyTo = line.replace(/^Reply-To:\s*/i, '').trim();
    }
    if (/^To:/i.test(line)) {
      to = line.replace(/^To:\s*/i, '').trim();
      foundHeaders.to = true;
    }
    if (/^Date:/i.test(line)) {
      date = line.replace(/^Date:\s*/i, '').trim();
      foundHeaders.date = true;
    }
    if (/^Message-ID:/i.test(line)) {
      messageId = line.replace(/^Message-ID:\s*/i, '').trim();
    }
    if (/^Authentication-Results:/i.test(line)) {
      authResults = line;
      // Collect continuation lines
      for (let j = i + 1; j < lines.length && /^\s+/.test(lines[j]); j++) {
        authResults += ' ' + lines[j].trim();
      }
    }
  }

  // ── Missing Header Warnings ──
  if (!foundHeaders.from && !foundHeaders.subject) {
    return { error: true, errorType: 'corrupted', message: "We couldn't read this email. The file may be corrupted or incomplete." };
  }

  if (!foundHeaders.from) {
    warnings.push("From header is missing. Sender identification unavailable.");
    from = "Unknown Sender";
  }
  if (!foundHeaders.subject) {
    warnings.push("Subject header is missing.");
    subject = "(No Subject)";
  }
  if (!foundHeaders.to) {
    warnings.push("To header is missing.");
    to = "Unknown Recipient";
  }
  if (!foundHeaders.date) {
    date = new Date().toUTCString();
  }

  // ── Authentication Results Parsing ──
  let spf = 'UNKNOWN';
  let dkim = 'UNKNOWN';
  let dmarc = 'UNKNOWN';

  if (authResults) {
    if (/spf=pass/i.test(authResults)) spf = 'PASS';
    else if (/spf=fail/i.test(authResults)) spf = 'FAIL';
    else if (/spf=softfail/i.test(authResults)) spf = 'SOFTFAIL';
    else if (/spf=neutral/i.test(authResults)) spf = 'NEUTRAL';

    if (/dkim=pass/i.test(authResults)) dkim = 'PASS';
    else if (/dkim=fail/i.test(authResults)) dkim = 'FAIL';
    else if (/dkim=neutral/i.test(authResults)) dkim = 'NEUTRAL';

    if (/dmarc=pass/i.test(authResults)) dmarc = 'PASS';
    else if (/dmarc=fail/i.test(authResults)) dmarc = 'FAIL';
  } else {
    warnings.push("Header information is incomplete. Some forensic checks may be unavailable.");
  }

  // ── Reply-To Alignment Check ──
  let alignmentStatus = 'UNKNOWN';
  let alignmentNote = 'Could not determine alignment';
  if (replyTo && from) {
    const fromDomain = extractDomain(from);
    const replyDomain = extractDomain(replyTo);
    if (fromDomain && replyDomain) {
      if (fromDomain.toLowerCase() === replyDomain.toLowerCase()) {
        alignmentStatus = 'MATCH';
        alignmentNote = 'From and Reply-To domains match';
      } else {
        alignmentStatus = 'MISMATCH';
        alignmentNote = `From: ${fromDomain} does not match Reply-To: ${replyDomain}`;
      }
    }
  } else if (!replyTo) {
    alignmentStatus = 'MATCH';
    alignmentNote = 'No separate Reply-To specified — replies go to sender';
    replyTo = from;
  }

  // ── URL Extraction ──
  const urlRegex = /(https?:\/\/[^\s"'<>]+)/gi;
  const allMatches = content.match(urlRegex) || [];
  const uniqueUrls = [...new Set(allMatches)];
  const extractedUrls = uniqueUrls.slice(0, 5).map(u => {
    let domain = '';
    try { domain = new URL(u).hostname; } catch (e) { domain = u; }
    return {
      url: u,
      domain: domain,
      age: 'Unknown',
      registrar: 'Unknown',
      vtHits: 'Threat intelligence lookup unavailable',
      ip: 'Unknown',
      status: 'SUSPICIOUS'
    };
  });

  // ── Received Hop Parsing ──
  const hops = parseReceivedHops(content);
  let relays = [];
  let infrastructure = {
    country: 'Unknown',
    city: 'Unknown',
    isp: 'Unknown',
    asn: 'Unknown',
    earliestIp: 'Unknown',
    confidence: 'UNKNOWN',
    caveat: 'Geolocation data unavailable for uploaded email. Integration with IP intelligence APIs would provide location data.'
  };

  if (hops.length > 0) {
    // Find earliest non-private IP
    const publicHops = hops.filter(h => !h.isPrivate);
    if (publicHops.length > 0) {
      const earliest = publicHops[0];
      infrastructure.earliestIp = earliest.ip;
      infrastructure.confidence = 'LOW';
      infrastructure.caveat = 'IP identified from Received headers. Geolocation requires threat intelligence API integration.';

      relays = publicHops.map((h, idx) => ({
        hop: idx,
        ip: h.ip,
        host: h.host,
        location: 'Location lookup unavailable',
        lat: 0,
        lng: 0,
        isp: 'ISP lookup unavailable',
        note: idx === 0 ? 'Earliest reliable public IP identified' : (idx === publicHops.length - 1 ? 'Recipient MX Inbound' : 'Intermediate Relay')
      }));
    } else {
      warnings.push("No reliable originating IP could be identified. All detected IPs are private/internal.");
      infrastructure.caveat = 'All detected IPs are private/internal addresses. Public geolocation is unavailable.';
    }
  } else {
    warnings.push("No Received headers found. Relay trace is unavailable.");
  }

  // ── NLP / Urgency Analysis ──
  const urgencyKeywords = [
    { pattern: /urgent/i, text: 'urgent', type: 'critical' },
    { pattern: /immediately/i, text: 'immediately', type: 'critical' },
    { pattern: /action required/i, text: 'action required', type: 'critical' },
    { pattern: /blocked|deactivat|suspend/i, text: 'account threat', type: 'critical' },
    { pattern: /within \d+ hours?/i, text: null, type: 'critical' },
    { pattern: /deadline/i, text: 'deadline', type: 'warning' },
    { pattern: /verify|verification/i, text: 'verification request', type: 'warning' },
    { pattern: /kyc|pan|aadhaar/i, text: 'identity document request', type: 'warning' },
    { pattern: /confidential/i, text: 'confidentiality pressure', type: 'warning' },
    { pattern: /unable to.*(?:call|phone|reach)/i, text: 'communication isolation', type: 'critical' },
    { pattern: /forfeit|penalty/i, text: 'penalty threat', type: 'critical' },
    { pattern: /refund|reward|prize|won/i, text: 'financial lure', type: 'info' },
    { pattern: /upi|rtgs|neft|bank\s*account/i, text: 'financial transfer request', type: 'critical' },
  ];

  const triggers = [];
  const lowerContent = content.toLowerCase();

  urgencyKeywords.forEach(kw => {
    const match = content.match(kw.pattern);
    if (match) {
      triggers.push({
        text: kw.text || match[0],
        type: kw.type
      });
    }
  });

  // ── Social Engineering Flags ──
  const seFlags = [];
  if (spf === 'FAIL' || dmarc === 'FAIL') seFlags.push('Sender domain authentication failure');
  if (alignmentStatus === 'MISMATCH') seFlags.push('Reply-To routes to different domain');
  if (triggers.some(t => t.type === 'critical')) seFlags.push('High-pressure urgency language detected');
  if (extractedUrls.length > 0) seFlags.push('Contains external URLs');
  if (seFlags.length === 0) seFlags.push('No significant social engineering indicators detected');

  // ── Risk Score Calculation ──
  let score = 0;
  const scoreFactors = [];

  // Authentication failures
  if (spf === 'FAIL') { score += 25; scoreFactors.push({ name: 'Sender authentication failed (SPF)', weight: '+25', desc: `SPF check returned ${spf}`, technical: 'SPF Authentication Failure' }); }
  else if (spf === 'SOFTFAIL') { score += 12; scoreFactors.push({ name: 'Sender authentication warning (SPF)', weight: '+12', desc: `SPF check returned ${spf}`, technical: 'SPF Soft Failure' }); }
  else if (spf === 'PASS') { score -= 15; scoreFactors.push({ name: 'Sender authentication passed (SPF)', weight: '-15', desc: 'SPF verified successfully', technical: 'SPF Pass' }); }

  if (dkim === 'FAIL') { score += 15; scoreFactors.push({ name: 'Email signature failed (DKIM)', weight: '+15', desc: 'DKIM signature is invalid or missing', technical: 'DKIM Failure' }); }
  else if (dkim === 'PASS') { score -= 10; scoreFactors.push({ name: 'Email signature valid (DKIM)', weight: '-10', desc: 'DKIM cryptographic signature verified', technical: 'DKIM Pass' }); }

  if (dmarc === 'FAIL') { score += 25; scoreFactors.push({ name: 'Domain policy violated (DMARC)', weight: '+25', desc: `DMARC policy check failed`, technical: 'DMARC Failure' }); }
  else if (dmarc === 'PASS') { score -= 10; scoreFactors.push({ name: 'Domain policy passed (DMARC)', weight: '-10', desc: 'DMARC alignment verified', technical: 'DMARC Pass' }); }

  // Reply-To mismatch
  if (alignmentStatus === 'MISMATCH') {
    score += 20;
    scoreFactors.push({ name: 'Reply-To routes to different domain', weight: '+20', desc: alignmentNote, technical: 'From vs Reply-To Mismatch' });
  }

  // Urgency language
  const criticalTriggers = triggers.filter(t => t.type === 'critical').length;
  if (criticalTriggers >= 3) { score += 15; scoreFactors.push({ name: 'Multiple high-pressure phrases detected', weight: '+15', desc: `${criticalTriggers} critical urgency indicators found`, technical: 'High Urgency NLP Score' }); }
  else if (criticalTriggers >= 1) { score += 8; scoreFactors.push({ name: 'Urgency language detected', weight: '+8', desc: `${criticalTriggers} urgency indicator(s) found`, technical: 'Moderate Urgency NLP Score' }); }

  // Suspicious URLs
  if (extractedUrls.length > 0) {
    score += 10;
    scoreFactors.push({ name: 'External URLs present', weight: '+10', desc: `${extractedUrls.length} URL(s) found in email body`, technical: 'URL Presence Check' });
  }

  // Clamp score
  score = Math.max(0, Math.min(100, score));

  // Determine risk level
  let riskLevel = 'clean';
  let classification = 'LEGITIMATE';
  if (score >= 80) { riskLevel = 'critical'; classification = 'PHISHING'; }
  else if (score >= 60) { riskLevel = 'high'; classification = 'HIGH RISK'; }
  else if (score >= 30) { riskLevel = 'medium'; classification = 'SUSPICIOUS'; }

  // ── Detect body ──
  const bodyStartIdx = content.indexOf('\n\n');
  let emailBody = '';
  if (bodyStartIdx > -1) {
    emailBody = content.substring(bodyStartIdx + 2).trim();
    // Strip HTML tags for safe display
    emailBody = emailBody.replace(/<[^>]*>/g, '').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').trim();
  }
  if (!emailBody) {
    warnings.push("Email body is empty or could not be extracted. Header analysis was still performed.");
  }

  // ── Build Result Object ──
  const caseId = 'INV-' + Date.now().toString(36).toUpperCase() + '-' + Math.floor(Math.random() * 9000 + 1000);

  return {
    error: false,
    id: caseId,
    title: 'Analyzed: ' + fileName,
    file: fileName,
    subject: subject,
    from: from,
    replyTo: replyTo,
    to: to,
    date: date,
    messageId: messageId || '<' + Math.random().toString(36).substring(2) + '@upload>',
    classification: classification,
    riskScore: score,
    riskLevel: riskLevel,
    isDemo: false,
    warnings: warnings,
    auth: {
      spf: { status: spf, note: `SPF evaluation: ${spf}`, explanation: getAuthExplanation('spf', spf) },
      dkim: { status: dkim, note: `DKIM evaluation: ${dkim}`, explanation: getAuthExplanation('dkim', dkim) },
      dmarc: { status: dmarc, note: `DMARC evaluation: ${dmarc}`, explanation: getAuthExplanation('dmarc', dmarc) },
      alignment: { status: alignmentStatus, note: alignmentNote, explanation: getAuthExplanation('alignment', alignmentStatus) }
    },
    nlp: {
      urgencyScore: Math.min(100, criticalTriggers * 20 + triggers.length * 10),
      sentiment: criticalTriggers > 2 ? 'High Urgency / Coercive Threat' : triggers.length > 0 ? 'Moderate Urgency Detected' : 'Standard Email Text',
      triggers: triggers,
      socialEngineeringFlags: seFlags
    },
    urls: extractedUrls,
    relays: relays,
    infrastructure: infrastructure,
    campaign: {
      name: 'No campaign data available',
      clusterId: 'N/A',
      relatedEmailsCount: 0,
      relatedDomains: [extractDomain(from) || 'unknown'],
      relatedIps: infrastructure.earliestIp !== 'Unknown' ? [infrastructure.earliestIp] : [],
      threatActorType: 'Under Investigation',
      groupingReason: 'Campaign correlation requires multiple analyzed emails sharing common infrastructure.'
    },
    explainableScore: scoreFactors,
    emailBody: emailBody,
    rawContent: content
  };
}

// ── Helpers ─────────────────────────────────────────────────────────
function extractDomain(emailStr) {
  if (!emailStr) return '';
  const match = emailStr.match(/@([^>\s,]+)/);
  return match ? match[1] : '';
}

function getAuthExplanation(type, status) {
  const explanations = {
    spf: {
      PASS: 'The sending server is authorized by the domain\'s SPF record.',
      FAIL: 'The sending server is not authorized by the domain\'s SPF record.',
      SOFTFAIL: 'The sending server is not explicitly authorized but the domain has a permissive policy.',
      NEUTRAL: 'The SPF check returned a neutral result — no definitive authorization.',
      UNKNOWN: 'SPF information was not available in the email headers.'
    },
    dkim: {
      PASS: 'The email\'s digital signature is valid and verified.',
      FAIL: 'The email\'s digital signature is invalid or has been tampered with.',
      NEUTRAL: 'No DKIM signature was present to verify.',
      UNKNOWN: 'DKIM information was not available in the email headers.'
    },
    dmarc: {
      PASS: 'The email satisfies the domain\'s DMARC authentication policy.',
      FAIL: 'The email violates the domain\'s DMARC policy.',
      UNKNOWN: 'DMARC information was not available in the email headers.'
    },
    alignment: {
      MATCH: 'The From address and Reply-To address are consistent.',
      MISMATCH: 'Replies to this email would go to a different domain than the claimed sender.',
      UNKNOWN: 'Could not determine header alignment.'
    }
  };
  return (explanations[type] && explanations[type][status]) || 'No additional information available.';
}

function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
