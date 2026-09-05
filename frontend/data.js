/**
 * AegisMail Forensics AI — Data Layer
 * Preset samples, application state, and investigation store.
 */

// ── Application State ──────────────────────────────────────────────
const AppState = {
  currentPage: 'dashboard',
  currentInvestigationId: null,
  currentResultTab: 'overview',
  isScanning: false,
  sidebarOpen: false,
};

// ── Investigation Store (in-memory) ────────────────────────────────
const InvestigationStore = {
  _items: [],

  add(investigation) {
    investigation._timestamp = new Date().toISOString();
    investigation._status = 'complete';
    this._items.unshift(investigation);
    return investigation;
  },

  getAll() {
    return this._items;
  },

  getById(id) {
    return this._items.find(item => item.id === id) || null;
  },

  getStats() {
    const all = this._items;
    return {
      total: all.length,
      critical: all.filter(i => i.riskLevel === 'critical').length,
      high: all.filter(i => i.riskLevel === 'high').length,
      suspicious: all.filter(i => i.riskLevel === 'medium').length,
      clean: all.filter(i => i.riskLevel === 'clean').length,
    };
  },

  search(query) {
    const q = query.toLowerCase();
    return this._items.filter(i =>
      i.subject.toLowerCase().includes(q) ||
      i.from.toLowerCase().includes(q) ||
      i.id.toLowerCase().includes(q) ||
      (i.infrastructure && i.infrastructure.earliestIp && i.infrastructure.earliestIp.includes(q))
    );
  },

  filterByLevel(level) {
    if (!level || level === 'all') return this._items;
    return this._items.filter(i => i.riskLevel === level);
  }
};

// ── Preset Sample Fixtures ─────────────────────────────────────────
const PRESET_SAMPLES = {
  sbi_bank: {
    id: "CASE-2026-SBI-98214",
    title: "SBI YONO Phishing & KYC Fraud",
    file: "sbi_bank_phishing.eml",
    subject: "[CRITICAL ACTION REQUIRED] Your SBI YONO Account Will Be Blocked in 24 Hours - Update PAN/KYC Immediately",
    from: '"State Bank of India - Security Desk" <alert@sbi.co.in>',
    replyTo: "support-verification@sbi-kyc-desk.cc",
    to: "victim.user@gmail.com",
    date: "Mon, 31 Aug 2026 14:21:40 +0530",
    messageId: "<20260831142140.98421.qmail@sbi-alert-secure-update.cc>",
    classification: "PHISHING",
    riskScore: 94,
    riskLevel: "critical",
    isDemo: true,
    auth: {
      spf: { status: "FAIL", note: "domain alert@sbi.co.in does not designate 185.220.101.45 as permitted sender", explanation: "The sending server's IP address is not authorized by the claimed sender domain's SPF record." },
      dkim: { status: "NEUTRAL", note: "No valid cryptographic signature found for sbi.co.in", explanation: "No DKIM signature was present, so the email's integrity cannot be cryptographically verified." },
      dmarc: { status: "FAIL", note: "p=REJECT policy strictly violated by unauthorized sending IP", explanation: "The domain's DMARC policy requires rejection of unauthorized emails, but this email was sent from an unauthorized server." },
      alignment: { status: "MISMATCH", note: "From: sbi.co.in does NOT match Reply-To: sbi-kyc-desk.cc", explanation: "Replies to this email would go to a completely different domain than the claimed sender — a strong indicator of phishing." }
    },
    nlp: {
      urgencyScore: 92,
      sentiment: "High Urgency / Coercive Financial Threat",
      triggers: [
        { text: "CRITICAL ACTION REQUIRED", type: "critical" },
        { text: "Blocked in 24 Hours", type: "critical" },
        { text: "Update PAN/KYC Immediately", type: "warning" },
        { text: "temporarily placed on restricted status", type: "critical" },
        { text: "permanent deactivation", type: "critical" },
        { text: "Tonight before 23:59 IST", type: "warning" },
        { text: "VERIFY KYC & UNBLOCK YONO ACCOUNT", type: "critical" }
      ],
      socialEngineeringFlags: [
        "Brand Impersonation (State Bank of India)",
        "Manufactured Urgency (24h timer)",
        "Credential / Identity Harvesting (PAN/KYC)"
      ]
    },
    urls: [
      {
        url: "http://sbi-kyc-update-portal.cc/login/verify.php?token=9823419082",
        domain: "sbi-kyc-update-portal.cc",
        age: "3 days old (Registered 28-Aug-2026)",
        registrar: "NameCheap Inc / Privacy Protected",
        vtHits: "17 / 92 engines flagged Malicious Phishing",
        ip: "185.220.101.45",
        status: "MALICIOUS"
      }
    ],
    relays: [
      { hop: 0, ip: "194.26.29.112", host: "vps-node-49.bulletproof-host.net", location: "Frankfurt, Germany", lat: 50.1109, lng: 8.6821, isp: "Bulletproof VPS Hosting Corp", note: "Earliest Reliable Source IP" },
      { hop: 1, ip: "185.220.101.45", host: "mail.sbi-alert-secure-update.cc", location: "Amsterdam, Netherlands", lat: 52.3676, lng: 4.9041, isp: "Tor / Anonymous Cloud Relay", note: "Intermediate Mail Relay" },
      { hop: 2, ip: "209.85.208.65", host: "mx.google.com", location: "Mountain View, CA, USA", lat: 37.3861, lng: -122.0839, isp: "Google LLC Gateway", note: "Recipient MX Inbound Node" }
    ],
    infrastructure: {
      country: "Germany",
      city: "Frankfurt am Main",
      isp: "Bulletproof VPS Hosting Corp",
      asn: "AS48291 (Bulletproof Network)",
      earliestIp: "194.26.29.112",
      confidence: "MEDIUM",
      caveat: "Attribution is supported by earliest Received header. High probability of bulletproof VPS infrastructure used by attacker."
    },
    campaign: {
      name: "Operation Bengal Phish #04",
      clusterId: "CAMP-2026-YONO-991",
      relatedEmailsCount: 6,
      relatedDomains: ["sbi-kyc-desk.cc", "sbi-kyc-update-portal.cc", "sbi-alert-secure-update.cc"],
      relatedIps: ["194.26.29.112", "185.220.101.45", "194.26.29.115"],
      threatActorType: "Financial Credential Harvesting Syndicate",
      groupingReason: "Shared bulletproof hosting IP (194.26.29.x range), common .cc TLD registrar pattern, identical phishing template structure"
    },
    explainableScore: [
      { name: "Sender authentication failed", weight: "+30", desc: "SPF and DMARC both failed — the sending server is not authorized to send email for sbi.co.in", technical: "DMARC / SPF Authentication Hard Failure" },
      { name: "Reply-To routes to different domain", weight: "+25", desc: "Replies would go to sbi-kyc-desk.cc instead of sbi.co.in — a common phishing redirection technique", technical: "Sender vs Reply-To Mismatch (.cc lookalike)" },
      { name: "Suspicious domain detected", weight: "+20", desc: "The linked domain was registered 3 days ago and is flagged by 17 threat intelligence engines", technical: "Adversary Lookalike Domain & Threat Intel Hits" },
      { name: "Urgency language detected", weight: "+15", desc: "Multiple high-pressure phrases found: '24 Hours', 'CRITICAL ACTION REQUIRED', 'permanent deactivation'", technical: "Urgency / Threat Social Engineering NLP Vector" },
      { name: "Suspicious hosting origin", weight: "+4", desc: "The earliest relay hop originates from a known bulletproof hosting IP range", technical: "Known Bulletproof ASN Source Origin" }
    ],
    emailBody: `Dear Valued Customer,

URGENT: Our automated fraud detection system has temporarily placed your SBI NetBanking and YONO Mobile App on restricted status.

You must update your PAN card details and re-verify your KYC identity immediately to avoid permanent deactivation of your account within 24 hours.

Deadline: Tonight before 23:59 IST

Link: http://sbi-kyc-update-portal.cc/login/verify.php?token=9823419082

Do not share your OTP or PIN with anyone.`,
    rawContent: `Delivered-To: victim.user@gmail.com
Received: from mail.sbi-alert-secure-update.cc (185.220.101.45) by mx.google.com; Mon, 31 Aug 2026 14:22:10 +0530
Received: from unknown (HELO vps-node-49.bulletproof-host.net) (194.26.29.112) by mail.sbi-alert-secure-update.cc; Mon, 31 Aug 2026 08:51:45 +0000
Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=alert@sbi.co.in; dkim=neutral; dmarc=fail header.from=sbi.co.in
From: "State Bank of India - Security Desk" <alert@sbi.co.in>
Reply-To: support-verification@sbi-kyc-desk.cc
To: victim.user@gmail.com
Subject: [CRITICAL ACTION REQUIRED] Your SBI YONO Account Will Be Blocked in 24 Hours - Update PAN/KYC Immediately
Date: Mon, 31 Aug 2026 14:21:40 +0530

Dear Valued Customer,
URGENT: Our automated fraud detection system has temporarily placed your SBI NetBanking and YONO Mobile App on restricted status.
You must update your PAN card details and re-verify your KYC identity immediately to avoid permanent deactivation of your account within 24 hours.
Deadline: Tonight before 23:59 IST
Link: http://sbi-kyc-update-portal.cc/login/verify.php?token=9823419082`
  },

  principal_bec: {
    id: "CASE-2026-BEC-41029",
    title: "College Principal NAAC Fund Fraud (BEC)",
    file: "principal_bec_fraud.eml",
    subject: "URGENT: Confidential Administrative Assistance Required - Immediate Fund Transfer for NAAC Inspection",
    from: '"Dr. Arvind Sharma (Principal)" <principal@engineering-college.edu.in>',
    replyTo: "principal.office.execdesk@gmail.com",
    to: "hod.cse@engineering-college.edu.in",
    date: "Mon, 31 Aug 2026 10:13:10 +0530",
    messageId: "<BEC-9821034-20260831101310@mail-relay-open.cloudvps-host.de>",
    classification: "BEC FRAUD",
    riskScore: 86,
    riskLevel: "high",
    isDemo: true,
    auth: {
      spf: { status: "SOFTFAIL", note: "IP 89.163.142.77 not listed in engineering-college.edu.in SPF record", explanation: "The sending server is not explicitly authorized by the domain's SPF record, but the domain has a soft policy that doesn't strictly reject." },
      dkim: { status: "NEUTRAL", note: "No cryptographic DKIM header found", explanation: "No digital signature was attached to this email, so its content integrity cannot be verified." },
      dmarc: { status: "FAIL", note: "DMARC policy failed due to unaligned sender IP", explanation: "The domain's email authentication policy was violated — this email was not sent from an authorized server." },
      alignment: { status: "MISMATCH", note: "From: engineering-college.edu.in vs Reply-To: @gmail.com", explanation: "The email claims to be from the college domain but replies would go to a personal Gmail account — a hallmark of business email compromise." }
    },
    nlp: {
      urgencyScore: 88,
      sentiment: "Authority Impersonation / Urgent Financial Transfer",
      triggers: [
        { text: "URGENT", type: "critical" },
        { text: "Confidential Administrative Assistance", type: "warning" },
        { text: "NAAC Peer Team accreditation visit", type: "info" },
        { text: "unable to answer phone calls", type: "critical" },
        { text: "emergency honorarium advance of Rs. 85,000", type: "critical" },
        { text: "immediate UPI / RTGS", type: "critical" },
        { text: "utmost discretion and confidentiality", type: "warning" }
      ],
      socialEngineeringFlags: [
        "Authority / Executive Impersonation (College Principal)",
        "Communication Isolation ('Cannot answer phone')",
        "Urgent Financial Disbursement Request"
      ]
    },
    urls: [],
    relays: [
      { hop: 0, ip: "185.181.61.15", host: "proxy-vpn-node.mullvad-exit.org", location: "Stockholm, Sweden", lat: 59.3293, lng: 18.0686, isp: "Mullvad Commercial VPN Gateway", note: "Source Client IP (VPN Exit Node)" },
      { hop: 1, ip: "89.163.142.77", host: "mail-relay-open.cloudvps-host.de", location: "Nuremberg, Germany", lat: 49.4521, lng: 11.0767, isp: "Hetzner Cloud VPS", note: "Misconfigured Open Relay" },
      { hop: 2, ip: "209.85.208.65", host: "mx.google.com", location: "Mountain View, CA, USA", lat: 37.3861, lng: -122.0839, isp: "Google LLC Gateway", note: "Recipient MX Inbound Node" }
    ],
    infrastructure: {
      country: "Sweden",
      city: "Stockholm",
      isp: "Mullvad VPN AB",
      asn: "AS39351 (Mullvad Privacy Network)",
      earliestIp: "185.181.61.15",
      confidence: "LOW",
      caveat: "Origin IP is an anonymizing commercial VPN exit node. Geolocation reflects the proxy gateway, not necessarily the physical actor."
    },
    campaign: {
      name: "HigherEd Executive Impersonation Syndicate",
      clusterId: "CAMP-2026-EDU-BEC-08",
      relatedEmailsCount: 4,
      relatedDomains: ["engineering-college.edu.in (spoofed)", "gmail.com (freemail reply)"],
      relatedIps: ["185.181.61.15", "89.163.142.77"],
      threatActorType: "CEO / Principal Fraud Business Email Compromise",
      groupingReason: "Shared open relay infrastructure, identical BEC template structure targeting higher education institutions"
    },
    explainableScore: [
      { name: "Executive identity spoofing with reply redirect", weight: "+30", desc: "Claims to be the college principal but routes replies to a personal Gmail account", technical: "Executive Display-Name Spoofing & Reply-To Hijack" },
      { name: "Unauthorized relay server", weight: "+25", desc: "Email was relayed through an unauthorized European VPS not associated with the college", technical: "Unauthenticated Relay Server (SPF/DMARC Fail)" },
      { name: "Financial request with pressure tactics", weight: "+20", desc: "Requests Rs. 85,000 via UPI while claiming inability to take phone calls — classic BEC isolation", technical: "Coercive Social Engineering / Financial Request" },
      { name: "VPN-anonymized origin", weight: "+11", desc: "Earliest hop traces to a known commercial VPN exit node, obscuring the actual sender location", technical: "Commercial VPN Origin Anonymizer" }
    ],
    emailBody: `Dear Professor,

I am currently locked in an emergency closed-door meeting regarding tomorrow's NAAC visit.
I am unable to answer phone calls until 4:00 PM.

We urgently need to disburse an emergency honorarium advance of Rs. 85,000.

UPI ID: emergency.naac.advance@okhdfcbank

Kindly reply with the screenshot. Treat this matter with utmost discretion.`,
    rawContent: `Delivered-To: hod.cse@engineering-college.edu.in
Received: from mail-relay-open.cloudvps-host.de (89.163.142.77) by mx.google.com; Mon, 31 Aug 2026 10:14:02 +0530
Received: from unknown (HELO proxy-vpn-node.mullvad-exit.org) (185.181.61.15) by mail-relay-open.cloudvps-host.de; Mon, 31 Aug 2026 11:43:20 +0200
Authentication-Results: mx.google.com; spf=softfail; dkim=neutral; dmarc=fail header.from=engineering-college.edu.in
From: "Dr. Arvind Sharma (Principal)" <principal@engineering-college.edu.in>
Reply-To: principal.office.execdesk@gmail.com
To: hod.cse@engineering-college.edu.in
Subject: URGENT: Confidential Administrative Assistance Required - Immediate Fund Transfer for NAAC Inspection
Date: Mon, 31 Aug 2026 10:13:10 +0530

Dear Professor,
I am currently locked in an emergency closed-door meeting regarding tomorrow's NAAC visit.
I am unable to answer phone calls until 4:00 PM.
We urgently need to disburse an emergency honorarium advance of Rs. 85,000.
UPI ID: emergency.naac.advance@okhdfcbank
Kindly reply with the screenshot. Treat this matter with utmost discretion.`
  },

  income_tax: {
    id: "CASE-2026-ITD-81203",
    title: "Income Tax Department Refund Scam",
    file: "income_tax_refund_scam.eml",
    subject: "Notice of Approved Tax Refund of Rs. 42,850 for Assessment Year 2025-26 - Action Pending",
    from: '"Income Tax Department (E-Filing Portal)" <donotreply@incometax.gov.in>',
    replyTo: "refund-disbursement@incometaxindia-refund.online",
    to: "taxpayer.citizen@gmail.com",
    date: "Mon, 31 Aug 2026 16:29:45 +0530",
    messageId: "<ITD-REFUND-2026-98120349@incometaxindia-refund.online>",
    classification: "PHISHING",
    riskScore: 92,
    riskLevel: "critical",
    isDemo: true,
    auth: {
      spf: { status: "FAIL", note: "domain donotreply@incometax.gov.in does not designate 178.62.204.99 as permitted sender", explanation: "The sending server is not authorized by the government domain's SPF record." },
      dkim: { status: "FAIL", note: "Cryptographic signature validation failed (invalid hash)", explanation: "The email's digital signature does not match, meaning the content may have been tampered with." },
      dmarc: { status: "FAIL", note: "p=REJECT policy strictly enforced by Government of India domain", explanation: "The government domain has a strict DMARC policy that rejects unauthorized emails — this email violates that policy." },
      alignment: { status: "MISMATCH", note: "From: incometax.gov.in vs Reply-To: incometaxindia-refund.online", explanation: "Replies go to a lookalike domain (.online TLD) instead of the real government domain (.gov.in)." }
    },
    nlp: {
      urgencyScore: 89,
      sentiment: "Government Impersonation / False Financial Reward",
      triggers: [
        { text: "Notice of Approved Tax Refund", type: "warning" },
        { text: "Rs. 42,850", type: "info" },
        { text: "within 2 hours", type: "critical" },
        { text: "verify your PAN, Aadhaar and preferred bank account", type: "critical" },
        { text: "Failure to claim within 48 hours will result in forfeiture", type: "critical" }
      ],
      socialEngineeringFlags: [
        "Government Body Impersonation (Income Tax Dept)",
        "Financial Incentive / False Lure (Refund)",
        "Sensitive PII & Banking Credential Theft"
      ]
    },
    urls: [
      {
        url: "https://incometaxindia-refund.online/claim/verify?pan=ABCDE1234F",
        domain: "incometaxindia-refund.online",
        age: "1 day old (Registered 30-Aug-2026)",
        registrar: "Hostinger International Ltd",
        vtHits: "23 / 92 security vendors flagged Phishing",
        ip: "178.62.204.99",
        status: "MALICIOUS"
      }
    ],
    relays: [
      { hop: 0, ip: "193.106.191.242", host: "localhost (unknown)", location: "Kyiv, Ukraine", lat: 50.4501, lng: 30.5234, isp: "Cloud Hosted Server", note: "Earliest Source Node" },
      { hop: 1, ip: "178.62.204.99", host: "mx-outbound.hostinger-spoof-node.xyz", location: "London, United Kingdom", lat: 51.5074, lng: -0.1278, isp: "DigitalOcean Cloud VPS", note: "Outbound Spoof Gateway" },
      { hop: 2, ip: "209.85.208.65", host: "mx.google.com", location: "Mountain View, CA, USA", lat: 37.3861, lng: -122.0839, isp: "Google LLC Gateway", note: "Recipient MX Inbound Node" }
    ],
    infrastructure: {
      country: "Ukraine",
      city: "Kyiv",
      isp: "Cloud Infrastructure Host",
      asn: "AS51852",
      earliestIp: "193.106.191.242",
      confidence: "MEDIUM",
      caveat: "Earliest hop identified from Received chain. Phishing portal hosted on DigitalOcean UK IP."
    },
    campaign: {
      name: "ITD Tax Season Phishing Wave 2026",
      clusterId: "CAMP-2026-GOV-ITD-11",
      relatedEmailsCount: 7,
      relatedDomains: ["incometaxindia-refund.online", "incometax-gov-in.cc", "hostinger-spoof-node.xyz"],
      relatedIps: ["193.106.191.242", "178.62.204.99"],
      threatActorType: "Government Impersonation Tax Lure Syndicate",
      groupingReason: "Shared hosting infrastructure, common government domain typosquatting pattern, identical refund lure template"
    },
    explainableScore: [
      { name: "Government domain spoofed", weight: "+32", desc: "SPF and DMARC rejected on a protected government (.gov.in) domain — strong forgery indicator", technical: "Government Domain Spoof (incometax.gov.in)" },
      { name: "Typosquatted lookalike domain", weight: "+25", desc: "The linked domain incometaxindia-refund.online was registered just yesterday", technical: "Phishing Domain Typosquatting / Lookalike" },
      { name: "High threat intelligence hit rate", weight: "+20", desc: "URL is blacklisted by 23 out of 92 security engines on VirusTotal and PhishTank", technical: "High Threat Intelligence Hit Rate (23 engines)" },
      { name: "Artificial deadline pressure", weight: "+15", desc: "Uses forfeiture threat and tight deadline to pressure the victim into acting quickly", technical: "Forfeiture Threat / Artificial Deadline" }
    ],
    emailBody: `Income Tax Department, Government of India

Approved refund: Rs. 42,850.

To claim your pending refund within 2 hours, verify PAN, Aadhaar & bank details:

=> https://incometaxindia-refund.online/claim/verify?pan=ABCDE1234F

Note: Failure to claim within 48 hours will result in forfeiture.`,
    rawContent: `Delivered-To: taxpayer.citizen@gmail.com
Received: from mx-outbound.hostinger-spoof-node.xyz (178.62.204.99) by mx.google.com; Mon, 31 Aug 2026 16:30:22 +0530
Received: from localhost (193.106.191.242) by mx-outbound.hostinger-spoof-node.xyz; Mon, 31 Aug 2026 13:59:10 +0200
Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail header.from=incometax.gov.in
From: "Income Tax Department (E-Filing Portal)" <donotreply@incometax.gov.in>
Reply-To: refund-disbursement@incometaxindia-refund.online
To: taxpayer.citizen@gmail.com
Subject: Notice of Approved Tax Refund of Rs. 42,850 for Assessment Year 2025-26 - Action Pending
Date: Mon, 31 Aug 2026 16:29:45 +0530

Income Tax Department, Government of India
Approved refund: Rs. 42,850.
To claim your pending refund within 2 hours, verify PAN, Aadhaar & bank details:
=> https://incometaxindia-refund.online/claim/verify?pan=ABCDE1234F
Note: Failure to claim within 48 hours will result in forfeiture.`
  },

  google_legit: {
    id: "CASE-2026-LEG-00129",
    title: "Google Security Alert (Legitimate)",
    file: "google_security_legit.eml",
    subject: "Security alert: New sign-in from Chrome on Windows",
    from: '"Google Accounts" <no-reply@accounts.google.com>',
    replyTo: "no-reply@accounts.google.com",
    to: "mriganka.developer@gmail.com",
    date: "Mon, 31 Aug 2026 19:00:12 GMT",
    messageId: "<110328912389102.1725102012093.no-reply@accounts.google.com>",
    classification: "LEGITIMATE",
    riskScore: 2,
    riskLevel: "clean",
    isDemo: true,
    auth: {
      spf: { status: "PASS", note: "domain of gaia.bounces.google.com designates 209.85.208.65 as permitted sender", explanation: "The sending server is explicitly authorized by Google's SPF record." },
      dkim: { status: "PASS", note: "Cryptographic signature matches google.com key (20230601)", explanation: "The email's digital signature is valid, confirming it was sent by Google and hasn't been modified." },
      dmarc: { status: "PASS", note: "Full alignment pass with google.com p=REJECT policy", explanation: "This email fully satisfies Google's strict authentication requirements." },
      alignment: { status: "MATCH", note: "From matches envelope sender and Return-Path perfectly", explanation: "The sender address, reply address, and envelope all match — consistent with a legitimate email." }
    },
    nlp: {
      urgencyScore: 12,
      sentiment: "Standard Informational Security Notification",
      triggers: [],
      socialEngineeringFlags: ["None detected — standard transactional notification"]
    },
    urls: [
      {
        url: "https://myaccount.google.com/notifications",
        domain: "myaccount.google.com",
        age: "27 years old (Google LLC)",
        registrar: "MarkMonitor Inc",
        vtHits: "0 / 92 engines flagged (Safe)",
        ip: "142.250.190.46",
        status: "SAFE"
      }
    ],
    relays: [
      { hop: 0, ip: "209.85.208.65", host: "mail-ed1-f65.google.com", location: "Mountain View, CA, USA", lat: 37.3861, lng: -122.0839, isp: "Google LLC", note: "Authorized Google Outbound MTA" },
      { hop: 1, ip: "2002:a17:906:848d::", host: "mx.google.com", location: "Mountain View, CA, USA", lat: 37.3861, lng: -122.0839, isp: "Google LLC Gateway", note: "Delivered to Target Mailbox" }
    ],
    infrastructure: {
      country: "United States",
      city: "Mountain View, California",
      isp: "Google LLC",
      asn: "AS15169 (Google Infrastructure)",
      earliestIp: "209.85.208.65",
      confidence: "HIGH",
      caveat: "Fully authenticated cryptographic TLS & DKIM chain from Google corporate servers."
    },
    campaign: {
      name: "Legitimate Corporate Traffic",
      clusterId: "LEG-GOOGLE-NOTIFICATIONS",
      relatedEmailsCount: 0,
      relatedDomains: ["google.com", "accounts.google.com"],
      relatedIps: ["209.85.208.65"],
      threatActorType: "None (Legitimate Service)",
      groupingReason: "Verified legitimate traffic from Google's authenticated email infrastructure"
    },
    explainableScore: [
      { name: "Full cryptographic authentication", weight: "-20", desc: "SPF, DKIM, and DMARC all pass — the email is verified from Google's authorized servers", technical: "Full Cryptographic SPF & DKIM Alignment" },
      { name: "Trusted established domain", weight: "-10", desc: "google.com is a whitelisted, highly trusted domain with 27+ years of registration history", technical: "Official Google Domain & High Domain Age" },
      { name: "Clean threat intelligence", weight: "-5", desc: "All URLs point to official Google HTTPS properties with zero blacklist hits", technical: "Zero Blacklist or Malicious URL Hits" }
    ],
    emailBody: `We noticed a new login to your Google Account from Chrome on Windows 11.

Location: Kolkata, West Bengal, India

If this was you, no action is needed.`,
    rawContent: `Delivered-To: mriganka.developer@gmail.com
Received: from mail-ed1-f65.google.com (209.85.208.65) by mx.google.com; Mon, 31 Aug 2026 12:00:14 -0700
Authentication-Results: mx.google.com; dkim=pass header.i=@google.com; spf=pass; dmarc=pass header.from=google.com
From: "Google Accounts" <no-reply@accounts.google.com>
Reply-To: no-reply@accounts.google.com
To: mriganka.developer@gmail.com
Subject: Security alert: New sign-in from Chrome on Windows
Date: Mon, 31 Aug 2026 19:00:12 GMT

We noticed a new login to your Google Account from Chrome on Windows 11.
Location: Kolkata, West Bengal, India
If this was you, no action is needed.`
  }
};
