import re
import numpy as np


# ============================================================
# SECURITY PATTERNS
# ============================================================

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+|www\.[^\s<>\"]+",
    re.IGNORECASE
)

IP_URL_PATTERN = re.compile(
    r"https?://(?:\d{1,3}\.){3}\d{1,3}",
    re.IGNORECASE
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".link",
    ".work",
    ".live",
    ".online",
    ".site",
    ".club",
    ".info",
    ".biz",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq"
}

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly"
}

URGENCY_WORDS = [
    "urgent",
    "immediately",
    "action required",
    "act now",
    "verify now",
    "within 24 hours",
    "within 48 hours",
    "expires",
    "suspended",
    "account locked",
    "final warning"
]

THREAT_WORDS = [
    "terminate",
    "blocked",
    "suspended",
    "closed",
    "legal action",
    "penalty",
    "arrest",
    "warning",
    "unauthorized"
]

CREDENTIAL_WORDS = [
    "password",
    "username",
    "login",
    "sign in",
    "verify your account",
    "credential",
    "security code",
    "otp",
    "pin"
]

FINANCIAL_WORDS = [
    "bank",
    "credit card",
    "debit card",
    "payment",
    "invoice",
    "refund",
    "money",
    "transfer",
    "transaction",
    "account number"
]

SUSPICIOUS_REQUEST_WORDS = [
    "click here",
    "click the link",
    "verify",
    "confirm your identity",
    "update your information",
    "send your",
    "provide your",
    "download attachment"
]


# ============================================================
# HELPER
# ============================================================

def count_keywords(text, keywords):

    text_lower = text.lower()

    return sum(
        text_lower.count(keyword)
        for keyword in keywords
    )


# ============================================================
# SECURITY FEATURE EXTRACTION
# ============================================================

def extract_security_features(text):

    text = str(text)

    text_lower = text.lower()

    # -----------------------------
    # Basic text
    # -----------------------------

    character_count = len(text)

    word_count = len(
        re.findall(r"\b\w+\b", text)
    )

    line_count = len(
        text.splitlines()
    )

    uppercase_count = sum(
        1 for c in text
        if c.isupper()
    )

    exclamation_count = text.count("!")

    question_count = text.count("?")

    dollar_count = text.count("$")

    digit_count = sum(
        1 for c in text
        if c.isdigit()
    )

    # -----------------------------
    # Keywords
    # -----------------------------

    urgency_count = count_keywords(
        text,
        URGENCY_WORDS
    )

    threat_count = count_keywords(
        text,
        THREAT_WORDS
    )

    credential_count = count_keywords(
        text,
        CREDENTIAL_WORDS
    )

    financial_count = count_keywords(
        text,
        FINANCIAL_WORDS
    )

    suspicious_request_count = count_keywords(
        text,
        SUSPICIOUS_REQUEST_WORDS
    )

    # -----------------------------
    # URLs
    # -----------------------------

    urls = URL_PATTERN.findall(text)

    url_count = len(urls)

    total_url_length = sum(
        len(url)
        for url in urls
    )

    max_url_length = max(
        [len(url) for url in urls],
        default=0
    )

    ip_url_count = len(
        IP_URL_PATTERN.findall(text)
    )

    suspicious_tld_count = 0

    shortened_url_count = 0

    https_url_count = 0

    subdomain_total = 0

    suspicious_character_total = 0

    for url in urls:

        url_lower = url.lower()

        # Suspicious TLD
        if any(
            tld in url_lower
            for tld in SUSPICIOUS_TLDS
        ):
            suspicious_tld_count += 1

        # URL shortener
        if any(
            shortener in url_lower
            for shortener in SHORTENERS
        ):
            shortened_url_count += 1

        # HTTPS
        if url_lower.startswith("https://"):
            https_url_count += 1

        # Subdomains
        domain_match = re.search(
            r"https?://([^/]+)",
            url_lower
        )

        if domain_match:

            domain = domain_match.group(1)

            domain = domain.split("@")[-1]

            domain = domain.split(":")[0]

            parts = domain.split(".")

            if len(parts) > 2:
                subdomain_total += len(parts) - 2

        # Suspicious URL characters
        suspicious_character_total += sum(
            url.count(character)
            for character in [
                "@",
                "-",
                "_",
                "%",
                "="
            ]
        )

    # -----------------------------
    # HTML
    # -----------------------------

    html_tag_count = len(
        re.findall(
            r"<[^>]+>",
            text
        )
    )

    href_count = len(
        re.findall(
            r"<a\s+[^>]*href=",
            text_lower
        )
    )

    form_count = len(
        re.findall(
            r"<form",
            text_lower
        )
    )

    script_count = len(
        re.findall(
            r"<script",
            text_lower
        )
    )

    iframe_count = len(
        re.findall(
            r"<iframe",
            text_lower
        )
    )

    hidden_element_count = len(
        re.findall(
            r"display\s*:\s*none|visibility\s*:\s*hidden|type\s*=\s*[\"']hidden",
            text_lower
        )
    )

    has_html = int(
        bool(
            re.search(
                r"<html|<body|<div|<table|<a\s",
                text_lower
            )
        )
    )

    # -----------------------------
    # Structure
    # -----------------------------

    has_attachment_word = int(
        any(
            word in text_lower
            for word in [
                "attachment",
                "attached file",
                "attached document"
            ]
        )
    )

    has_email_address = int(
        bool(
            EMAIL_PATTERN.search(text)
        )
    )

    # ========================================================
    # FEATURE VECTOR
    # ========================================================

    features = [
        character_count,
        word_count,
        line_count,
        uppercase_count,
        exclamation_count,
        question_count,
        dollar_count,
        digit_count,

        urgency_count,
        threat_count,
        credential_count,
        financial_count,
        suspicious_request_count,

        url_count,
        total_url_length,
        max_url_length,
        ip_url_count,
        suspicious_tld_count,
        shortened_url_count,
        https_url_count,
        subdomain_total,
        suspicious_character_total,

        html_tag_count,
        href_count,
        form_count,
        script_count,
        iframe_count,
        hidden_element_count,

        has_html,
        has_attachment_word,
        has_email_address
    ]

    return np.array(
        features,
        dtype=np.float32
    )


# ============================================================
# SECURITY RISK SCORE
# ============================================================

def calculate_security_risk(text):

    features = extract_security_features(text)

    (
        character_count,
        word_count,
        line_count,
        uppercase_count,
        exclamation_count,
        question_count,
        dollar_count,
        digit_count,

        urgency_count,
        threat_count,
        credential_count,
        financial_count,
        suspicious_request_count,

        url_count,
        total_url_length,
        max_url_length,
        ip_url_count,
        suspicious_tld_count,
        shortened_url_count,
        https_url_count,
        subdomain_total,
        suspicious_character_total,

        html_tag_count,
        href_count,
        form_count,
        script_count,
        iframe_count,
        hidden_element_count,

        has_html,
        has_attachment_word,
        has_email_address
    ) = features

    score = 0

    # Urgency
    score += min(urgency_count * 5, 15)

    # Threats
    score += min(threat_count * 5, 15)

    # Credential requests
    score += min(credential_count * 5, 15)

    # Financial content
    score += min(financial_count * 3, 10)

    # Suspicious requests
    score += min(
        suspicious_request_count * 5,
        15
    )

    # URLs
    score += min(url_count * 2, 6)

    # IP-based URL
    score += min(ip_url_count * 10, 20)

    # Suspicious TLD
    score += min(
        suspicious_tld_count * 8,
        16
    )

    # Shortened URLs
    score += min(
        shortened_url_count * 6,
        12
    )

    # Suspicious URL characters
    score += min(
        suspicious_character_total,
        10
    )

    # HTML forms
    score += min(form_count * 8, 16)

    # Scripts
    score += min(script_count * 5, 10)

    # Iframes
    score += min(iframe_count * 8, 16)

    # Hidden elements
    score += min(
        hidden_element_count * 8,
        16
    )

    return min(float(score), 100.0)


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("\n" + "=" * 50)
    print("       SECURITY FEATURE ENGINE")
    print("=" * 50)

    test_emails = [

        """
        URGENT!

        Your bank account has been suspended.

        Click here immediately:
        http://192.168.1.10/verify

        Verify your password and credit card information
        within 24 hours or your account will be closed.
        """,

        """
        Hi John,

        The meeting has been scheduled for tomorrow
        at 10:00 AM in the conference room.

        Regards,
        Team
        """
    ]

    for i, email in enumerate(
        test_emails,
        1
    ):

        print(f"\nTEST EMAIL {i}")
        print("-" * 50)

        features = extract_security_features(
            email
        )

        security_score = calculate_security_risk(
            email
        )

        print(
            f"Security feature count : "
            f"{len(features)}"
        )

        print(
            f"Security Risk Score    : "
            f"{security_score}/100"
        )

        print(
            f"URL count              : "
            f"{int(features[13])}"
        )

        print(
            f"Urgency count          : "
            f"{int(features[8])}"
        )

        print(
            f"Credential count       : "
            f"{int(features[10])}"
        )

        print(
            f"Financial count        : "
            f"{int(features[11])}"
        )

        print(
            f"Suspicious request     : "
            f"{int(features[12])}"
        )