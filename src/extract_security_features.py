import os
import re
import numpy as np
import pandas as pd
from urllib.parse import urlparse
import ipaddress


# ==========================================
# CONFIGURATION
# ==========================================

TEXT_PATH = "models/embeddings/email_texts.csv"
OUTPUT_DIR = "models/security_features"

FEATURES_PATH = os.path.join(
    OUTPUT_DIR,
    "security_features.npy"
)

FEATURE_NAMES_PATH = os.path.join(
    OUTPUT_DIR,
    "security_feature_names.csv"
)


# ==========================================
# SECURITY KEYWORDS
# ==========================================

URGENCY_WORDS = [
    "urgent",
    "immediately",
    "immediate",
    "now",
    "asap",
    "action required",
    "act now",
    "hurry",
    "important",
    "warning",
    "alert",
    "expire",
    "expired",
    "deadline"
]

THREAT_WORDS = [
    "suspend",
    "suspended",
    "terminate",
    "terminated",
    "block",
    "blocked",
    "close",
    "closed",
    "delete",
    "deleted",
    "penalty",
    "legal action",
    "arrest",
    "lawsuit",
    "violation"
]

CREDENTIAL_WORDS = [
    "password",
    "passwd",
    "username",
    "login",
    "log in",
    "sign in",
    "signin",
    "credential",
    "credentials",
    "verify your account",
    "verification",
    "authenticate",
    "authentication",
    "otp",
    "pin",
    "security code"
]

FINANCIAL_WORDS = [
    "bank",
    "banking",
    "credit card",
    "debit card",
    "account",
    "payment",
    "transaction",
    "invoice",
    "money",
    "refund",
    "cash",
    "wire transfer",
    "billing",
    "wallet",
    "bitcoin",
    "cryptocurrency"
]

SUSPICIOUS_REQUEST_WORDS = [
    "click here",
    "click the link",
    "verify",
    "confirm",
    "update your account",
    "provide",
    "send",
    "download",
    "open the attachment",
    "enable",
    "install"
]


# ==========================================
# URL REGEX
# ==========================================

URL_PATTERN = re.compile(
    r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+)",
    re.IGNORECASE
)


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def count_keywords(text, keywords):
    """
    Count how many keyword occurrences appear in text.
    """

    text_lower = text.lower()

    count = 0

    for keyword in keywords:
        count += text_lower.count(keyword.lower())

    return count


def extract_urls(text):
    """
    Extract URLs from email text.
    """

    return URL_PATTERN.findall(text)


def is_ip_address(hostname):
    """
    Check whether hostname is an IP address.
    """

    if not hostname:
        return 0

    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def analyze_url(url):
    """
    Extract security-related features from one URL.
    """

    url_lower = url.lower()

    if not url_lower.startswith(("http://", "https://")):
        parsed = urlparse("http://" + url_lower)
    else:
        parsed = urlparse(url_lower)

    hostname = parsed.hostname or ""

    path = parsed.path or ""

    # URL length
    url_length = len(url)

    # HTTPS
    https = 1 if url_lower.startswith("https://") else 0

    # IP address
    ip_url = is_ip_address(hostname)

    # Number of subdomains
    subdomain_count = 0

    if hostname and not ip_url:
        parts = hostname.split(".")

        if len(parts) > 2:
            subdomain_count = len(parts) - 2

    # Suspicious characters
    suspicious_chars = sum(
        url.count(c)
        for c in ["@", "%", "-", "_", "="]
    )

    # Number of dots
    dot_count = url.count(".")

    # Number of digits
    digit_count = sum(c.isdigit() for c in url)

    # URL contains @ symbol
    contains_at = 1 if "@" in url else 0

    # URL uses a port
    contains_port = 1 if parsed.port else 0

    # Suspicious TLDs
    suspicious_tlds = [
        ".xyz",
        ".top",
        ".click",
        ".link",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".work",
        ".zip",
        ".review",
        ".country"
    ]

    suspicious_tld = 1 if any(
        hostname.endswith(tld)
        for tld in suspicious_tlds
    ) else 0

    # URL shortening services
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly"
    ]

    shortened_url = 1 if any(
        domain in hostname
        for domain in shorteners
    ) else 0

    return [
        url_length,
        https,
        ip_url,
        subdomain_count,
        suspicious_chars,
        dot_count,
        digit_count,
        contains_at,
        contains_port,
        suspicious_tld,
        shortened_url
    ]


# ==========================================
# FEATURE EXTRACTION
# ==========================================

def extract_features(text):

    # --------------------------------------
    # BASIC TEXT FEATURES
    # --------------------------------------

    character_count = len(text)

    word_count = len(text.split())

    line_count = text.count("\n") + 1

    uppercase_count = sum(
        1 for word in text.split()
        if len(word) > 1 and word.isupper()
    )

    exclamation_count = text.count("!")

    question_count = text.count("?")

    dollar_count = text.count("$")

    digit_count = sum(
        1 for char in text
        if char.isdigit()
    )

    # --------------------------------------
    # KEYWORD FEATURES
    # --------------------------------------

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

    # --------------------------------------
    # URL FEATURES
    # --------------------------------------

    urls = extract_urls(text)

    url_count = len(urls)

    total_url_length = 0

    max_url_length = 0

    ip_url_count = 0

    suspicious_tld_count = 0

    shortened_url_count = 0

    https_url_count = 0

    subdomain_total = 0

    suspicious_character_total = 0

    for url in urls:

        (
            url_length,
            https,
            ip_url,
            subdomain_count,
            suspicious_chars,
            dot_count,
            url_digits,
            contains_at,
            contains_port,
            suspicious_tld,
            shortened_url
        ) = analyze_url(url)

        total_url_length += url_length

        max_url_length = max(
            max_url_length,
            url_length
        )

        ip_url_count += ip_url

        suspicious_tld_count += suspicious_tld

        shortened_url_count += shortened_url

        https_url_count += https

        subdomain_total += subdomain_count

        suspicious_character_total += suspicious_chars

    # --------------------------------------
    # HTML FEATURES
    # --------------------------------------

    html_tag_count = len(
        re.findall(
            r"<[a-zA-Z][^>]*>",
            text
        )
    )

    href_count = len(
        re.findall(
            r"<a\s+[^>]*href\s*=",
            text,
            re.IGNORECASE
        )
    )

    form_count = len(
        re.findall(
            r"<form\b",
            text,
            re.IGNORECASE
        )
    )

    script_count = len(
        re.findall(
            r"<script\b",
            text,
            re.IGNORECASE
        )
    )

    iframe_count = len(
        re.findall(
            r"<iframe\b",
            text,
            re.IGNORECASE
        )
    )

    hidden_element_count = len(
        re.findall(
            r"display\s*:\s*none|visibility\s*:\s*hidden",
            text,
            re.IGNORECASE
        )
    )

    # --------------------------------------
    # EMAIL STRUCTURE FEATURES
    # --------------------------------------

    has_html = 1 if re.search(
        r"<html|<body|<div|<table|<a\s",
        text,
        re.IGNORECASE
    ) else 0

    has_attachment_word = 1 if re.search(
        r"\battachment\b|\battached\b",
        text,
        re.IGNORECASE
    ) else 0

    has_email_address = len(
        re.findall(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            text
        )
    )

    # --------------------------------------
    # COMBINED FEATURE VECTOR
    # --------------------------------------

    return [
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


# ==========================================
# FEATURE NAMES
# ==========================================

FEATURE_NAMES = [
    "character_count",
    "word_count",
    "line_count",
    "uppercase_count",
    "exclamation_count",
    "question_count",
    "dollar_count",
    "digit_count",

    "urgency_count",
    "threat_count",
    "credential_count",
    "financial_count",
    "suspicious_request_count",

    "url_count",
    "total_url_length",
    "max_url_length",
    "ip_url_count",
    "suspicious_tld_count",
    "shortened_url_count",
    "https_url_count",
    "subdomain_total",
    "suspicious_character_total",

    "html_tag_count",
    "href_count",
    "form_count",
    "script_count",
    "iframe_count",
    "hidden_element_count",

    "has_html",
    "has_attachment_word",
    "has_email_address"
]


# ==========================================
# MAIN
# ==========================================

print("==========================================")
print("       SECURITY FEATURE EXTRACTION")
print("==========================================")

print("\nLoading email texts...")

df = pd.read_csv(TEXT_PATH)

texts = df["text_combined"].astype(str).tolist()

print(f"Emails loaded: {len(texts)}")

print("\nExtracting security features...")

features = []

for index, text in enumerate(texts):

    features.append(
        extract_features(text)
    )

    if (index + 1) % 5000 == 0:
        print(
            f"Processed: {index + 1}/{len(texts)}"
        )


# ==========================================
# CONVERT TO NUMPY
# ==========================================

features = np.asarray(
    features,
    dtype=np.float32
)


# ==========================================
# SAVE
# ==========================================

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)

np.save(
    FEATURES_PATH,
    features
)

pd.DataFrame({
    "feature_name": FEATURE_NAMES
}).to_csv(
    FEATURE_NAMES_PATH,
    index=False
)


# ==========================================
# INFORMATION
# ==========================================

print("\n==========================================")
print("       SECURITY FEATURES COMPLETE")
print("==========================================")

print(
    f"\nFeature matrix shape: {features.shape}"
)

print(
    f"Number of features: {features.shape[1]}"
)

print("\nSaved files:")

print(FEATURES_PATH)

print(FEATURE_NAMES_PATH)

print("\n==========================================")
print("                 DONE")
print("==========================================")