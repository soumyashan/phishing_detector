import re
import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

from final_detector import detect_phishing
from security_risk import extract_security_features


# ============================================================
# EXPLANATION ENGINE
# ============================================================

def generate_explanation(email_text):

    result = detect_phishing(email_text)

    features = extract_security_features(
        email_text
    )

    reasons = []

    text = email_text.lower()

    # --------------------------------------------------------
    # Security indicators
    # --------------------------------------------------------

    if features[13] > 0:
        reasons.append(
            f"Suspicious URL activity detected "
            f"({int(features[13])} URL(s))"
        )

    if features[16] > 0:
        reasons.append(
            "IP-address based URL detected"
        )

    if features[17] > 0:
        reasons.append(
            "Suspicious URL domain extension detected"
        )

    if features[18] > 0:
        reasons.append(
            "URL shortening service detected"
        )

    if features[8] > 0:
        reasons.append(
            "Urgency or pressure language detected"
        )

    if features[9] > 0:
        reasons.append(
            "Threatening or account-warning language detected"
        )

    if features[10] > 0:
        reasons.append(
            "Credential or login information requested"
        )

    if features[11] > 0:
        reasons.append(
            "Financial or payment-related information detected"
        )

    if features[12] > 0:
        reasons.append(
            "Suspicious action/request detected"
        )

    if features[25] > 0:
        reasons.append(
            "HTML form detected"
        )

    if features[26] > 0:
        reasons.append(
            "JavaScript detected in email"
        )

    if features[27] > 0:
        reasons.append(
            "Embedded iframe detected"
        )

    if features[28] > 0:
        reasons.append(
            "Hidden HTML element detected"
        )

    if features[29] > 0:
        reasons.append(
            "HTML content detected"
        )

    if features[30] > 0:
        reasons.append(
            "Email address detected in content"
        )

    if features[29] == 0 and features[13] == 0:
        # No obvious structural/security indicators.
        # The AI model may still detect semantic phishing.
        if result["ai_risk_score"] >= 70:
            reasons.append(
                "AI model detected suspicious semantic patterns"
            )

    # --------------------------------------------------------
    # AI indicator
    # --------------------------------------------------------

    if result["ai_risk_score"] >= 80:

        reasons.append(
            "AI model confidence strongly indicates phishing"
        )

    elif result["ai_risk_score"] >= 60:

        reasons.append(
            "AI model detected several suspicious language patterns"
        )

    elif result["ai_risk_score"] >= 40:

        reasons.append(
            "AI model detected moderately suspicious content"
        )

    # --------------------------------------------------------
    # If no reasons
    # --------------------------------------------------------

    if not reasons:

        reasons.append(
            "No significant phishing indicators detected"
        )

    return {
        "prediction": result["label"],
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "phishing_probability": result[
            "phishing_probability"
        ],
        "ai_risk_score": result[
            "ai_risk_score"
        ],
        "security_risk_score": result[
            "security_risk_score"
        ],
        "reasons": reasons
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("\n" + "=" * 65)
    print("             PHISHING EXPLANATION ENGINE")
    print("=" * 65)

    test_email = """
    URGENT SECURITY ALERT!

    Your bank account has been suspended.

    Click here immediately to verify your password
    and credit card information:

    http://192.168.1.10/verify

    Failure to verify your account within 24 hours
    will result in permanent account closure.

    Please confirm your identity immediately.
    """

    result = generate_explanation(
        test_email
    )

    print(
        f"\nPrediction          : "
        f"{result['prediction']}"
    )

    print(
        f"Risk Score          : "
        f"{result['risk_score']}/100"
    )

    print(
        f"Risk Level          : "
        f"{result['risk_level']}"
    )

    print(
        f"Phishing Probability: "
        f"{result['phishing_probability']:.4f}"
    )

    print(
        f"AI/SVM Risk         : "
        f"{result['ai_risk_score']}/100"
    )

    print(
        f"Security Risk       : "
        f"{result['security_risk_score']}/100"
    )

    print("\nReasons:")
    for reason in result["reasons"]:
        print(f"  - {reason}")