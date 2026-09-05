import os
import sys

# Allow importing files from src/
sys.path.append(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

from risk_engine import predict_email
from security_risk import calculate_security_risk


# ============================================================
# FINAL RISK ENGINE
# ============================================================

def detect_phishing(email_text):

    # --------------------------------------------------------
    # 1. AI / SVM RISK
    # --------------------------------------------------------

    svm_result = predict_email(email_text)

    svm_risk = svm_result["risk_score"]

    # --------------------------------------------------------
    # 2. SECURITY RISK
    # --------------------------------------------------------

    security_risk = calculate_security_risk(
        email_text
    )

    # --------------------------------------------------------
    # 3. COMBINED RISK
    # --------------------------------------------------------
    #
    # SVM is the primary detector because it has the
    # strongest validation performance.
    #
    # Security analysis acts as an additional signal.
    #
    # 80% AI + 20% Security
    # --------------------------------------------------------

    final_risk = (
        0.80 * svm_risk
        +
        0.20 * security_risk
    )

    final_risk = round(
        min(max(final_risk, 0), 100),
        2
    )

    # --------------------------------------------------------
    # 4. FINAL RISK LEVEL
    # --------------------------------------------------------

    if final_risk < 20:
        risk_level = "Very Low"

    elif final_risk < 40:
        risk_level = "Low"

    elif final_risk < 60:
        risk_level = "Medium"

    elif final_risk < 80:
        risk_level = "High"

    else:
        risk_level = "Critical"

    # --------------------------------------------------------
    # 5. FINAL CLASSIFICATION
    # --------------------------------------------------------

    if final_risk >= 50:
        final_label = "PHISHING"
        final_prediction = 1

    else:
        final_label = "LEGITIMATE"
        final_prediction = 0

    # --------------------------------------------------------
    # 6. RETURN RESULT
    # --------------------------------------------------------

    return {
        "prediction": final_prediction,
        "label": final_label,
        "risk_score": final_risk,
        "risk_level": risk_level,

        "ai_risk_score": svm_risk,

        "phishing_probability":
            svm_result["phishing_probability"],

        "security_risk_score":
            security_risk
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("\n" + "=" * 60)
    print("             FINAL PHISHING DETECTOR")
    print("=" * 60)

    test_emails = [

        """
        URGENT SECURITY ALERT!

        Your bank account has been suspended.

        Click here immediately to verify your password
        and credit card information:

        http://192.168.1.10/verify

        Failure to verify your account within 24 hours
        will result in permanent account closure.

        Please confirm your identity immediately.
        """,

        """
        Hi John,

        The meeting has been scheduled for tomorrow
        at 10:00 AM in the conference room.

        Please bring the project report.

        Regards,
        Team
        """,

        """
        Dear customer,

        Your account requires verification.

        Please log in to your account and review
        your recent activity.

        Thank you,
        Customer Support
        """
    ]

    for i, email in enumerate(
        test_emails,
        1
    ):

        print(f"\nTEST EMAIL {i}")
        print("-" * 60)

        result = detect_phishing(email)

        print(
            f"Final Prediction       : "
            f"{result['label']}"
        )

        print(
            f"Final Risk Score       : "
            f"{result['risk_score']}/100"
        )

        print(
            f"Risk Level             : "
            f"{result['risk_level']}"
        )

        print(
            f"AI/SVM Risk            : "
            f"{result['ai_risk_score']}/100"
        )

        print(
            f"Phishing Probability   : "
            f"{result['phishing_probability']:.4f}"
        )

        print(
            f"Security Risk          : "
            f"{result['security_risk_score']}/100"
        )