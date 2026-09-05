import os
import joblib
import numpy as np


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

SVM_PATH = os.path.join(
    BASE_DIR,
    "models",
    "phishing_calibrated_svm.pkl"
)

VECTORIZER_PATH = os.path.join(
    BASE_DIR,
    "models",
    "tfidf_vectorizer_calibrated.pkl"
)


# ============================================================
# LOAD MODELS
# ============================================================

print("Loading phishing detection models...")

svm_model = joblib.load(SVM_PATH)

vectorizer = joblib.load(VECTORIZER_PATH)

print("Models loaded successfully.")


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk_score(phishing_probability):

    risk_score = float(phishing_probability) * 100

    return round(risk_score, 2)


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(risk_score):

    if risk_score < 20:
        return "Very Low"

    elif risk_score < 40:
        return "Low"

    elif risk_score < 60:
        return "Medium"

    elif risk_score < 80:
        return "High"

    else:
        return "Critical"


# ============================================================
# EMAIL PREDICTION
# ============================================================

def predict_email(text):

    if not isinstance(text, str):
        text = str(text)

    if not text.strip():
        raise ValueError("Email text cannot be empty.")

    # Convert email text into TF-IDF
    tfidf_features = vectorizer.transform([text])

    # Get calibrated probabilities
    probabilities = svm_model.predict_proba(
        tfidf_features
    )[0]

    # Find phishing class
    classes = svm_model.classes_

    phishing_index = np.where(
        classes == 1
    )[0][0]

    phishing_probability = probabilities[
        phishing_index
    ]

    # Final prediction
    prediction = (
        1
        if phishing_probability >= 0.5
        else 0
    )

    # Risk score
    risk_score = calculate_risk_score(
        phishing_probability
    )

    # Risk level
    risk_level = get_risk_level(
        risk_score
    )

    return {
        "prediction": prediction,

        "label": (
            "PHISHING"
            if prediction == 1
            else "LEGITIMATE"
        ),

        "phishing_probability": round(
            float(phishing_probability),
            4
        ),

        "risk_score": risk_score,

        "risk_level": risk_level
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("\n" + "=" * 50)
    print("          PHISHING RISK ENGINE")
    print("=" * 50)

    test_emails = [

        """
        Dear customer,

        Your account has been suspended.
        Click here immediately to verify your password
        and credit card information.

        Failure to verify your account within 24 hours
        will result in permanent account closure.
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

        result = predict_email(email)

        print(
            f"Prediction           : "
            f"{result['label']}"
        )

        print(
            f"Phishing Probability : "
            f"{result['phishing_probability']:.4f}"
        )

        print(
            f"Risk Score           : "
            f"{result['risk_score']}/100"
        )

        print(
            f"Risk Level           : "
            f"{result['risk_level']}"
        )