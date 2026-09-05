# AegisMail Forensics AI

AI-powered phishing email detection and forensic analysis system built for cybersecurity investigation workflows.

AegisMail combines machine-learning phishing detection, security-feature analysis, explainable risk scoring, and a FastAPI backend integrated with a forensic investigation dashboard.

## Features

- AI-powered phishing email classification
- Calibrated Linear SVM production model
- TF-IDF text representation
- Probability-based phishing risk scoring
- 31 security-focused email features
- Combined AI + security risk scoring
- Explainable detection reasons
- `.eml` email analysis
- FastAPI REST API
- AegisMail forensic investigation dashboard

## Detection Pipeline

```text
Email / .eml
    |
Email Parsing
    |
TF-IDF Vectorization
    |
Calibrated Linear SVM
    |
Phishing Probability
    |
AI Risk Score
    |
Security Feature Analysis
    |
Security Risk Score
    |
Final Risk Score
    |
Explainable Result
    |
AegisMail Forensics Dashboard
```

## Model Performance

| Model | Accuracy | Precision | Recall | F1 Score |
|---|---:|---:|---:|---:|
| Logistic Regression + TF-IDF | 98.52% | 98.36% | 98.81% | 98.59% |
| Linear SVM + TF-IDF | 99.21% | 99.10% | 99.38% | 99.24% |
| **Calibrated Linear SVM (Production)** | **99.17%** | **99.01%** | **99.40%** | **99.21%** |

The calibrated Linear SVM is the production model because it provides strong classification performance together with calibrated phishing probabilities for risk scoring.

## Risk Scoring

The final risk score combines AI detection and security-feature analysis:

```text
Final Risk = 0.80 × AI Risk + 0.20 × Security Risk
```

Risk levels:

| Score | Level |
|---:|---|
| 0–20 | Very Low |
| 20–40 | Low |
| 40–60 | Medium |
| 60–80 | High |
| 80–100 | Critical |

A final score of 50 or higher is classified as `PHISHING`.

## Explainability

Each analyzed email provides:

- Phishing or legitimate classification
- Phishing probability
- AI/SVM risk score
- Security risk score
- Final combined risk score
- Risk level
- Detection reasons

## Project Structure

```text
phishing_detector/
├── data/
│   └── phishing_email.csv
├── frontend/
│   ├── index.html
│   ├── app.js
│   ├── pages.js
│   ├── components.js
│   ├── ai-integration.js
│   └── styles.css
├── models/
│   ├── phishing_calibrated_svm.pkl
│   ├── tfidf_vectorizer_calibrated.pkl
│   └── security_features/
├── src/
│   ├── api.py
│   ├── final_detector.py
│   ├── explain_detector.py
│   ├── risk_engine.py
│   ├── security_risk.py
│   └── extract_security_features.py
├── .gitignore
├── LICENSE
├── README.md
└── requirements.txt
```

## Running the Project

Create and activate the virtual environment:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Start the FastAPI server:

```powershell
uvicorn src.api:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

## API

Health check:

```text
GET /health
```

Prediction endpoint:

```text
POST /predict
```

Example request:

```json
{
  "email_text": "Urgent account verification required. Click the link immediately."
}
```

## Security and Data Handling

Large training data and generated MiniLM embeddings are intentionally excluded from GitHub.

Production model artifacts required by the API are tracked in the repository.

Do not commit credentials, API keys, private email content, or other sensitive information.

## Experimental Work

The project also contains experimental work involving:

- Sentence Transformers / MiniLM embeddings
- Security-feature fusion
- XGBoost experiments

These experiments were evaluated separately and are not used by the production detection pipeline.

## License

This project is licensed under the MIT License. See `LICENSE` for details.

## Author

**Soumyashan**

Built as part of cybersecurity and AI/ML development work for **SIH 2026**.