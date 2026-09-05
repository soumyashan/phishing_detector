import pandas as pd
import numpy as np
import os
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# 1. LOAD DATASET
# ============================================================

print("\n==========================================")
print("       PHISHING EMAIL AI TRAINING")
print("==========================================\n")

DATA_PATH = "data/phishing_email.csv"

print("Loading dataset...")

df = pd.read_csv(DATA_PATH)

print(f"Total emails: {len(df)}")


# ============================================================
# 2. CLEAN DATA
# ============================================================

print("\nCleaning dataset...")

df = df[["text_combined", "label"]]

df = df.dropna()

df["text_combined"] = df["text_combined"].astype(str)

# Remove empty emails
df = df[df["text_combined"].str.strip() != ""]

# Remove duplicate emails
df = df.drop_duplicates(subset=["text_combined"])

print(f"Emails after cleaning: {len(df)}")


# ============================================================
# 3. CHECK LABELS
# ============================================================

print("\nLabel distribution:")

print(df["label"].value_counts())

print("\nLabel percentages:")

print(df["label"].value_counts(normalize=True) * 100)


# ============================================================
# 4. SEPARATE X AND Y
# ============================================================

X = df["text_combined"]

y = df["label"]


# ============================================================
# 5. TRAIN / TEST SPLIT
# ============================================================

print("\nSplitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print(f"Training emails: {len(X_train)}")
print(f"Testing emails: {len(X_test)}")


# ============================================================
# 6. TF-IDF
# ============================================================

print("\nCreating TF-IDF features...")

vectorizer = TfidfVectorizer(
    lowercase=True,
    stop_words="english",
    max_features=50000,
    ngram_range=(1, 2),
    min_df=2
)

X_train_tfidf = vectorizer.fit_transform(X_train)

X_test_tfidf = vectorizer.transform(X_test)

print("TF-IDF shape:")
print(X_train_tfidf.shape)


# ============================================================
# 7. LOGISTIC REGRESSION
# ============================================================

print("\nTraining Logistic Regression...")

model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced"
)

model.fit(X_train_tfidf, y_train)

print("Training completed!")


# ============================================================
# 8. PREDICTIONS
# ============================================================

print("\nTesting model...")

y_pred = model.predict(X_test_tfidf)

y_probability = model.predict_proba(X_test_tfidf)[:, 1]


# ============================================================
# 9. EVALUATION
# ============================================================

accuracy = accuracy_score(y_test, y_pred)

precision = precision_score(y_test, y_pred)

recall = recall_score(y_test, y_pred)

f1 = f1_score(y_test, y_pred)


print("\n==========================================")
print("              MODEL RESULTS")
print("==========================================")

print(f"\nAccuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))


# ============================================================
# 10. SAVE MODEL
# ============================================================

print("\nSaving model...")

os.makedirs("models", exist_ok=True)

joblib.dump(
    model,
    "models/phishing_logistic_model.pkl"
)

joblib.dump(
    vectorizer,
    "models/tfidf_vectorizer.pkl"
)

print("\nModel saved successfully!")

print("models/phishing_logistic_model.pkl")
print("models/tfidf_vectorizer.pkl")


print("\n==========================================")
print("              DONE")
print("==========================================")