import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

try:
    from sklearn.frozen import FrozenEstimator
except ImportError:
    from sklearn.calibration import FrozenEstimator


print("=" * 42)
print("       CALIBRATED SVM TRAINING")
print("=" * 42)


# ============================================================
# 1. LOAD DATASET
# ============================================================

print("\nLoading dataset...")

df = pd.read_csv("data/phishing_email.csv")

print(f"Total emails: {len(df)}")


# ============================================================
# 2. CLEAN DATA
# ============================================================

print("\nCleaning dataset...")

df = df.dropna(subset=["text_combined", "label"])

df["text_combined"] = df["text_combined"].astype(str)

df = df[df["text_combined"].str.strip() != ""]

df = df.drop_duplicates(subset=["text_combined"])

print(f"Emails after cleaning: {len(df)}")


X = df["text_combined"]
y = df["label"]


# ============================================================
# 3. TRAIN / TEST SPLIT
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
print(f"Testing emails : {len(X_test)}")


# ============================================================
# 4. TF-IDF
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

print(f"TF-IDF shape: {X_train_tfidf.shape}")


# ============================================================
# 5. SPLIT TRAINING DATA
# ============================================================

print("\nCreating calibration split...")

X_svm, X_calibration, y_svm, y_calibration = train_test_split(
    X_train_tfidf,
    y_train,
    test_size=0.20,
    random_state=42,
    stratify=y_train
)

print(f"SVM training samples : {X_svm.shape[0]}")
print(f"Calibration samples  : {X_calibration.shape[0]}")


# ============================================================
# 6. TRAIN BASE SVM
# ============================================================

print("\nTraining Linear SVM...")

base_svm = LinearSVC(
    class_weight="balanced",
    random_state=42
)

base_svm.fit(X_svm, y_svm)

print("Base SVM trained.")


# ============================================================
# 7. FREEZE SVM
# ============================================================

print("\nFreezing trained SVM...")

frozen_svm = FrozenEstimator(base_svm)

print("SVM frozen successfully.")


# ============================================================
# 8. CALIBRATE
# ============================================================

print("\nCalibrating SVM probabilities...")

calibrated_svm = CalibratedClassifierCV(
    estimator=frozen_svm,
    method="sigmoid"
)

calibrated_svm.fit(
    X_calibration,
    y_calibration
)

print("SVM probability calibration completed.")


# ============================================================
# 9. EVALUATE
# ============================================================

print("\nEvaluating calibrated SVM...")

y_pred = calibrated_svm.predict(X_test_tfidf)

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

cm = confusion_matrix(y_test, y_pred)


print("\n==========================================")
print("      CALIBRATED SVM RESULTS")
print("==========================================")

print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")

print("\nConfusion Matrix:")
print(cm)


# ============================================================
# 10. SAVE
# ============================================================

os.makedirs("models", exist_ok=True)

joblib.dump(
    calibrated_svm,
    "models/phishing_calibrated_svm.pkl"
)

joblib.dump(
    vectorizer,
    "models/tfidf_vectorizer_calibrated.pkl"
)

print("\n==========================================")
print("Models saved successfully:")
print("models/phishing_calibrated_svm.pkl")
print("models/tfidf_vectorizer_calibrated.pkl")
print("==========================================")