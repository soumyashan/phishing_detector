import pandas as pd
import joblib
import time

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# ==========================================
# CONFIGURATION
# ==========================================

DATA_PATH = "data/phishing_email.csv"

MODEL_PATH = "models/phishing_svm_model.pkl"
VECTORIZER_PATH = "models/tfidf_vectorizer_svm.pkl"


# ==========================================
# LOAD DATASET
# ==========================================

print("==========================================")
print("       TRAINING FINAL LINEAR SVM")
print("==========================================")

print("\nLoading dataset...")

df = pd.read_csv(DATA_PATH)

print(f"Total emails: {len(df)}")


# ==========================================
# CLEAN DATA
# ==========================================

print("\nCleaning dataset...")

df = df[["text_combined", "label"]]

df = df.dropna()

df["text_combined"] = df["text_combined"].astype(str)

df = df[df["text_combined"].str.strip() != ""]

df = df.drop_duplicates(subset=["text_combined"])

print(f"Emails after cleaning: {len(df)}")


# ==========================================
# FEATURES AND LABEL
# ==========================================

X = df["text_combined"]
y = df["label"]


# ==========================================
# TRAIN / TEST SPLIT
# ==========================================

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


# ==========================================
# TF-IDF
# ==========================================

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


# ==========================================
# TRAIN LINEAR SVM
# ==========================================

print("\n==========================================")
print("          TRAINING LINEAR SVM")
print("==========================================")

start_time = time.time()

model = LinearSVC(
    class_weight="balanced"
)

model.fit(X_train_tfidf, y_train)

training_time = time.time() - start_time

print("Training completed.")
print(f"Training time: {training_time:.2f} seconds")


# ==========================================
# PREDICTION
# ==========================================

y_pred = model.predict(X_test_tfidf)


# ==========================================
# EVALUATION
# ==========================================

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

cm = confusion_matrix(y_test, y_pred)


print("\n==========================================")
print("             FINAL RESULTS")
print("==========================================")

print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")

print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))


# ==========================================
# SAVE MODEL
# ==========================================

print("\n==========================================")
print("              SAVING MODEL")
print("==========================================")

joblib.dump(model, MODEL_PATH)
joblib.dump(vectorizer, VECTORIZER_PATH)

print(f"\nSVM model saved to:")
print(MODEL_PATH)

print(f"\nTF-IDF vectorizer saved to:")
print(VECTORIZER_PATH)

print("\n==========================================")
print("                 DONE")
print("==========================================")