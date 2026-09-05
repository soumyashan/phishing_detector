import pandas as pd
import numpy as np
import os
import joblib
import time

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer

from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


print("\n==========================================")
print("       PHISHING MODEL COMPARISON")
print("==========================================\n")


# ==========================================
# 1. LOAD DATASET
# ==========================================

DATA_PATH = "data/phishing_email.csv"

print("Loading dataset...")

df = pd.read_csv(DATA_PATH)

print(f"Total emails: {len(df)}")


# ==========================================
# 2. CLEAN DATA
# ==========================================

print("\nCleaning dataset...")

df = df[["text_combined", "label"]]

df = df.dropna()

df["text_combined"] = df["text_combined"].astype(str)

df = df[df["text_combined"].str.strip() != ""]

df = df.drop_duplicates(subset=["text_combined"])

print(f"Emails after cleaning: {len(df)}")


# ==========================================
# 3. SPLIT DATA
# ==========================================

X = df["text_combined"]
y = df["label"]

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
# 4. TF-IDF
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
# 5. DEFINE MODELS
# ==========================================

models = {

    "Logistic Regression": LogisticRegression(
        max_iter=1000,
        class_weight="balanced"
    ),

    "Linear SVM": LinearSVC(
        class_weight="balanced"
    ),

    "Random Forest": RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    )
}


# ==========================================
# 6. TRAIN AND TEST MODELS
# ==========================================

results = []


for name, model in models.items():

    print("\n==========================================")
    print(f"TRAINING: {name}")
    print("==========================================")

    start_time = time.time()

    model.fit(
        X_train_tfidf,
        y_train
    )

    training_time = time.time() - start_time

    print("Training completed.")

    # Predictions
    y_pred = model.predict(X_test_tfidf)

    # Metrics
    accuracy = accuracy_score(y_test, y_pred)

    precision = precision_score(
        y_test,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0
    )

    print("\nResults:")

    print(f"Accuracy  : {accuracy:.4f}")
    print(f"Precision : {precision:.4f}")
    print(f"Recall    : {recall:.4f}")
    print(f"F1 Score  : {f1:.4f}")

    print(f"Training Time: {training_time:.2f} seconds")

    print("\nConfusion Matrix:")

    print(
        confusion_matrix(
            y_test,
            y_pred
        )
    )

    results.append({

        "Model": name,

        "Accuracy": accuracy,

        "Precision": precision,

        "Recall": recall,

        "F1 Score": f1,

        "Training Time (sec)": training_time
    })


# ==========================================
# 7. COMPARISON TABLE
# ==========================================

results_df = pd.DataFrame(results)

print("\n\n==========================================")
print("             MODEL COMPARISON")
print("==========================================\n")

print(
    results_df.to_string(
        index=False,
        float_format=lambda x: f"{x:.4f}"
    )
)


# ==========================================
# 8. SAVE RESULTS
# ==========================================

os.makedirs("models", exist_ok=True)

results_df.to_csv(
    "models/model_comparison.csv",
    index=False
)

print("\nComparison saved to:")

print("models/model_comparison.csv")


# ==========================================
# 9. FIND BEST MODEL
# ==========================================

best_model = results_df.loc[
    results_df["F1 Score"].idxmax()
]

print("\n==========================================")
print("               BEST MODEL")
print("==========================================")

print(
    f"\nModel: {best_model['Model']}"
)

print(
    f"F1 Score: {best_model['F1 Score']:.4f}"
)

print(
    f"Accuracy: {best_model['Accuracy']:.4f}"
)

print(
    f"Precision: {best_model['Precision']:.4f}"
)

print(
    f"Recall: {best_model['Recall']:.4f}"
)


print("\n==========================================")
print("                 DONE")
print("==========================================")