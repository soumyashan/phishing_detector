import os
import time
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
from sklearn.ensemble import RandomForestClassifier

from xgboost import XGBClassifier


# ==========================================
# CONFIGURATION
# ==========================================

EMBEDDINGS_PATH = "models/embeddings/email_embeddings.npy"
LABELS_PATH = "models/embeddings/email_labels.npy"

SECURITY_FEATURES_PATH = (
    "models/security_features/security_features.npy"
)

FEATURE_NAMES_PATH = (
    "models/security_features/security_feature_names.csv"
)

OUTPUT_DIR = "models/fusion"

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ==========================================
# LOAD DATA
# ==========================================

print("==========================================")
print("        FEATURE FUSION EXPERIMENT")
print("==========================================")

print("\nLoading semantic embeddings...")

embeddings = np.load(EMBEDDINGS_PATH)

print(f"Embeddings shape: {embeddings.shape}")


print("\nLoading labels...")

labels = np.load(LABELS_PATH)

print(f"Labels shape: {labels.shape}")


print("\nLoading security features...")

security_features = np.load(SECURITY_FEATURES_PATH)

print(
    f"Security features shape: "
    f"{security_features.shape}"
)


# ==========================================
# VALIDATE DATA
# ==========================================

if len(embeddings) != len(labels):
    raise ValueError(
        "Number of embeddings and labels do not match."
    )

if len(security_features) != len(labels):
    raise ValueError(
        "Number of security features and labels do not match."
    )


# ==========================================
# FEATURE NAMES
# ==========================================

feature_names_df = pd.read_csv(
    FEATURE_NAMES_PATH
)

security_feature_names = (
    feature_names_df["feature_name"].tolist()
)


# ==========================================
# TRAIN / TEST SPLIT
# ==========================================

print("\nSplitting dataset...")

indices = np.arange(len(labels))

train_idx, test_idx = train_test_split(
    indices,
    test_size=0.20,
    random_state=42,
    stratify=labels
)


X_embed_train = embeddings[train_idx]
X_embed_test = embeddings[test_idx]

X_security_train = security_features[train_idx]
X_security_test = security_features[test_idx]

y_train = labels[train_idx]
y_test = labels[test_idx]


print(f"Training samples: {len(train_idx)}")
print(f"Testing samples : {len(test_idx)}")


# ==========================================
# SCALE SECURITY FEATURES
# ==========================================

print("\nScaling security features...")

scaler = StandardScaler()

X_security_train_scaled = scaler.fit_transform(
    X_security_train
)

X_security_test_scaled = scaler.transform(
    X_security_test
)


# ==========================================
# FEATURE FUSION
# ==========================================

print("\n==========================================")
print("           FEATURE FUSION")
print("==========================================")

print("\nCombining:")

print("384 semantic features")
print("+")
print("31 security features")

X_train = np.hstack([
    X_embed_train,
    X_security_train_scaled
])

X_test = np.hstack([
    X_embed_test,
    X_security_test_scaled
])

print(
    f"\nCombined training shape: "
    f"{X_train.shape}"
)

print(
    f"Combined testing shape : "
    f"{X_test.shape}"
)


# ==========================================
# SAVE SCALER
# ==========================================

import joblib

scaler_path = os.path.join(
    OUTPUT_DIR,
    "security_feature_scaler.pkl"
)

joblib.dump(
    scaler,
    scaler_path
)


# ==========================================
# EVALUATION FUNCTION
# ==========================================

results = []


def evaluate_model(
    model,
    model_name
):

    print("\n==========================================")
    print(f"TRAINING: {model_name}")
    print("==========================================")

    start = time.time()

    model.fit(
        X_train,
        y_train
    )

    training_time = time.time() - start

    y_pred = model.predict(
        X_test
    )

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    precision = precision_score(
        y_test,
        y_pred
    )

    recall = recall_score(
        y_test,
        y_pred
    )

    f1 = f1_score(
        y_test,
        y_pred
    )

    cm = confusion_matrix(
        y_test,
        y_pred
    )

    print("\nResults:")

    print(
        f"Accuracy  : {accuracy:.4f}"
    )

    print(
        f"Precision : {precision:.4f}"
    )

    print(
        f"Recall    : {recall:.4f}"
    )

    print(
        f"F1 Score  : {f1:.4f}"
    )

    print(
        f"Training Time: "
        f"{training_time:.2f} seconds"
    )

    print("\nConfusion Matrix:")

    print(cm)

    results.append({
        "Model": model_name,
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1 Score": f1,
        "Training Time": training_time
    })

    model_path = os.path.join(
        OUTPUT_DIR,
        model_name.lower()
        .replace(" ", "_")
        + ".pkl"
    )

    joblib.dump(
        model,
        model_path
    )

    print(
        f"\nModel saved to: {model_path}"
    )


# ==========================================
# MODEL 1
# ==========================================

logistic_model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced"
)

evaluate_model(
    logistic_model,
    "Fusion Logistic Regression"
)


# ==========================================
# MODEL 2
# ==========================================

random_forest_model = RandomForestClassifier(
    n_estimators=300,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

evaluate_model(
    random_forest_model,
    "Fusion Random Forest"
)


# ==========================================
# MODEL 3
# ==========================================

xgb_model = XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    objective="binary:logistic",
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1
)

evaluate_model(
    xgb_model,
    "Fusion XGBoost"
)


# ==========================================
# COMPARISON
# ==========================================

results_df = pd.DataFrame(results)

results_df = results_df.sort_values(
    by="F1 Score",
    ascending=False
)

comparison_path = os.path.join(
    OUTPUT_DIR,
    "fusion_model_comparison.csv"
)

results_df.to_csv(
    comparison_path,
    index=False
)


print("\n==========================================")
print("          FUSION MODEL COMPARISON")
print("==========================================")

print(
    results_df.to_string(
        index=False
    )
)


print("\nComparison saved to:")

print(comparison_path)


# ==========================================
# BEST MODEL
# ==========================================

best_model = results_df.iloc[0]

print("\n==========================================")
print("              BEST FUSION MODEL")
print("==========================================")

print(
    f"Model: {best_model['Model']}"
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