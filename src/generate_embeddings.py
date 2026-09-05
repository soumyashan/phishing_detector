import os
import numpy as np
import pandas as pd
from sentence_transformers import SentenceTransformer


# ==========================================
# CONFIGURATION
# ==========================================

DATA_PATH = "data/phishing_email.csv"

OUTPUT_DIR = "models/embeddings"

EMBEDDINGS_PATH = os.path.join(
    OUTPUT_DIR,
    "email_embeddings.npy"
)

LABELS_PATH = os.path.join(
    OUTPUT_DIR,
    "email_labels.npy"
)

TEXTS_PATH = os.path.join(
    OUTPUT_DIR,
    "email_texts.csv"
)

MODEL_NAME = "all-MiniLM-L6-v2"


# ==========================================
# START
# ==========================================

print("==========================================")
print("     PRETRAINED NLP EMBEDDING GENERATOR")
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

df = df.reset_index(drop=True)

print(f"Emails after cleaning: {len(df)}")


# ==========================================
# LOAD PRETRAINED MODEL
# ==========================================

print("\nLoading pretrained model...")

print(f"Model: {MODEL_NAME}")

model = SentenceTransformer(MODEL_NAME)

print("Model loaded successfully.")


# ==========================================
# PREPARE TEXT
# ==========================================

texts = df["text_combined"].tolist()

labels = df["label"].to_numpy()


# ==========================================
# GENERATE EMBEDDINGS
# ==========================================

print("\nGenerating semantic embeddings...")

print("This may take some time depending on your CPU/GPU.")

embeddings = model.encode(
    texts,
    batch_size=32,
    show_progress_bar=True,
    convert_to_numpy=True,
    normalize_embeddings=True
)


# ==========================================
# DISPLAY EMBEDDING INFORMATION
# ==========================================

print("\n==========================================")
print("        EMBEDDING INFORMATION")
print("==========================================")

print(f"Number of emails : {len(embeddings)}")
print(f"Embedding shape  : {embeddings.shape}")
print(f"Embedding dtype  : {embeddings.dtype}")


# ==========================================
# CREATE OUTPUT DIRECTORY
# ==========================================

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ==========================================
# SAVE EMBEDDINGS
# ==========================================

print("\nSaving embeddings...")

np.save(EMBEDDINGS_PATH, embeddings)

np.save(LABELS_PATH, labels)

pd.DataFrame({
    "text_combined": texts
}).to_csv(
    TEXTS_PATH,
    index=False
)


# ==========================================
# FINISHED
# ==========================================

print("\n==========================================")
print("       EMBEDDING GENERATION COMPLETE")
print("==========================================")

print("\nFiles created:")

print(f"Embeddings:")
print(EMBEDDINGS_PATH)

print("\nLabels:")
print(LABELS_PATH)

print("\nTexts:")
print(TEXTS_PATH)

print("\n==========================================")
print("                 DONE")
print("==========================================")