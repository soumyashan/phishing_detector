import pandas as pd
import os

DATA_FOLDER = "data"

print("\n======================================")
print("       PHISHING DATASET CHECKER")
print("======================================\n")

files = [f for f in os.listdir(DATA_FOLDER) if f.endswith(".csv")]

if not files:
    print("ERROR: No CSV files found in data folder.")
    exit()

print("CSV files found:\n")

for file in files:
    path = os.path.join(DATA_FOLDER, file)

    try:
        df = pd.read_csv(path, encoding="utf-8", on_bad_lines="skip")

        print("--------------------------------------")
        print("FILE:", file)
        print("Rows:", len(df))
        print("Columns:", list(df.columns))
        print("\nFirst row:")
        print(df.head(1).to_string(index=False))
        print()

    except Exception as e:
        print("ERROR reading", file)
        print(e)

print("\n======================================")
print("             DONE")
print("======================================")