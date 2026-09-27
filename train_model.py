import pandas as pd
import pickle

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

from ml_features import extract_features


DATASET = "dataset.csv"
MODEL_FILE = "phishing_model.pkl"


# =========================================================
# LOAD DATASET
# =========================================================

df = pd.read_csv(DATASET)

print("=" * 60)
print("        V3.0 PHISHING URL ML TRAINING")
print("=" * 60)

print(f"Dataset samples : {len(df)}")
print(f"Legitimate      : {(df['label'] == 0).sum()}")
print(f"Phishing        : {(df['label'] == 1).sum()}")


# =========================================================
# FEATURE EXTRACTION
# =========================================================

feature_rows = []

for url in df["url"]:
    feature_rows.append(extract_features(url))


X = pd.DataFrame(feature_rows)
y = df["label"]


print(f"Features        : {len(X.columns)}")

print("\nFeature columns:")
for column in X.columns:
    print(f" - {column}")


# =========================================================
# TRAIN / TEST SPLIT
# =========================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.30,
    random_state=42,
    stratify=y
)


print("\nTraining samples :", len(X_train))
print("Testing samples  :", len(X_test))


# =========================================================
# TRAIN RANDOM FOREST
# =========================================================

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced"
)

model.fit(X_train, y_train)


# =========================================================
# EVALUATE MODEL
# =========================================================

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\n" + "=" * 60)
print("MODEL EVALUATION")
print("=" * 60)

print(f"\nAccuracy: {accuracy * 100:.2f}%")

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions,
        target_names=["Legitimate", "Phishing"],
        zero_division=0
    )
)


# =========================================================
# FEATURE IMPORTANCE
# =========================================================

print("=" * 60)
print("FEATURE IMPORTANCE")
print("=" * 60)

importance = pd.Series(
    model.feature_importances_,
    index=X.columns
).sort_values(ascending=False)

for feature, value in importance.items():
    print(f"{feature:25} : {value:.4f}")


# =========================================================
# SAVE MODEL
# =========================================================

with open(MODEL_FILE, "wb") as file:
    pickle.dump(
        {
            "model": model,
            "features": list(X.columns)
        },
        file
    )


print("\n" + "=" * 60)
print(f"Model saved as: {MODEL_FILE}")
print("=" * 60)
