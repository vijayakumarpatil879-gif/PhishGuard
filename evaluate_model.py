import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

from ml_features import extract_features


# =========================================================
# V3.8 STEP 3
# MODEL EVALUATION + REPORT GENERATION
# =========================================================

DATASET = "dataset.csv"
REPORT_FILE = "model_evaluation_report.txt"


# =========================================================
# LOAD DATASET
# =========================================================

def load_dataset():

    df = pd.read_csv(DATASET)

    features = []

    for url in df["url"]:
        features.append(
            extract_features(url)
        )

    X = pd.DataFrame(features)
    y = df["label"]

    return X, y


# =========================================================
# EVALUATION
# =========================================================

def evaluate_model():

    print("=" * 60)
    print("       V3.8 STEP 3 - MODEL EVALUATION")
    print("=" * 60)

    X, y = load_dataset()

    print(f"\nTotal samples : {len(X)}")
    print(f"Features      : {len(X.columns)}")

    # -----------------------------------------------------
    # Train / Test Split
    # -----------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print("\n" + "=" * 60)
    print("TRAIN / TEST SPLIT")
    print("=" * 60)

    print(f"\nTraining samples : {len(X_train)}")
    print(f"Testing samples  : {len(X_test)}")

    # -----------------------------------------------------
    # Random Forest
    # -----------------------------------------------------

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced"
    )

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    # -----------------------------------------------------
    # Metrics
    # -----------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    # -----------------------------------------------------
    # Confusion Matrix
    # -----------------------------------------------------

    cm = confusion_matrix(
        y_test,
        predictions,
        labels=[0, 1]
    )

    tn, fp, fn, tp = cm.ravel()

    # -----------------------------------------------------
    # Classification Report
    # -----------------------------------------------------

    report = classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=[
            "Legitimate",
            "Phishing"
        ],
        zero_division=0
    )

    # -----------------------------------------------------
    # Create report text
    # -----------------------------------------------------

    report_text = []

    report_text.append("=" * 60)
    report_text.append(
        "PHISHING URL DETECTION - MODEL EVALUATION REPORT"
    )
    report_text.append("=" * 60)

    report_text.append("")
    report_text.append("DATASET INFORMATION")
    report_text.append("-" * 60)

    report_text.append(
        f"Dataset samples     : {len(X)}"
    )

    report_text.append(
        f"Number of features  : {len(X.columns)}"
    )

    report_text.append(
        "Dataset type        : Educational"
    )

    report_text.append("")

    report_text.append("TRAIN / TEST SPLIT")
    report_text.append("-" * 60)

    report_text.append(
        f"Training samples    : {len(X_train)}"
    )

    report_text.append(
        f"Testing samples     : {len(X_test)}"
    )

    report_text.append(
        "Test size           : 20%"
    )

    report_text.append("")

    report_text.append("MODEL")
    report_text.append("-" * 60)

    report_text.append(
        "Algorithm           : Random Forest"
    )

    report_text.append(
        "Estimators          : 100"
    )

    report_text.append(
        "Random state        : 42"
    )

    report_text.append("")

    report_text.append("MODEL PERFORMANCE")
    report_text.append("-" * 60)

    report_text.append(
        f"Accuracy            : {accuracy * 100:.2f}%"
    )

    report_text.append(
        f"Precision           : {precision * 100:.2f}%"
    )

    report_text.append(
        f"Recall              : {recall * 100:.2f}%"
    )

    report_text.append(
        f"F1 Score            : {f1 * 100:.2f}%"
    )

    report_text.append("")

    report_text.append("CONFUSION MATRIX")
    report_text.append("-" * 60)

    report_text.append(
        "                 Predicted"
    )

    report_text.append(
        "              Legit  Phishing"
    )

    report_text.append(
        f"Actual Legit    {tn:3d}      {fp:3d}"
    )

    report_text.append(
        f"Actual Phishing {fn:3d}      {tp:3d}"
    )

    report_text.append("")

    report_text.append(
        f"True Negatives  (TN): {tn}"
    )

    report_text.append(
        f"False Positives (FP): {fp}"
    )

    report_text.append(
        f"False Negatives (FN): {fn}"
    )

    report_text.append(
        f"True Positives  (TP): {tp}"
    )

    report_text.append("")

    report_text.append("CLASSIFICATION REPORT")
    report_text.append("-" * 60)

    report_text.append(report)

    report_text.append(
        "INTERPRETATION"
    )

    report_text.append("-" * 60)

    if fn == 0:

        report_text.append(
            "No phishing URLs were missed "
            "in this test split."
        )

    else:

        report_text.append(
            f"{fn} phishing URL(s) were "
            "missed in this test split."
        )

    if fp == 0:

        report_text.append(
            "No legitimate URLs were incorrectly "
            "flagged in this test split."
        )

    else:

        report_text.append(
            f"{fp} legitimate URL(s) were "
            "incorrectly flagged."
        )

    report_text.append("")

    report_text.append("IMPORTANT NOTE")
    report_text.append("-" * 60)

    report_text.append(
        "This evaluation uses an 80/20 train/test split."
    )

    report_text.append(
        "The test URLs were not used during training."
    )

    report_text.append(
        "The dataset is small and educational."
    )

    report_text.append(
        "These results should NOT be interpreted as "
        "real-world phishing detection accuracy."
    )

    report_text.append("")

    report_text.append("=" * 60)
    report_text.append(
        "V3.8 STEP 3 COMPLETE"
    )
    report_text.append("=" * 60)

    # -----------------------------------------------------
    # Join report
    # -----------------------------------------------------

    final_report = "\n".join(report_text)

    # -----------------------------------------------------
    # Display report
    # -----------------------------------------------------

    print("\n")
    print(final_report)

    # -----------------------------------------------------
    # Save report
    # -----------------------------------------------------

    with open(
        REPORT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(final_report)

    print(
        f"\nReport saved successfully as: "
        f"{REPORT_FILE}"
    )


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":
    evaluate_model()
