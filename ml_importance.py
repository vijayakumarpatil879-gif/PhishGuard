import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

from ml_features import extract_features


DATASET = "dataset.csv"


def get_feature_importance():

    # Load dataset
    df = pd.read_csv(DATASET)

    # Extract URL features
    feature_rows = []

    for url in df["url"]:
        feature_rows.append(extract_features(url))

    X = pd.DataFrame(feature_rows)
    y = df["label"]

    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.30,
        random_state=42,
        stratify=y
    )

    # Train Random Forest
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced"
    )

    model.fit(X_train, y_train)

    # Get importance
    importance = pd.DataFrame({
        "feature": X.columns,
        "importance": model.feature_importances_
    })

    # Sort highest first
    importance = importance.sort_values(
        by="importance",
        ascending=False
    )

    # Convert to dictionary for Flask/Jinja
    results = []

    for _, row in importance.iterrows():

        results.append({
            "feature": row["feature"],
            "importance": round(
                float(row["importance"]) * 100,
                2
            )
        })

    return results
