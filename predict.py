import pickle
import pandas as pd

from ml_features import extract_features


MODEL_FILE = "phishing_model.pkl"


def predict_url(url):
    # Load trained model
    with open(MODEL_FILE, "rb") as file:
        saved = pickle.load(file)

    model = saved["model"]
    feature_names = saved["features"]

    # Extract features
    features = extract_features(url)

    # Keep the same feature order used during training
    X = pd.DataFrame(
        [features],
        columns=feature_names
    )

    # Predict
    prediction = model.predict(X)[0]

    # Get confidence/probability
    probabilities = model.predict_proba(X)[0]

    phishing_probability = probabilities[1] * 100

    if prediction == 1:
        label = "PHISHING"
    else:
        label = "LEGITIMATE"

    return label, phishing_probability


if __name__ == "__main__":

    print("=" * 60)
    print("          V3.0 ML URL PREDICTOR")
    print("=" * 60)

    url = input("\nEnter a URL: ").strip()

    if not url:
        print("Error: URL cannot be empty.")
        raise SystemExit

    try:
        label, probability = predict_url(url)

        print("\n" + "=" * 60)
        print("ML PREDICTION")
        print("=" * 60)

        print(f"\nURL                : {url}")
        print(f"Prediction         : {label}")
        print(f"Phishing Probability: {probability:.2f}%")

        print("=" * 60)

    except FileNotFoundError:
        print("\nError: phishing_model.pkl was not found.")

    except Exception as error:
        print(f"\nError: {error}")
