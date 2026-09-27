import pickle
import pandas as pd

from ml_features import extract_features


MODEL_FILE = "phishing_model.pkl"


def predict_url(url):
    """
    Load the trained ML model and predict whether
    the supplied URL is legitimate or phishing.
    """

    with open(MODEL_FILE, "rb") as file:
        saved_model = pickle.load(file)

    model = saved_model["model"]
    feature_names = saved_model["features"]

    features = extract_features(url)

    # Keep exactly the same feature order used during training
    X = pd.DataFrame(
        [features],
        columns=feature_names
    )

    prediction = int(model.predict(X)[0])

    probabilities = model.predict_proba(X)[0]

    phishing_probability = float(probabilities[1] * 100)

    legitimate_probability = float(probabilities[0] * 100)

    if prediction == 1:
        prediction_label = "PHISHING"
    else:
        prediction_label = "LEGITIMATE"

    return {
        "prediction": prediction_label,
        "phishing_probability": phishing_probability,
        "legitimate_probability": legitimate_probability
    }
