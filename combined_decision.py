# =========================================================
# V3.7 - COMBINED SECURITY DECISION ENGINE
# =========================================================


def get_combined_decision(
    rule_score,
    rule_level,
    ml_prediction,
    phishing_probability
):
    """
    Combine rule-based analysis with ML prediction.

    Parameters:
        rule_score: Rule-based risk score (0-100)
        rule_level: LOW / MEDIUM / HIGH / CRITICAL
        ml_prediction: PHISHING or LEGITIMATE
        phishing_probability: ML phishing probability (0-100)

    Returns:
        Dictionary containing the final security assessment.
    """

    # -----------------------------------------------------
    # Normalize inputs
    # -----------------------------------------------------

    try:
        rule_score = float(rule_score)
    except (TypeError, ValueError):
        rule_score = 0.0

    try:
        phishing_probability = float(phishing_probability)
    except (TypeError, ValueError):
        phishing_probability = 0.0

    rule_score = max(0, min(rule_score, 100))
    phishing_probability = max(
        0,
        min(phishing_probability, 100)
    )

    rule_level = str(
        rule_level or "LOW"
    ).upper()

    ml_prediction = str(
        ml_prediction or "UNKNOWN"
    ).upper()


    # -----------------------------------------------------
    # Calculate combined score
    # -----------------------------------------------------

    combined_score = (
        (rule_score * 0.50)
        +
        (phishing_probability * 0.50)
    )

    combined_score = round(
        combined_score,
        2
    )


    # -----------------------------------------------------
    # Determine agreement
    # -----------------------------------------------------

    rule_suspicious = rule_score >= 20

    ml_suspicious = (
        ml_prediction == "PHISHING"
        or phishing_probability >= 50
    )


    # -----------------------------------------------------
    # Final assessment
    # -----------------------------------------------------

    if (
        rule_score >= 60
        and phishing_probability >= 70
    ):

        verdict = "HIGHLY SUSPICIOUS"

        explanation = (
            "Both the rule-based analyzer and the "
            "machine-learning model indicate elevated "
            "phishing risk."
        )


    elif (
        rule_suspicious
        and ml_suspicious
    ):

        verdict = "POTENTIALLY SUSPICIOUS"

        explanation = (
            "The URL triggered rule-based security "
            "indicators and the ML model also identified "
            "phishing-related characteristics."
        )


    elif (
        not rule_suspicious
        and not ml_suspicious
    ):

        verdict = "LOW RISK"

        explanation = (
            "Neither the rule-based analyzer nor the "
            "ML model identified strong phishing indicators."
        )


    elif ml_suspicious:

        verdict = "ML WARNING"

        explanation = (
            "The rule-based score is relatively low, "
            "but the machine-learning model indicates "
            "possible phishing characteristics."
        )


    else:

        verdict = "RULE-BASED WARNING"

        explanation = (
            "The rule-based analyzer detected suspicious "
            "URL characteristics, while the ML model "
            "did not strongly classify the URL as phishing."
        )


    # -----------------------------------------------------
    # Return result
    # -----------------------------------------------------

    return {
        "combined_score": combined_score,
        "verdict": verdict,
        "explanation": explanation,
        "rule_score": round(rule_score, 2),
        "rule_level": rule_level,
        "ml_prediction": ml_prediction,
        "phishing_probability": round(
            phishing_probability,
            2
        )
    }


# =========================================================
# TEST
# =========================================================

if __name__ == "__main__":

    print("=" * 60)
    print("       V3.7 COMBINED DECISION ENGINE")
    print("=" * 60)

    result = get_combined_decision(
        rule_score=50,
        rule_level="MEDIUM",
        ml_prediction="PHISHING",
        phishing_probability=100
    )

    print("\nRULE SCORE:")
    print(f"{result['rule_score']}/100")

    print("\nRULE LEVEL:")
    print(result["rule_level"])

    print("\nML PREDICTION:")
    print(result["ml_prediction"])

    print("\nPHISHING PROBABILITY:")
    print(f"{result['phishing_probability']}%")

    print("\nCOMBINED SCORE:")
    print(f"{result['combined_score']}/100")

    print("\nFINAL VERDICT:")
    print(result["verdict"])

    print("\nEXPLANATION:")
    print(result["explanation"])

    print("\n" + "=" * 60)
    print("V3.7 STEP 1 COMPLETE")
    print("=" * 60)
