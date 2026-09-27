from flask import Flask, render_template, request
import sqlite3
from datetime import datetime
import traceback
import os


# ============================================================
# PHISHGUARD
# Security Analysis Dashboard
# ============================================================

app = Flask(__name__)

# Always use the directory where app.py is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATABASE = os.path.join(
    BASE_DIR,
    "scan_history.db"
)

EVALUATION_FILE = os.path.join(
    BASE_DIR,
    "model_evaluation_report.txt"
)


# ============================================================
# IMPORT RULE-BASED ANALYZER
# ============================================================

try:
    from analyzer import analyze_url
    ANALYZER_ERROR = ""
except Exception as e:
    analyze_url = None
    ANALYZER_ERROR = str(e)


# ============================================================
# IMPORT MACHINE LEARNING PREDICTOR
# ============================================================

try:
    from ml_predictor import predict_url
    ML_ERROR = ""
except Exception as e:
    predict_url = None
    ML_ERROR = str(e)


# ============================================================
# IMPORT ML FEATURE IMPORTANCE
# ============================================================

try:
    from ml_importance import get_feature_importance
    ML_IMPORTANCE_ERROR = ""
except Exception as e:
    get_feature_importance = None
    ML_IMPORTANCE_ERROR = str(e)


# ============================================================
# IMPORT CATEGORY CLASSIFIER
# ============================================================

try:
    from category_classifier import classify_url
    CATEGORY_ERROR = ""
except Exception as e:
    classify_url = None
    CATEGORY_ERROR = str(e)


# ============================================================
# IMPORT COMBINED DECISION MODULE
# ============================================================

try:
    from combined_decision import get_combined_decision
    COMBINED_ERROR = ""
except Exception as e:
    get_combined_decision = None
    COMBINED_ERROR = str(e)


# ============================================================
# SAFE FLOAT
# ============================================================

def safe_float(value, default=0.0):
    """
    Safely convert a value to float.
    """

    try:
        return float(value)

    except (TypeError, ValueError):
        return default


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_database():
    """
    Create the scan history table if it does not exist.
    """

    try:

        conn = sqlite3.connect(DATABASE)

        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                url TEXT NOT NULL,

                score INTEGER,

                risk TEXT,

                scanned_at TEXT

            )
        """)

        conn.commit()
        conn.close()

        print("Database initialized successfully.")

    except Exception as e:

        print(
            "Database initialization error:",
            str(e)
        )


# ============================================================
# SAVE SCAN
# ============================================================

def save_scan(url, score, risk):
    """
    Save a URL scan to SQLite.
    """

    try:

        conn = sqlite3.connect(DATABASE)

        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO scan_history
            (
                url,
                score,
                risk,
                scanned_at
            )
            VALUES (?, ?, ?, ?)
        """, (

            url,

            int(
                safe_float(
                    score
                )
            ),

            str(risk),

            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        ))

        conn.commit()
        conn.close()

    except Exception as e:

        print(
            "Save scan error:",
            str(e)
        )


# ============================================================
# GET SCAN HISTORY
# ============================================================

def get_history():
    """
    Get the latest 10 scans.
    """

    try:

        conn = sqlite3.connect(DATABASE)

        conn.row_factory = sqlite3.Row

        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                id,
                url,
                score,
                risk,
                scanned_at
            FROM scan_history
            ORDER BY id DESC
            LIMIT 10
        """)

        history = cursor.fetchall()

        conn.close()

        return history

    except Exception as e:

        print(
            "History loading error:",
            str(e)
        )

        return []


# ============================================================
# DASHBOARD STATISTICS
# ============================================================

def get_dashboard_statistics():
    """
    Calculate dashboard summary statistics.

    LOW       = safe
    MEDIUM    = detected/suspicious threat
    HIGH      = detected/high threat
    """

    statistics = {

        "total_scans": 0,

        "phishing_urls": 0,

        "safe_urls": 0,

        "last_scan": "No scans yet"

    }

    try:

        conn = sqlite3.connect(DATABASE)

        cursor = conn.cursor()

        # ----------------------------------------------------
        # TOTAL SCANS
        # ----------------------------------------------------

        cursor.execute("""
            SELECT COUNT(*)
            FROM scan_history
        """)

        statistics["total_scans"] = (
            cursor.fetchone()[0]
        )


        # ----------------------------------------------------
        # DETECTED THREATS
        #
        # MEDIUM + HIGH
        # ----------------------------------------------------

        cursor.execute("""
            SELECT COUNT(*)
            FROM scan_history
            WHERE UPPER(TRIM(risk))
            IN (
                'MEDIUM',
                'HIGH',
                'HIGH RISK',
                'PHISHING',
                'POTENTIAL PHISHING'
            )
        """)

        statistics["phishing_urls"] = (
            cursor.fetchone()[0]
        )


        # ----------------------------------------------------
        # SAFE URLS
        #
        # LOW
        # ----------------------------------------------------

        cursor.execute("""
            SELECT COUNT(*)
            FROM scan_history
            WHERE UPPER(TRIM(risk))
            IN (
                'LOW',
                'LOW RISK',
                'SAFE',
                'LEGITIMATE'
            )
        """)

        statistics["safe_urls"] = (
            cursor.fetchone()[0]
        )


        # ----------------------------------------------------
        # LAST SCAN
        # ----------------------------------------------------

        cursor.execute("""
            SELECT scanned_at
            FROM scan_history
            ORDER BY id DESC
            LIMIT 1
        """)

        last_scan = cursor.fetchone()

        if last_scan and last_scan[0]:

            statistics["last_scan"] = (
                last_scan[0]
            )


        conn.close()

    except Exception as e:

        print(
            "Dashboard statistics error:",
            str(e)
        )

    return statistics


# ============================================================
# NORMALIZE ML RESULT
# ============================================================

def normalize_ml_result(result):
    """
    Normalize the ML predictor output.

    Supports the current ml_predictor.py format:
        prediction
        phishing_probability
        legitimate_probability
    """

    if not isinstance(
        result,
        dict
    ):

        return {

            "ml_prediction":
                "Unknown",

            "phishing_probability":
                0.0,

            "legitimate_probability":
                0.0

        }


    prediction = result.get(

        "ml_prediction",

        result.get(

            "prediction",

            result.get(
                "label",
                "Unknown"
            )

        )

    )


    phishing_probability = safe_float(

        result.get(

            "phishing_probability",

            result.get(

                "phishing_prob",

                result.get(
                    "probability",
                    0.0
                )

            )

        )

    )


    legitimate_probability = safe_float(

        result.get(

            "legitimate_probability",

            result.get(
                "legitimate_prob",
                0.0
            )

        )

    )


    return {

        "ml_prediction":
            prediction,

        "phishing_probability":
            phishing_probability,

        "legitimate_probability":
            legitimate_probability

    }


# ============================================================
# MODEL EVALUATION
# ============================================================

def get_model_evaluation():
    """
    Read Accuracy, Precision, Recall and F1 Score
    from model_evaluation_report.txt.
    """

    evaluation = {

        "accuracy": 0.0,

        "precision": 0.0,

        "recall": 0.0,

        "f1": 0.0

    }


    if not os.path.exists(
        EVALUATION_FILE
    ):

        print(
            "Evaluation report not found:",
            EVALUATION_FILE
        )

        return evaluation


    try:

        with open(
            EVALUATION_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            content = file.read()


        for line in content.splitlines():

            if ":" not in line:
                continue


            key, value = line.split(
                ":",
                1
            )


            key = key.strip()

            value = (
                value
                .strip()
                .replace(
                    "%",
                    ""
                )
            )


            if key == "Accuracy":

                evaluation["accuracy"] = (
                    safe_float(value)
                )


            elif key == "Precision":

                evaluation["precision"] = (
                    safe_float(value)
                )


            elif key == "Recall":

                evaluation["recall"] = (
                    safe_float(value)
                )


            elif key == "F1 Score":

                evaluation["f1"] = (
                    safe_float(value)
                )


    except Exception as e:

        print(
            "Model evaluation error:",
            str(e)
        )


    return evaluation


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

def get_dashboard_feature_importance():
    """
    Get Random Forest feature importance
    for the dashboard.
    """

    if get_feature_importance is None:

        print(
            "Feature importance unavailable:",
            ML_IMPORTANCE_ERROR
        )

        return []


    try:

        importance = (
            get_feature_importance()
        )


        if not isinstance(
            importance,
            list
        ):

            return []


        return importance


    except Exception as e:

        print(
            "Feature importance error:",
            str(e)
        )

        return []


# ============================================================
# CATEGORY CLASSIFICATION
# ============================================================

def get_category_result(url):
    """
    Run URL category classification safely.
    """

    if classify_url is None:

        return {

            "category":
                "Unavailable",

            "confidence":
                0.0,

            "matched_keywords":
                []

        }


    try:

        result = classify_url(
            url
        )


        if not isinstance(
            result,
            dict
        ):

            return {

                "category":
                    "Unknown",

                "confidence":
                    0.0,

                "matched_keywords":
                    []

            }


        return {

            "category":
                result.get(
                    "category",
                    "Unknown"
                ),

            "confidence":
                safe_float(
                    result.get(
                        "confidence",
                        0.0
                    )
                ),

            "matched_keywords":
                result.get(
                    "matched_keywords",
                    []
                )

        }


    except Exception as e:

        print(
            "Category classification error:",
            str(e)
        )


        return {

            "category":
                "Error",

            "confidence":
                0.0,

            "matched_keywords":
                [],

            "error":
                str(e)

        }


# ============================================================
# RISK SCORE BREAKDOWN
# ============================================================

def get_risk_breakdown(score):
    """
    Convert the risk score into data that can be
    displayed by the dashboard.
    """

    score = safe_float(
        score
    )


    # Keep score between 0 and 100

    score = max(
        0,
        min(
            100,
            score
        )
    )


    # Risk category

    if score <= 30:

        risk_level = "LOW"

    elif score <= 70:

        risk_level = "MEDIUM"

    else:

        risk_level = "HIGH"


    return {

        "score":
            round(
                score,
                2
            ),

        "percentage":
            round(
                score,
                2
            ),

        "risk_level":
            risk_level,

        "low_range":
            "0-30",

        "medium_range":
            "31-70",

        "high_range":
            "71-100"

    }


# ============================================================
# COMBINED RISK DECISION
# ============================================================

def make_combined_decision(

    rule_score,

    rule_level,

    ml_prediction,

    phishing_probability

):

    rule_score = safe_float(
        rule_score
    )


    phishing_probability = safe_float(
        phishing_probability
    )


    # --------------------------------------------------------
    # ML probability
    #
    # Current ml_predictor.py returns 0-100.
    # This also supports 0-1 just in case.
    # --------------------------------------------------------

    if (
        0 <=
        phishing_probability <=
        1
    ):

        ml_percent = (
            phishing_probability
            * 100
        )

    else:

        ml_percent = (
            phishing_probability
        )


    # --------------------------------------------------------
    # Normalize
    # --------------------------------------------------------

    rule_percent = max(
        0,
        min(
            100,
            rule_score
        )
    )


    ml_percent = max(
        0,
        min(
            100,
            ml_percent
        )
    )


    # --------------------------------------------------------
    # 50% Rule + 50% ML
    # --------------------------------------------------------

    combined_score = (

        (
            rule_percent
            * 0.50
        )

        +

        (
            ml_percent
            * 0.50
        )

    )


    # --------------------------------------------------------
    # Combined risk level
    # --------------------------------------------------------

    if combined_score >= 70:

        decision = "HIGH RISK"

    elif combined_score >= 40:

        decision = "MEDIUM RISK"

    else:

        decision = "LOW RISK"


    return {

        "decision":
            decision,

        "combined_score":
            round(
                combined_score,
                2
            ),

        "rule_score":
            round(
                rule_percent,
                2
            ),

        "ml_score":
            round(
                ml_percent,
                2
            )

    }


# ============================================================
# MAIN DASHBOARD ROUTE
# ============================================================

@app.route(
    "/",
    methods=[
        "GET",
        "POST"
    ]
)

def index():

    url = ""

    result = None

    error = ""


    # ========================================================
    # LOAD DASHBOARD DATA
    # ========================================================

    history = get_history()

    evaluation = (
        get_model_evaluation()
    )

    feature_importance = (
        get_dashboard_feature_importance()
    )

    statistics = (
        get_dashboard_statistics()
    )


    # Default risk breakdown

    risk_breakdown = {

        "score":
            0,

        "percentage":
            0,

        "risk_level":
            "LOW",

        "low_range":
            "0-30",

        "medium_range":
            "31-70",

        "high_range":
            "71-100"

    }


    # ========================================================
    # URL SCANNING
    # ========================================================

    if request.method == "POST":

        url = (
            request.form
            .get(
                "url",
                ""
            )
            .strip()
        )


        # ----------------------------------------------------
        # Empty URL
        # ----------------------------------------------------

        if not url:

            error = (
                "Please enter a URL."
            )


        else:

            try:

                # ============================================
                # 1. RULE-BASED ANALYSIS
                # ============================================

                if analyze_url is None:

                    raise RuntimeError(

                        "Rule analyzer unavailable: "

                        + ANALYZER_ERROR

                    )


                rule_result = (
                    analyze_url(
                        url
                    )
                )


                if not isinstance(
                    rule_result,
                    dict
                ):

                    rule_result = {}


                rule_score = safe_float(

                    rule_result.get(
                        "risk_score",
                        0
                    )

                )


                rule_level = (
                    rule_result.get(
                        "risk_level",
                        "LOW"
                    )
                )


                # ============================================
                # 2. MACHINE LEARNING
                # ============================================

                ml_result = {

                    "ml_prediction":
                        "Unavailable",

                    "phishing_probability":
                        0.0,

                    "legitimate_probability":
                        0.0

                }


                if predict_url is not None:

                    try:

                        raw_ml_result = (
                            predict_url(
                                url
                            )
                        )


                        ml_result = (
                            normalize_ml_result(
                                raw_ml_result
                            )
                        )


                    except Exception as ml_error:

                        print(
                            "ML prediction error:",
                            str(ml_error)
                        )


                        ml_result = {

                            "ml_prediction":
                                "Error",

                            "phishing_probability":
                                0.0,

                            "legitimate_probability":
                                0.0,

                            "error":
                                str(ml_error)

                        }


                # ============================================
                # 3. CATEGORY
                # ============================================

                category_result = (
                    get_category_result(
                        url
                    )
                )


                # ============================================
                # 4. COMBINED DECISION
                # ============================================

                combined = (
                    make_combined_decision(

                        rule_score=
                            rule_score,

                        rule_level=
                            rule_level,

                        ml_prediction=
                            ml_result[
                                "ml_prediction"
                            ],

                        phishing_probability=
                            ml_result[
                                "phishing_probability"
                            ]

                    )
                )


                # ============================================
                # 5. RISK BREAKDOWN
                # ============================================

                risk_breakdown = (
                    get_risk_breakdown(
                        rule_score
                    )
                )


                # ============================================
                # 6. BUILD FINAL RESULT
                # ============================================

                result = (
                    rule_result.copy()
                )


                # Rule information

                result[
                    "risk_score"
                ] = rule_score


                result[
                    "risk_level"
                ] = rule_level


                # ML information

                result[
                    "ml_prediction"
                ] = ml_result[
                    "ml_prediction"
                ]


                result[
                    "phishing_probability"
                ] = ml_result[
                    "phishing_probability"
                ]


                result[
                    "legitimate_probability"
                ] = ml_result[
                    "legitimate_probability"
                ]


                # Category information

                result[
                    "category"
                ] = category_result[
                    "category"
                ]


                result[
                    "category_confidence"
                ] = category_result[
                    "confidence"
                ]


                result[
                    "category_keywords"
                ] = category_result[
                    "matched_keywords"
                ]


                # Combined information

                result[
                    "combined"
                ] = combined


                # Risk breakdown

                result[
                    "risk_breakdown"
                ] = risk_breakdown


                # ============================================
                # 7. SAVE TO DATABASE
                # ============================================

                save_scan(

                    url,

                    rule_score,

                    rule_level

                )


                # ============================================
                # 8. REFRESH DASHBOARD DATA
                # ============================================

                history = (
                    get_history()
                )


                statistics = (
                    get_dashboard_statistics()
                )


            except Exception as e:

                error = str(e)


                print(
                    "\n========================================"
                )

                print(
                    "PHISHGUARD ANALYSIS ERROR"
                )

                print(
                    "========================================"
                )

                traceback.print_exc()

                print(
                    "========================================\n"
                )


    # ========================================================
    # RENDER HTML
    # ========================================================

    return render_template(

        "index.html",

        url=url,

        result=result,

        error=error,

        history=history,

        evaluation=evaluation,

        feature_importance=feature_importance,

        combined=(

            result.get(
                "combined",
                {}
            )

            if result

            else {}

        ),

        # ----------------------------------------------------
        # Dashboard statistics
        # ----------------------------------------------------

        total_scans=(
            statistics[
                "total_scans"
            ]
        ),

        phishing_urls=(
            statistics[
                "phishing_urls"
            ]
        ),

        safe_urls=(
            statistics[
                "safe_urls"
            ]
        ),

        last_scan=(
            statistics[
                "last_scan"
            ]
        ),

        # ----------------------------------------------------
        # Risk breakdown
        # ----------------------------------------------------

        risk_breakdown=
            risk_breakdown

    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route(
    "/health"
)

def health():

    return {

        "status":
            "running",

        "analyzer":
            analyze_url is not None,

        "ml_predictor":
            predict_url is not None,

        "ml_feature_importance":
            get_feature_importance is not None,

        "category_classifier":
            classify_url is not None,

        "combined_decision":
            get_combined_decision is not None,

        "database":
            os.path.exists(
                DATABASE
            ),

        "evaluation_report":
            os.path.exists(
                EVALUATION_FILE
            )

    }


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    # Create database

    init_database()


    print(
        "\n========================================"
    )

    print(
        "          PHISHGUARD"
    )

    print(
        "   Security Analysis Dashboard"
    )

    print(
        "========================================"
    )


    print(
        "Rule Analyzer       :",
        "OK"
        if analyze_url is not None
        else "ERROR"
    )


    print(
        "ML Predictor        :",
        "OK"
        if predict_url is not None
        else "ERROR"
    )


    print(
        "Feature Importance  :",
        "OK"
        if get_feature_importance is not None
        else "ERROR"
    )


    print(
        "Category Classifier :",
        "OK"
        if classify_url is not None
        else "ERROR"
    )


    print(
        "Database            : OK"
    )


    print(
        "========================================"
    )


    print(
        "Dashboard URL:"
    )


    print(
        "http://127.0.0.1:5000"
    )


    print(
        "========================================\n"
    )


    app.run(

        host="127.0.0.1",

        port=5000,

        debug=True

    )
