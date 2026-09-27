# Phishing URL Detection System

## 1. Project Overview

The Phishing URL Detection System is an educational cybersecurity project designed to analyze URLs and identify characteristics associated with phishing.

The system combines:

1. Rule-Based URL Analysis
2. Machine Learning Prediction
3. Combined Security Decision
4. Feature Importance Analysis
5. SQLite Scan History
6. Flask Web Dashboard

The purpose of the project is to demonstrate how traditional security rules and machine learning can be combined to analyze suspicious URLs.

---

## 2. Problem Statement

Phishing attacks commonly use deceptive URLs to trick users into visiting malicious websites or providing sensitive information.

Manually identifying suspicious URLs can be difficult because attackers may use:

- Long URLs
- Suspicious paths
- Multiple subdomains
- IP addresses instead of domain names
- Excessive special characters
- Hyphens and digits
- Login or verification paths
- URL encoding
- Suspicious domain structures

This project analyzes these characteristics automatically.

---

## 3. Objectives

The main objectives are:

- Detect suspicious URL characteristics.
- Extract useful URL features.
- Apply rule-based security analysis.
- Train a Random Forest machine learning model.
- Predict whether a URL is legitimate or phishing.
- Combine rule-based and ML results.
- Display the analysis through a Flask web interface.
- Store previous scans in an SQLite database.
- Display machine-learning feature importance.
- Evaluate the trained model.

---

## 4. System Architecture

The system follows this workflow:

User
  |
  v
Flask Web Dashboard
  |
  v
Input Validation
  |
  v
URL Feature Extraction
  |
  +----------------------+
  |                      |
  v                      v
Rule-Based Analysis    ML Prediction
  |                      |
  +----------+-----------+
             |
             v
       Combined Decision
             |
             v
       Security Verdict
             |
       +-----+------+
       |            |
       v            v
   Dashboard    SQLite Database
                    |
                    v
               Scan History

---

## 5. Technologies Used

### Programming Language

- Python 3

### Web Framework

- Flask

### Machine Learning

- Scikit-learn
- Random Forest Classifier

### Data Processing

- Pandas

### Database

- SQLite

### URL Processing

- Python urllib.parse

### Frontend

- HTML
- CSS
- Jinja2 templates

### Operating System

- Kali Linux

### Virtualization

- Oracle VirtualBox

---

## 6. Dataset

The project uses an educational URL dataset stored in:

dataset.csv

The dataset contains two columns:

- url
- label

Labels are:

- 0 = Legitimate
- 1 = Phishing

The current educational dataset contains approximately 80 labeled URL examples.

The dataset is intentionally small and is used for project demonstration and learning.

It should not be considered a production-grade phishing dataset.

---

## 7. URL Feature Extraction

The system extracts structural characteristics from URLs.

The features include:

- https
- url_length
- path_length
- hostname_length
- slash_count
- subdomain_count
- dot_count
- hyphen_count
- digit_count
- is_ip
- special_character_count
- has_punycode
- at_symbol
- equal_count
- question_count
- has_percent_encoding
- query_parameter_count

These features convert a URL into numerical information that can be processed by the machine-learning model.

---

## 8. Rule-Based Analysis

The rule-based component checks URL characteristics associated with suspicious URLs.

Examples include:

- Use of an IP address
- Suspicious URL paths
- Long URLs
- Multiple subdomains
- Excessive special characters
- Suspicious login or verification patterns
- Lack of HTTPS
- Other structural indicators

The rules produce a security score.

The score is then converted into a risk level such as:

- LOW
- MEDIUM
- HIGH

---

## 9. Machine Learning Model

The project uses a Random Forest Classifier.

The training process is:

1. Load dataset.
2. Extract URL features.
3. Separate features and labels.
4. Split the dataset into training and testing data.
5. Train the Random Forest model.
6. Evaluate the model.
7. Save the trained model.

The trained model is saved as:

phishing_model.pkl

---

## 10. Machine Learning Prediction

For a new URL, the system:

1. Extracts the same features used during training.
2. Sends the features to the trained Random Forest model.
3. Predicts the URL class.
4. Calculates phishing probability.
5. Calculates legitimate probability.

The prediction is displayed on the dashboard.

Example:

Prediction: PHISHING

Phishing Probability: 100%

---

## 11. Feature Importance

The Random Forest model provides feature importance values.

These values indicate which URL features contributed most to the model's decisions on the educational dataset.

The project generates:

feature_importance.png

Important features in the current model include characteristics such as:

- HTTPS usage
- URL length
- Path length
- Hostname length
- Slash count
- Subdomain count
- Dot count

Feature importance does not mean that one feature alone proves that a URL is malicious.

---

## 12. Combined Security Decision

The project combines:

- Rule-Based Score
- Rule-Based Risk
- Machine Learning Prediction
- Machine Learning Probability

The combined decision provides a final security verdict.

Example:

Final Security Verdict:
POTENTIALLY SUSPICIOUS

Combined Score:
75/100

Rule-Based Score:
50/100

Rule-Based Risk:
MEDIUM

ML Prediction:
PHISHING

Phishing Probability:
100%

This combined approach demonstrates how multiple detection techniques can work together.

---

## 13. Flask Web Dashboard

The project provides a local web interface.

The application runs at:

http://127.0.0.1:5000

The dashboard provides:

- URL Scanner
- Security Verdict
- Combined Score
- Rule-Based Analysis
- ML Prediction
- Phishing Probability
- Feature Importance
- Model Evaluation
- Scan History

---

## 14. SQLite Scan History

The system stores scan results in:

scan_history.db

The database records information such as:

- Scan ID
- URL
- Security score
- Risk level
- Scan timestamp

The dashboard displays previous scans under:

Scan History

This allows users to review URLs that were previously analyzed.

---

## 15. Model Evaluation

The model is evaluated using common classification metrics:

- Accuracy
- Precision
- Recall
- F1 Score
- Confusion Matrix

The project also generates:

model_evaluation_report.txt

and:

confusion_matrix.png

The current educational evaluation produced very high results, including 100% accuracy on the tested educational split.

However, these results should NOT be interpreted as real-world phishing detection accuracy because the dataset is small and educational.

---

## 16. Example Tests

### Legitimate URL

https://www.google.com

Expected behavior:

Low risk / legitimate characteristics.

### Legitimate URL

https://www.microsoft.com

Expected behavior:

Low risk / legitimate characteristics.

### Educational Suspicious URL

http://example.com/login/verify-account

Expected behavior:

Suspicious characteristics may be detected because of the login/verification path and URL structure.

These URLs are used only for educational testing.

---

## 17. Project Files

Important project files include:

app.py
analyzer.py
ml_features.py
ml_predictor.py
combined_decision.py
ml_importance.py
evaluate_model.py
train_model.py
dataset.csv
phishing_model.pkl
scan_history.db
feature_importance.png
confusion_matrix.png
model_evaluation_report.txt
templates/
static/
tests/

---

## 18. How to Run the Project

Navigate to the project directory:

cd ~/phishing-url-detector

Activate the virtual environment:

source .venv/bin/activate

Check the Python application:

python3 -m py_compile app.py

Run the Flask application:

python3 app.py

Open the browser:

http://127.0.0.1:5000

Enter a URL and click:

Analyze

---

## 19. Model Training

The machine-learning model can be trained using the training script.

Example:

python3 train_model.py

The trained model is saved as:

phishing_model.pkl

Before retraining, make sure the dataset and feature extraction code are compatible.

---

## 20. Model Evaluation

The evaluation script can be used to measure model performance.

Example:

python3 evaluate_model.py

The evaluation includes:

- Accuracy
- Precision
- Recall
- F1 Score
- Confusion Matrix
- Classification Report

---

## 21. Security and Ethical Considerations

This project is designed for cybersecurity education and defensive analysis.

The system analyzes URL structure and does not require visiting a suspicious website.

Users should not open unknown or malicious URLs during testing.

The project should not be used to collect credentials, impersonate websites, or conduct phishing attacks.

---

## 22. Limitations

The current system has several limitations:

- The dataset is small.
- The dataset is educational.
- URL structure alone cannot prove that a website is malicious.
- Machine-learning accuracy on a small dataset may not represent real-world performance.
- The system does not perform complete website reputation analysis.
- The system does not replace commercial threat-intelligence services.
- Attackers can change URL structures to avoid simple detection rules.

---

## 23. Future Enhancements

Possible future improvements include:

- Larger real-world datasets
- Cross-validation
- Additional machine-learning algorithms
- URL reputation APIs
- Domain age analysis
- DNS analysis
- WHOIS information
- SSL certificate analysis
- Redirect analysis
- Threat-intelligence integration
- Improved visualization
- User authentication
- Production deployment using a WSGI server

---

## 24. Conclusion

The Phishing URL Detection System demonstrates a defensive cybersecurity approach to URL analysis.

The project combines rule-based detection with machine learning to produce a final security assessment.

The Flask dashboard provides an easy interface for URL analysis, while SQLite stores scan history and the machine-learning components provide prediction and feature-importance information.

The project successfully demonstrates the complete pipeline:

URL Input
    ->
Validation
    ->
Feature Extraction
    ->
Rule-Based Analysis
    ->
Machine Learning Prediction
    ->
Combined Decision
    ->
Security Verdict
    ->
Database Storage
    ->
Dashboard Display

This project is intended for educational and defensive cybersecurity purposes.
