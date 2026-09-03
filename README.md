# AI Cyber Threat Prediction System

A Python-based cybersecurity threat detection and prediction system that combines rule-based threat assessment with machine learning.

## Features

- JSON-based cybersecurity event input
- Event preprocessing and normalization
- Time-difference calculation between events
- Numerical feature extraction
- Decision Tree classification
- Rule-based threat assessment
- ML prediction confidence
- Model evaluation with accuracy, precision, recall and F1-score
- Confusion matrix
- Command-line interface
- CLI help with `--help`
- Multiple predefined threat scenarios
- Automated tests with pytest

## Project Architecture

```text
ai-cyber-threat-prediction/
├── data/
│   ├── events.json
│   ├── evaluation.json
│   └── scenarios/
│       ├── normal.json
│       ├── low.json
│       ├── medium.json
│       └── high.json
├── src/
│   ├── detection/
│   │   └── rules.py
│   ├── prediction/
│   │   ├── evaluate.py
│   │   ├── features.py
│   │   ├── model.py
│   │   └── training_data.py
│   ├── preprocessing/
│   │   ├── event_loader.py
│   │   ├── events.py
│   │   └── normalize.py
│   └── main.py
├── tests/
│   ├── test_prediction.py
│   └── test_rules.py
├── requirements.txt
├── README.md
└── .gitignore

How It Works
The system accepts cybersecurity events such as:
port_scan
failed_login
successful_login
Events are loaded from JSON, normalized and processed.
The system extracts numerical features including:

port_scan_count
failed_login_count
successful_login_count
These features are passed to a Decision Tree classifier.
At the same time, rule-based detection evaluates the event sequence and timing.

The final output contains:

ML prediction
prediction confidence
rule-based threat level
Example:
ML prediction: high
Confidence: 100.00%
Threat level: high

Threat Levels
The system supports four threat levels:
Level	Description
normal	No significant suspicious activity
low	Suspicious authentication activity
medium	Port scan followed by a failed login
high	Port scan followed by a failed login and subsequent successful login

Installation
Create a virtual environment:
python3 -m venv .venv

Activate it:
source .venv/bin/activate

Install dependencies:
pip install -r requirements.txt

Running the System
Run the system using the default event file:
python -m src.main

You can also provide a custom JSON event file:
python -m src.main data/scenarios/high.json

Scenario Examples
Normal:
python -m src.main data/scenarios/normal.json

Low:
python -m src.main data/scenarios/low.json

Medium:
python -m src.main data/scenarios/medium.json

High:
python -m src.main data/scenarios/high.json

Command-Line Help
Display available CLI options:
python -m src.main --help

The application supports:
usage: python -m src.main [-h] [--evaluate] [events_file]

Model Evaluation
Evaluate the machine-learning model using the evaluation dataset:
python -m src.main --evaluate

The evaluation reports:
accuracy
precision
recall
F1-score
confusion matrix
The current evaluation dataset contains 8 samples, with two samples for each threat class.
Current result:

Accuracy: 1.00

The perfect score should be interpreted carefully because the project currently uses a small synthetic dataset.
Running Tests
Run the complete test suite:
python -m pytest

Current test suite:
17 passed

The tests cover:
feature extraction
model predictions
prediction pipeline
evaluation dataset
CLI functionality
rule-based threat detection
Example
Running a high-threat scenario:
python -m src.main data/scenarios/high.json

Expected output:
AI Cyber Threat Prediction System
Project started successfully!
Input: data/scenarios/high.json
ML prediction: high
Confidence: 100.00%
Threat level: high

Current Status
The project currently provides a working MVP with:
cybersecurity event ingestion from JSON
preprocessing and normalization
feature extraction
Decision Tree classification
prediction confidence
rule-based threat assessment
model evaluation
CLI support
predefined test scenarios
automated tests
Git version control
Limitations
This is an educational MVP rather than a production cybersecurity detection system.
The current machine-learning model uses a small synthetic training dataset. Therefore, the reported evaluation accuracy and prediction confidence should not be interpreted as real-world cybersecurity performance.

A production system would require a substantially larger and representative dataset, validation on unseen real-world data, monitoring, model calibration and additional security controls.

Future Improvements
Possible future improvements include:
expanding the training dataset
adding more cybersecurity event types
using real-world or realistically generated datasets
improving model validation
adding cross-validation
comparing multiple ML algorithms
improving confidence calibration
adding structured logging
adding a REST API
adding monitoring and alerting
containerizing the application
adding CI/CD with automated tests
