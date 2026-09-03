AI Cyber Threat Prediction
A Python-based cybersecurity threat detection and prediction system.
The project combines:

rule-based threat detection;
event preprocessing;
feature extraction;
machine learning prediction using a Decision Tree classifier;
automated tests with pytest.
Project Architecture
ai-cyber-threat-prediction/
├── src/
│   ├── detection/
│   │   └── rules.py
│   ├── prediction/
│   │   ├── features.py
│   │   ├── model.py
│   │   └── training_data.py
│   ├── preprocessing/
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
The system processes cybersecurity events such as:
port scans;
failed login attempts;
successful logins.
The events are normalized and converted into numerical features:
port_scan_count
failed_login_count
successful_login_count

These features are passed to a Decision Tree machine learning model.
At the same time, rule-based detection analyzes event sequences and timing.

The system produces two results:

ML prediction: high
Threat level: high

Threat Levels
The current system supports four threat levels:
Level	Description
normal	No suspicious activity detected
low	Suspicious authentication activity
medium	Port scan followed by a failed login
high	Port scan followed by failed login and subsequent successful login

Installation
Create and activate a virtual environment:
python3 -m venv .venv
AI Cyber Threat Prediction
A Python-based cybersecurity threat detection and prediction system.
The project combines:

rule-based threat detection;
event preprocessing;
feature extraction;
machine learning prediction using a Decision Tree classifier;
automated tests with pytest.
Project Architecture
ai-cyber-threat-prediction/
├── src/
│   ├── detection/
│   │   └── rules.py
│   ├── prediction/
│   │   ├── features.py
│   │   ├── model.py
│   │   └── training_data.py
│   ├── preprocessing/
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
The system processes cybersecurity events such as:
port scans;
failed login attempts;
successful logins.
The events are normalized and converted into numerical features:
port_scan_count
failed_login_count
successful_login_count

These features are passed to a Decision Tree machine learning model.
At the same time, rule-based detection analyzes event sequences and timing.

The system produces two results:

ML prediction: high
Threat level: high

Threat Levels
The current system supports four threat levels:
Level	Description
normal	No suspicious activity detected
low	Suspicious authentication activity
medium	Port scan followed by a failed login
high	Port scan followed by failed login and subsequent successful login

Installation
Create and activate a virtual environment:
python3 -m venv .venv
source .venv/bin/activate

Install dependencies:
pip install -r requirements.txt

Running the System
Run:
python -m src.main

Example output:
AI Cyber Threat Prediction System
Project started successfully!
ML prediction: high
Threat level: high

Running Tests
Run the complete test suite:
python -m pytest

The current test suite verifies both machine-learning predictions and rule-based threat detection.
Current Status
The project currently contains a working MVP with:
event preprocessing;
feature extraction;
Decision Tree classification;
rule-based threat assessment;
automated tests;
dependency management;
Git version control.
Future Improvements
Possible next steps include:
accepting events from JSON or API input;
expanding the training dataset;
improving ML evaluation;
adding precision, recall and F1-score metrics;
separating training from prediction;
adding a REST API;
adding logging and monitoring;
supporting additional cybersecurity event types.ў

