# AI Cyber Threat Prediction System

A Python-based cybersecurity threat detection and prediction system that combines rule-based threat assessment with machine learning.

The system processes cybersecurity events from JSON files, extracts numerical features, predicts a threat level using a Decision Tree classifier, identifies the likely attack type, generates a security alert, and compares the ML prediction with a rule-based assessment.

## Features

* JSON-based cybersecurity event input
* Event loading and validation
* Event preprocessing and normalization
* Time-difference calculation between events
* Numerical feature extraction
* Sequence-based feature detection
* Decision Tree classification
* ML prediction confidence
* Rule-based threat assessment
* ML/rule-based assessment comparison
* Risk explanation
* Event severity calculation
* Attack type detection
* Security alert generation
* Feature importance analysis
* Model evaluation with accuracy, precision, recall and F1-score
* Confusion matrix
* Cross-validation
* Command-line interface
* CLI help with `--help`
* Multiple predefined threat scenarios
* Automated tests with pytest
* GitHub Actions CI

## Project Architecture

```text
ai-cyber-threat-prediction/

├── .github/
│   └── workflows/
│       └── tests.yml
│
├── data/
│   ├── events.json
│   ├── evaluation.json
│   └── scenarios/
│       ├── normal.json
│       ├── low.json
│       ├── medium.json
│       └── high.json
│
├── src/
│   ├── detection/
│   │   ├── alerts.py
│   │   ├── assessment.py
│   │   ├── attack_type.py
│   │   ├── explanation.py
│   │   ├── rules.py
│   │   └── severity.py
│   │
│   ├── prediction/
│   │   ├── evaluate.py
│   │   ├── features.py
│   │   ├── model.py
│   │   └── training_data.py
│   │
│   ├── preprocessing/
│   │   ├── event_loader.py
│   │   ├── events.py
│   │   └── normalize.py
│   │
│   ├── __init__.py
│   └── main.py
│
├── tests/
│   ├── test_alerts.py
│   ├── test_assessment.py
│   ├── test_attack_type.py
│   ├── test_explanation.py
│   ├── test_features.py
│   ├── test_normalize.py
│   ├── test_prediction.py
│   ├── test_rules.py
│   └── test_severity.py
│
├── requirements.txt
├── README.md
└── .gitignore
```

## How It Works

The system follows a multi-stage detection pipeline:

1. Cybersecurity events are loaded from a JSON file.
2. Events are validated, normalized and prepared for analysis.
3. Time differences between consecutive events are calculated.
4. Numerical features are extracted from the event sequence.
5. A Decision Tree classifier predicts the threat level.
6. The prediction confidence is calculated using the model probabilities.
7. Rule-based detection independently evaluates event sequences and timing.
8. The system identifies the likely attack type.
9. A security alert is generated according to the detected threat level.
10. The ML prediction and rule-based assessment are compared.
11. Risk explanations, severity information and feature importance are displayed.

### Extracted Features

The current model uses the following features:

* `port_scan_count`
* `failed_login_count`
* `successful_login_count`
* `port_scan_followed_by_failed_login`

These features are passed to a Decision Tree classifier.

## Threat Levels

The system supports four threat levels:

| Level    | Description                                                          |
| -------- | -------------------------------------------------------------------- |
| `normal` | No significant suspicious activity                                   |
| `low`    | Suspicious authentication activity                                   |
| `medium` | Port scan followed by a failed login                                 |
| `high`   | Port scan followed by a failed login and subsequent successful login |

## Attack Types

The system currently identifies several attack categories:

| Attack type             | Description                                                                       |
| ----------------------- | --------------------------------------------------------------------------------- |
| `normal`                | No significant attack pattern detected                                            |
| `brute_force`           | Multiple failed login attempts                                                    |
| `port_scanning`         | Port scanning activity detected                                                   |
| `credential_compromise` | Failed login activity followed by successful authentication                       |
| `multi_stage_attack`    | Combination of port scanning, failed authentication and successful authentication |

## Security Alerts

The system generates a security alert based on the rule-based threat level and detected attack type.

Examples include:

```text
SECURITY WARNING: credential_compromise detected (confidence: 100%)
```

```text
SECURITY ALERT: port_scanning detected (confidence: 100%)
```

```text
CRITICAL SECURITY ALERT: multi_stage_attack detected (confidence: 100%)
```

For a normal scenario, the system reports:

```text
No significant security threat detected
```

## Installation

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Running the System

Run the system using the default event file:

```bash
python -m src.main
```

You can also provide a custom JSON event file:

```bash
python -m src.main data/scenarios/high.json
```

## Scenario Examples

### Normal

```bash
python -m src.main data/scenarios/normal.json
```

### Low

```bash
python -m src.main data/scenarios/low.json
```

### Medium

```bash
python -m src.main data/scenarios/medium.json
```

### High

```bash
python -m src.main data/scenarios/high.json
```

## Command-Line Help

Display available CLI options:

```bash
python -m src.main --help
```

The application supports:

```text
usage: python -m src.main [-h] [--evaluate] [events_file]
```

The `events_file` argument is optional and defaults to:

```text
data/events.json
```

The `--evaluate` option runs model evaluation using the evaluation dataset.

## Model Evaluation

Evaluate the machine-learning model:

```bash
python -m src.main --evaluate
```

The evaluation reports:

* accuracy
* precision
* recall
* F1-score
* confusion matrix
* cross-validation scores

### Current Evaluation Results

The current evaluation dataset contains **12 samples**, with **3 samples for each threat class**.

Current accuracy:

```text
Accuracy: 1.00
```

Current classification performance:

```text
high:
  precision: 1.00
  recall:    1.00
  f1-score:  1.00
  support:   3

low:
  precision: 1.00
  recall:    1.00
  f1-score:  1.00
  support:   3

medium:
  precision: 1.00
  recall:    1.00
  f1-score:  1.00
  support:   3

normal:
  precision: 1.00
  recall:    1.00
  f1-score:  1.00
  support:   3
```

Confusion matrix:

```text
[[3 0 0 0]
 [0 3 0 0]
 [0 0 3 0]
 [0 0 0 3]]
```

Cross-validation:

```text
Scores: [1. 1. 1. 1.]
Mean accuracy: 1.00
```

The perfect evaluation results should be interpreted carefully because the project currently uses a small synthetic dataset.

The evaluation results demonstrate that the current model correctly classifies the provided evaluation samples, but they do not represent real-world cybersecurity performance.

## Running Tests

Run the complete test suite:

```bash
python -m pytest
```

Current test result:

```text
46 passed
```

The tests cover:

* alert generation
* attack type detection
* assessment comparison
* risk explanation
* feature extraction
* event normalization
* model prediction
* prediction pipeline
* rule-based threat detection
* event severity

## Example

Running a high-threat scenario:

```bash
python -m src.main data/scenarios/high.json
```

Example output:

```text
AI Cyber Threat Prediction System

Project started successfully!

Input: data/scenarios/high.json

ML prediction: high
Confidence: 100.00%
Threat level: high
Attack type: multi_stage_attack
Alert: CRITICAL SECURITY ALERT: multi_stage_attack detected (confidence: 100%)
Assessment agreement: YES

Risk explanation:

  - Port scan activity detected
  - Failed login attempts detected
  - Successful login after failed attempts detected

Risk severity:

  - MEDIUM: Port scan activity detected
  - LOW: Failed login attempts detected
  - HIGH: Successful login after failed attempts detected
```

## Feature Importance

The Decision Tree model also provides feature importance information.

Feature importance depends on the current training data and trained model.

For the current training configuration, the model exposes importance values for:

```text
port_scan_count
failed_login_count
successful_login_count
port_scan_followed_by_failed_login
```

These values describe the relative importance assigned by the current trained model and should not be interpreted as universal indicators of cybersecurity risk.

## Continuous Integration

The project uses GitHub Actions to automatically run the test suite.

The CI workflow is located at:

```text
.github/workflows/tests.yml
```

The workflow verifies that the automated test suite passes in the repository.

## Current Status

The project currently provides a working cybersecurity threat detection and prediction MVP with:

* cybersecurity event ingestion from JSON
* preprocessing and normalization
* time-difference calculation
* feature extraction
* sequence-based feature detection
* Decision Tree classification
* prediction confidence
* rule-based threat assessment
* ML/rule-based assessment comparison
* risk explanation
* event severity analysis
* attack type detection
* security alert generation
* model evaluation
* cross-validation
* feature importance analysis
* CLI support
* predefined threat scenarios
* automated tests
* Git version control
* GitHub Actions CI

## Limitations

This is an educational MVP rather than a production cybersecurity detection system.

The current machine-learning model uses a small synthetic training dataset. Therefore, the reported evaluation accuracy and prediction confidence should not be interpreted as real-world cybersecurity performance.

The attack type detection logic is also intentionally simple and is based on event patterns and counts rather than a comprehensive intrusion detection framework.

A production system would require:

* a substantially larger and representative dataset
* validation on unseen real-world data
* model calibration
* broader attack coverage
* more advanced sequence analysis
* monitoring
* additional security controls
* integration with real security infrastructure

## Future Improvements

Possible future improvements include:

* expanding the training dataset
* adding more cybersecurity event types
* using real-world or realistically generated datasets
* improving model validation
* comparing multiple ML algorithms
* improving confidence calibration
* improving attack sequence analysis
* adding structured logging
* adding a REST API
* adding monitoring and alerting
* containerizing the application
* expanding CI/CD pipelines
* adding integration tests
* adding more realistic attack scenarios
