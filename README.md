# AI Cyber Threat Prediction System

A Python-based cybersecurity threat detection and prediction system that combines rule-based threat assessment with machine learning.

The system processes cybersecurity events from JSON files, extracts numerical features, predicts a threat level using a Decision Tree classifier, and compares the ML prediction with a rule-based assessment.

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
│   │   ├── assessment.py
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
│   ├── test_assessment.py
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

The system accepts cybersecurity events such as:

* `port_scan_count`

* `failed_login_count`

* `successful_login_count`

* `port_scan_followed_by_failed_login`

Events are loaded from JSON, normalized and processed.

The system extracts numerical features including:

* `port_scan_count`

* `failed_login_count`

* `successful_login_count`

* `port_scan_followed_by_failed_login`

These features are passed to a Decision Tree classifier.

At the same time, rule-based detection evaluates the event sequence and timing.

The system then compares the ML prediction with the rule-based threat assessment.

The final output contains:

* ML prediction
* prediction confidence
* rule-based threat level
* assessment agreement
* risk explanations
* event severity
* feature importance

## Threat Levels

The system supports four threat levels:

| Level    | Description                                                          |
| -------- | -------------------------------------------------------------------- |
| `normal` | No significant suspicious activity                                   |
| `low`    | Suspicious authentication activity                                   |
| `medium` | Port scan followed by a failed login                                 |
| `high`   | Port scan followed by a failed login and subsequent successful login |

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

The current evaluation dataset contains 8 samples, with two samples for each threat class.

Current accuracy:

```text
Accuracy: 1.00
```

Current cross-validation result:

```text
Scores: [1.00, 1.00, 0.75, 1.00]

Mean accuracy: 0.94
```

The perfect evaluation accuracy should be interpreted carefully because the project currently uses a small synthetic dataset.

Cross-validation also shows that performance can vary between folds, which is expected with a small dataset.

## Running Tests

Run the complete test suite:

```bash
python -m pytest
```

Current test result:

```text
37 passed
```

The tests cover:

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

For the current training data:

```text
port_scan_count: 0.00%

failed_login_count: 33.33%

successful_login_count: 33.33%

port_scan_followed_by_failed_login: 33.33%
```

These values describe the relative importance assigned by the current trained model and should not be interpreted as universal indicators of cybersecurity risk.

## Continuous Integration

The project uses GitHub Actions to automatically run the test suite.

The CI workflow is located at:

```text
.github/workflows/tests.yml
```

The current workflow successfully passes the project's automated tests.

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

A production system would require a substantially larger and representative dataset, validation on unseen real-world data, model calibration, monitoring, additional security controls and more comprehensive threat coverage.

## Future Improvements

Possible future improvements include:

* expanding the training dataset
* adding more cybersecurity event types
* using real-world or realistically generated datasets
* improving model validation
* comparing multiple ML algorithms
* improving confidence calibration
* adding structured logging
* adding a REST API
* adding monitoring and alerting
* containerizing the application
* expanding CI/CD pipelines
* adding integration tests
* adding more realistic attack scenarios
