# AI Cyber Threat Prediction System

A Python-based cybersecurity threat detection and prediction system that combines machine learning with rule-based risk assessment, attack-chain detection, explainable security analysis, and alert generation.

The system processes cybersecurity events from JSON files, performs preprocessing and feature engineering, predicts a threat level using a trained machine-learning model, evaluates the result using rule-based security logic, detects attack patterns, and generates security alerts.

The project uses a layered architecture with application, domain, infrastructure, and ML components.

## Features

* JSON-based cybersecurity event ingestion
* Event validation and preprocessing
* Timestamp normalization and time-difference calculation
* Feature engineering from event sequences
* 11 ML features
* Synthetic balanced ML dataset generation
* Stratified train/test split
* Logistic Regression production model
* Random Forest and SVM benchmarks
* Decision Tree baseline
* Model comparison
* 5-fold cross-validation
* Prediction confidence using `predict_proba`
* Model persistence with `joblib`
* Rule-based threat assessment
* ML/rule-based assessment comparison
* Risk explanation
* Event severity calculation
* Attack type detection
* Multi-stage attack-chain detection
* Security alert generation
* Feature importance analysis
* Asynchronous analysis jobs
* In-memory and PostgreSQL persistence components
* FastAPI application layer
* Command-line interface
* Automated tests with pytest
* GitHub Actions CI

## Project Architecture

```text
ai-cyber-threat-prediction/
│
├── .github/
│   └── workflows/
│       └── tests.yml
│
├── data/
│   ├── events.json
│   ├── ml_dataset.json
│   └── scenarios/
│       ├── normal.json
│       ├── low.json
│       ├── medium.json
│       └── high.json
│
├── models/
│   └── threat_model.joblib
│
├── src/
│   │
│   ├── application/
│   │   ├── analyze_threat.py
│   │   ├── composition.py
│   │   ├── job.py
│   │   ├── job_repository.py
│   │   ├── model_evaluation.py
│   │   └── ...
│   │
│   ├── alerts/
│   │   └── ...
│   │
│   ├── bootstrap/
│   │   └── ...
│   │
│   ├── config/
│   │   └── settings.py
│   │
│   ├── detection/
│   │   ├── alerts.py
│   │   ├── assessment.py
│   │   ├── attack_type.py
│   │   ├── explanation.py
│   │   ├── rules.py
│   │   └── severity.py
│   │
│   ├── features/
│   │   └── ...
│   │
│   ├── ingestion/
│   │   └── ...
│   │
│   ├── infrastructure/
│   │   └── ...
│   │
│   ├── pipeline/
│   │   └── ...
│   │
│   ├── prediction/
│   │   ├── baseline.py
│   │   ├── compare_models.py
│   │   ├── cross_validation.py
│   │   ├── data/
│   │   │   └── generator.py
│   │   ├── dataset.py
│   │   ├── evaluate.py
│   │   ├── features.py
│   │   ├── final_evaluation.py
│   │   ├── legacy_prediction_engine.py
│   │   ├── model.py
│   │   ├── model_comparison.py
│   │   ├── persistence.py
│   │   ├── predict.py
│   │   └── train.py
│   │
│   ├── preprocessing/
│   │   ├── event_loader.py
│   │   ├── events.py
│   │   └── normalize.py
│   │
│   ├── risk/
│   │   └── ...
│   │
│   ├── main.py
│   └── ...
│
├── tests/
│   ├── test_dataset.py
│   ├── test_persistence.py
│   ├── test_prediction.py
│   ├── test_prediction_engine.py
│   ├── test_threat_pipeline.py
│   └── ...
│
├── requirements.txt
├── README.md
└── .gitignore
```

The exact implementation is divided into separate layers so that machine-learning logic can evolve without breaking the application architecture.

## How It Works

The system follows a multi-stage analysis pipeline:

1. Cybersecurity events are loaded from a JSON source.
2. Events are validated and normalized.
3. Timestamp differences are calculated.
4. Features are extracted from the event sequence.
5. The ML prediction engine converts the extracted features into the model input vector.
6. The saved Logistic Regression model predicts the threat level.
7. Prediction confidence is calculated from model probabilities.
8. Rule-based security logic independently evaluates the event sequence.
9. Correlations and attack chains are analysed.
10. The system identifies the likely attack type.
11. Risk explanations and event severity information are generated.
12. The ML prediction and rule-based assessment are compared.
13. A security alert is generated when appropriate.

The production architecture uses a prediction-engine abstraction, allowing the underlying ML model to be replaced without changing the application pipeline.

## Machine Learning Pipeline

The current ML pipeline consists of:

```text
Synthetic Dataset
       │
       ▼
Dataset Loading
       │
       ▼
Stratified Train/Test Split
       │
       ▼
Model Benchmarking
       │
       ├── Decision Tree
       ├── Random Forest
       ├── Logistic Regression
       └── SVM
       │
       ▼
5-Fold Cross-Validation
       │
       ▼
Logistic Regression Selected
       │
       ▼
Training on Full Dataset
       │
       ▼
joblib Persistence
       │
       ▼
Production Prediction Engine
```

## Dataset

The project currently uses a synthetic cybersecurity dataset generated specifically for the ML pipeline.

The dataset contains:

* **1000 samples**
* **4 balanced threat classes**
* **250 samples per class**
* **11 numerical features**

Classes:

* `normal`
* `low`
* `medium`
* `high`

The dataset is generated by:

```bash
python -m src.prediction.data.generator
```

The generated dataset is stored in:

```text
data/ml_dataset.json
```

### Important limitation

The dataset is synthetic and intentionally designed for development and architectural validation.

Therefore, perfect or near-perfect benchmark results **must not be interpreted as real-world cybersecurity detection accuracy**.

A production cybersecurity system would require validation against representative real-world or independently generated data.

## Extracted ML Features

The production model currently uses the following 11 features:

1. `port_scan_count`
2. `failed_login_count`
3. `successful_login_count`
4. `event_count`
5. `unique_source_count`
6. `time_span_seconds`
7. `failed_login_rate`
8. `successful_login_rate`
9. `rapid_failed_login_count`
10. `port_scan_followed_by_failed_login`
11. `failed_login_followed_by_successful_login`

The feature vector is created centrally by:

```text
src/prediction/features.py
```

This ensures that training and production inference use the same feature ordering.

## Dataset Split

The dataset is divided using a stratified 80/20 train/test split.

Configuration:

```text
Test size: 20%
Random state: 42
Stratification: enabled
```

Result:

```text
Training samples: 800
Test samples: 200
```

Each split preserves the class distribution.

Dataset loading and splitting are implemented in:

```text
src/prediction/dataset.py
```

## Model Comparison

The project compares several machine-learning algorithms.

### Holdout Evaluation

| Model                   |   Accuracy |   Macro F1 |
| ----------------------- | ---------: | ---------: |
| Random Forest           |     0.9950 |     0.9950 |
| **Logistic Regression** | **1.0000** | **1.0000** |
| SVM                     |     0.9950 |     0.9950 |

The final production model is Logistic Regression.

### Cross-Validation

Five-fold cross-validation produced:

| Model                   | Mean Accuracy |        Std |
| ----------------------- | ------------: | ---------: |
| Decision Tree           |        0.9860 |     0.0086 |
| Random Forest           |        0.9930 |     0.0068 |
| **Logistic Regression** |    **0.9960** | **0.0037** |
| **SVM**                 |    **0.9960** | **0.0037** |

Logistic Regression was selected for production because it provides:

* competitive cross-validation performance
* perfect holdout performance on the current synthetic dataset
* probability estimates through `predict_proba`
* simple and efficient inference
* straightforward integration with the existing prediction abstraction

Benchmark implementations are kept separately from the production prediction path.

## Production Model

The trained production model is stored as:

```text
models/threat_model.joblib
```

The model is loaded by the production prediction engine:

```text
src/prediction/legacy_prediction_engine.py
```

Model persistence is implemented in:

```text
src/prediction/persistence.py
```

The model can be retrained with:

```bash
python -m src.prediction.train
```

This trains the final Logistic Regression model using the complete dataset and saves it to the `models/` directory.

## Prediction Example

To test the saved model directly:

```bash
python -m src.prediction.predict
```

Example:

```text
Prediction: high
Confidence: 0.9910
```

## Model Evaluation

Run the application-level model evaluation with:

```bash
python -m src.main --evaluate
```

Current evaluation on the 20% holdout set:

```text
Accuracy: 1.0000
Macro F1: 1.0000
```

All four classes currently achieve:

```text
Precision: 1.00
Recall:    1.00
F1-score:  1.00
```

with 50 test samples per class.

Confusion matrix:

```text
[[50  0  0  0]
 [ 0 50  0  0]
 [ 0  0 50  0]
 [ 0  0  0 50]]
```

Again, these results describe performance on the current synthetic benchmark dataset and should not be interpreted as production-world performance.

## Threat Levels

The system supports four threat levels:

| Level    | Description                                                                                       |
| -------- | ------------------------------------------------------------------------------------------------- |
| `normal` | No significant suspicious activity                                                                |
| `low`    | Suspicious authentication activity                                                                |
| `medium` | Suspicious scanning or repeated authentication activity                                           |
| `high`   | Multi-stage malicious activity involving reconnaissance, credential attacks and successful access |

## Attack Types

The system identifies several attack categories:

| Attack type             | Description                                                                        |
| ----------------------- | ---------------------------------------------------------------------------------- |
| `normal`                | No significant attack pattern detected                                             |
| `brute_force`           | Multiple failed login attempts                                                     |
| `port_scanning`         | Port scanning activity detected                                                    |
| `credential_compromise` | Failed authentication followed by successful authentication                        |
| `multi_stage_attack`    | Combination of reconnaissance, failed authentication and successful authentication |

## Attack Chain Detection

The system can identify multi-stage attack chains from correlated events.

For example:

```text
port_scan
    ↓
failed_login
    ↓
successful_login
```

This can produce:

```text
attack_type: multi_stage_attack
stage_count: 3
```

The attack-chain analysis is separate from the ML prediction and contributes to the overall risk assessment.

## Security Alerts

Security alerts are generated from the risk assessment and detected attack type.

Example:

```text
CRITICAL SECURITY ALERT: multi_stage_attack detected (confidence: 98%)
```

The system also provides explanations and severity information, for example:

```text
Risk explanation:
  - Port scan activity detected
  - Failed login attempts detected
  - Successful login after failed attempts detected

Risk severity:
  - MEDIUM: Port scan activity detected
  - LOW: Failed login attempts detected
  - HIGH: Successful login after failed attempts detected
```

## Running the System

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

Run the default analysis:

```bash
python -m src.main
```

Run a specific scenario:

```bash
python -m src.main data/scenarios/high.json
```

Available scenarios include:

```text
data/scenarios/normal.json
data/scenarios/low.json
data/scenarios/medium.json
data/scenarios/high.json
```

## Command-Line Interface

Display available CLI options:

```bash
python -m src.main --help
```

The main application supports:

```text
python -m src.main [-h] [--evaluate] [events_file]
```

The event file is optional and defaults to:

```text
data/events.json
```

The `--evaluate` option runs the current ML evaluation pipeline.

## API and Application Layer

The project also contains an application/API layer for asynchronous threat analysis and job processing.

The architecture supports:

* threat analysis requests
* asynchronous jobs
* job lifecycle management
* job repositories
* in-memory persistence
* PostgreSQL persistence
* FastAPI endpoints
* dependency composition through application/bootstrap components

The ML implementation is integrated through application-level ports rather than being directly coupled to the main pipeline.

This allows the ML model to evolve independently of the rest of the application architecture.

## Running Tests

Run the complete test suite:

```bash
python -m pytest
```

Current result:

```text
156 passed, 1 warning
```

The tests cover:

* event ingestion
* preprocessing
* normalization
* feature extraction
* dataset loading
* dataset splitting
* model prediction
* model persistence
* prediction engine
* risk assessment
* rule-based detection
* attack-chain detection
* alert generation
* threat pipeline
* asynchronous analysis
* job lifecycle
* API behavior
* PostgreSQL repositories
* configuration
* model evaluation

The current warning originates from an external Starlette/AnyIO deprecation and does not cause test failures.

## Example

Running the default application:

```bash
python -m src.main
```

Current example output:

```text
AI Cyber Threat Prediction System

Project started successfully!

Input: data/events.json

ML prediction: high

Confidence: 98.18%

Threat level: high

Attack type: multi_stage_attack

Assessment agreement: YES

Risk explanation:
  - Port scan activity detected
  - Failed login attempts detected
  - Successful login after failed attempts detected

Risk severity:
  - MEDIUM: Port scan activity detected
  - LOW: Failed login attempts detected
  - HIGH: Successful login after failed attempts detected

Alert: CRITICAL SECURITY ALERT: multi_stage_attack detected (confidence: 98%)
```

## Feature Importance

The prediction module supports feature-importance analysis.

For models exposing coefficients, such as the production Logistic Regression model, the absolute coefficient magnitudes are used to estimate relative feature importance.

The feature names correspond to the 11 production ML features listed above.

These values describe the trained model and should not be interpreted as universal measures of cybersecurity risk.

## Continuous Integration

The project uses GitHub Actions to automatically run the test suite.

The workflow is located at:

```text
.github/workflows/tests.yml
```

CI verifies that the automated test suite continues to pass after changes.

## Current Status

The project currently provides a working cybersecurity threat detection and prediction MVP with:

* modular application architecture
* cybersecurity event ingestion
* preprocessing and normalization
* feature engineering
* 11-feature ML pipeline
* synthetic balanced dataset
* stratified train/test split
* model comparison
* 5-fold cross-validation
* Logistic Regression production model
* model persistence
* prediction confidence
* rule-based threat assessment
* ML/rule-based assessment comparison
* risk explanation
* event severity analysis
* attack type detection
* multi-stage attack-chain detection
* security alert generation
* asynchronous job processing
* API layer
* PostgreSQL persistence components
* CLI support
* predefined threat scenarios
* automated tests
* GitHub Actions CI

## Limitations

This project is an educational cybersecurity ML MVP rather than a production intrusion-detection platform.

The current ML dataset is synthetic. Therefore:

* benchmark accuracy does not represent real-world detection accuracy
* model confidence is not necessarily calibrated to real-world probabilities
* attack patterns are simplified
* the dataset does not represent the full diversity of cybersecurity telemetry
* additional validation on independent real-world data is required

The current rule-based attack-chain detection is also intentionally simplified.

A production system would require additional capabilities such as:

* large representative cybersecurity datasets
* independent external validation datasets
* temporal and sequence-aware modelling
* probability calibration
* concept-drift monitoring
* false-positive analysis
* adversarial robustness
* model monitoring
* explainability improvements
* broader attack coverage
* real SIEM/security-tool integration
* production authentication and authorization
* structured observability
* scalable deployment

## Future Improvements

Potential future improvements include:

* replacing synthetic data with representative real-world datasets
* expanding event types and attack scenarios
* adding independent validation data
* calibrating prediction probabilities
* introducing more advanced temporal features
* experimenting with sequence models
* improving attack-chain analysis
* adding model monitoring
* tracking model performance over time
* expanding API functionality
* improving observability and structured logging
* containerizing the application
* expanding CI/CD
* adding deployment automation
* integrating with real cybersecurity infrastructure

## Project Status

The current ML improvement roadmap has been completed through the following stages:

1. ML implementation audit
2. Dataset improvement
3. Feature engineering and preprocessing
4. Stratified train/test split
5. Model comparison
6. Full evaluation
7. Model persistence
8. Integration with the existing architecture
9. Automated tests and final verification
