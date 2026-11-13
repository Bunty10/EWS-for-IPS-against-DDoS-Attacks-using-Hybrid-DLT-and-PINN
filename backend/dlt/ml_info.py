"""
Static description of the detection engine for the ML Information page.
Kept in sync with approach_hybrid.py / preprocessing.py.
"""
from dlt import pipeline


def ml_info():
    mod = pipeline.active()
    return {
        "name": mod.NAME,
        "approach_id": mod.ID,
        "summary": (
            "A neural network trained only on benign traffic learns the per-second "
            "signature of 'normal'. Each second is scored by the Euclidean distance "
            "between its normalised features and the network's reconstruction; distances "
            "crossing the learned thresholds become LOW/MED/HIGH early warnings."
        ),
        "approach": [
            "Aggregate raw flows into 1-second bins.",
            "Normalise the features of each second.",
            "Reconstruct the expected benign vector with the trained network.",
            "Score = Euclidean distance between observed and reconstructed features.",
            "Grade the score against benign-baseline thresholds (mean + k·std).",
        ],
        "framework": "PyTorch neural network",
        "thresholds": {
            "LOW": "mean + 1·std of benign scores",
            "MED": "mean + 2·std",
            "HIGH": "mean + 3·std",
        },
        "features": pipeline.FEATURES,
        "feature_count": pipeline.NUM_FEATURES,
        "min_seconds": mod.MIN_SECONDS,
        "configuration": {
            "attack_ratio_threshold": 0.07,
            "live_reanalyze_interval_s": 1.0,
            "per_workflow_baselines": "LIVE → VNRVJIET · CSV → CICDDoS2019",
            "database": "dlt_results/alerts.db (SQLite)",
            "email": "SMTP via env vars (SMTP_HOST, ALERT_EMAIL_TO, ...) — HIGH alerts only",
        },
    }
