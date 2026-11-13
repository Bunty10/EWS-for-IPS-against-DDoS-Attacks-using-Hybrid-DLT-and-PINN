"""
Hybrid DLT-PINNs EWS IPS — detection engine.

A small neural network (see ../model.py) is trained on benign-only traffic to
reconstruct the expected per-second feature vector. Each second is scored by the
Euclidean distance between its normalised features and that reconstruction; the
larger the distance, the more anomalous the second. A pre-trained network and its
score thresholds ship per workflow.

PyTorch is required and imported lazily, so a missing install surfaces a clear
message at analysis time rather than at import.
"""
import logging
import pickle
from pathlib import Path

import numpy as np

from dlt import preprocessing as pp

logger = logging.getLogger("dlt.hybrid")

ID = "hybrid"
NAME = "Hybrid DLT-PINNs EWS IPS"
DESCRIPTION = ("Neural network (DLT-NN) trained on benign traffic; scores each second "
               "by its distance from the learned baseline. Requires PyTorch.")
MODEL_SUBDIR = "hybrid"

# The network scores every second, so only a couple of seconds are needed to
# normalise the features.
MIN_SECONDS = 2

# Each workflow uses its own pre-trained network + thresholds, never the other's.
MODEL_SETS = {
    "LIVE": {"model": "model_VNRVJIET.pkl", "thresholds": "thresholds_VNRVJIET.pkl", "dataset": "VNRVJIET"},
    "CSV": {"model": "model_CICDDoS2019.pkl", "thresholds": "thresholds_CICDDoS2019.pkl", "dataset": "CICDDoS2019"},
}


def resolve_model_set(mode):
    key = (mode or "").strip().upper()
    if key not in MODEL_SETS:
        raise ValueError(f"Unknown analysis mode {mode!r}. Expected one of {list(MODEL_SETS)}.")
    return key, MODEL_SETS[key]


def _require_torch():
    try:
        import torch  # noqa: F401
        return torch
    except ImportError as e:
        raise RuntimeError(
            "This engine needs PyTorch. Install it with: pip install torch"
        ) from e


def _nn_scores(df, model):
    """Euclidean distance between each second's normalised features and the
    network's reconstruction of the benign baseline."""
    torch = _require_torch()
    norm = {f: (df[f] - df[f].mean()) / df[f].std() for f in pp.FEATURES}
    observed = np.column_stack([norm[f].values for f in pp.FEATURES]).astype(np.float32)
    x = torch.arange(1, len(df) + 1, dtype=torch.float32).reshape(-1, 1)
    with torch.no_grad():
        reconstructed = model(x).numpy()
    return np.sqrt(np.sum((observed - reconstructed) ** 2, axis=1))


def run_test_only(test_df, results_folder, model_folder, mode="LIVE", allow_ungraded=False):
    """Score a dataset for the given workflow mode using the pre-trained network."""
    mode_key, mset = resolve_model_set(mode)
    base = Path(model_folder) / MODEL_SUBDIR
    model_path, thr_path = base / mset["model"], base / mset["thresholds"]
    logger.info("Hybrid DLT-NN analysis | mode=%s | dataset=%s", mode_key, mset["dataset"])
    if not model_path.is_file() or not thr_path.is_file():
        raise FileNotFoundError(f"{mode_key}-mode model files not found in {base}.")

    _require_torch()
    with open(model_path, "rb") as f:
        model = pickle.load(f)
    with open(thr_path, "rb") as f:
        th = pickle.load(f)

    df = pp.prepare(test_df)
    graded = len(df) >= MIN_SECONDS
    if not graded and not allow_ungraded:
        raise ValueError(f"Need at least {MIN_SECONDS} seconds to analyse; got {len(df)}.")
    df["Score"] = _nn_scores(df, model) if graded else np.nan

    return pp.build_test_result(df, th["thresholds"], graded, {
        "approach": ID, "approach_name": NAME,
        "mode": mode_key, "dataset": mset["dataset"],
        "model_file": mset["model"], "thresholds_file": mset["thresholds"],
    })


def run_train_only(train_df, results_folder, model_folder):
    """Train the benign-baseline network and save it with its thresholds."""
    torch = _require_torch()
    import torch.nn as nn
    import torch.optim as optim
    from model import DatasetGeneratorNN

    df = pp.prepare(train_df)
    df = df[df[pp.LABEL_COL] == "BENIGN"]
    if len(df) < MIN_SECONDS:
        raise ValueError(f"Need at least {MIN_SECONDS} benign seconds to train; got {len(df)}.")

    norm = {f: (df[f] - df[f].mean()) / df[f].std() for f in pp.FEATURES}
    y = torch.tensor(np.column_stack([norm[f].values for f in pp.FEATURES]).astype(np.float32))
    x = torch.arange(1, len(df) + 1, dtype=torch.float32).reshape(-1, 1)

    def dlt(v, s=0.5):
        n = torch.arange(len(v), dtype=torch.float32)
        return torch.sum(v * torch.exp(-s * n))
    x_ref = torch.stack([dlt(y[:, i]) for i in range(pp.NUM_FEATURES)])

    model = DatasetGeneratorNN(pp.NUM_FEATURES)
    opt, mse = optim.Adam(model.parameters(), lr=0.01), nn.MSELoss()
    for _ in range(50):
        opt.zero_grad()
        pred = model(x)
        dlt_pred = torch.stack([dlt(pred[:, i]) for i in range(pp.NUM_FEATURES)])
        (mse(y, pred) + 0.1 * torch.mean((x_ref - dlt_pred) ** 2)).backward()
        opt.step()

    with torch.no_grad():
        scores = np.sqrt(np.sum((y.numpy() - model(x).numpy()) ** 2, axis=1))
    mu, std = float(scores.mean()), float(scores.std())
    thresholds = {"LOW": mu + std, "MED": mu + 2 * std, "HIGH": mu + 3 * std}
    out = Path(model_folder) / MODEL_SUBDIR
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "model_VNRVJIET.pkl", "wb") as f:
        pickle.dump(model, f)
    with open(out / "thresholds_VNRVJIET.pkl", "wb") as f:
        pickle.dump({"thresholds": thresholds, "LOW_THR": thresholds["LOW"],
                     "MED_THR": thresholds["MED"], "HIGH_THR": thresholds["HIGH"]}, f)
    return {"thresholds": thresholds,
            "residual_stats": {"mean": mu, "std": std, "max": float(scores.max())}}
