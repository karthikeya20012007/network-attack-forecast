import io
import asyncio
import redis
import json
import uuid
from pathlib import Path
from typing import Dict, List, Optional
import traceback

import numpy as np
import pandas as pd
import torch
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

from .model import (
    TGAT_WorldModel,
    ManualScaler,
    signed_log1p,
    normalize_col,
    build_agg_names,
    MITRE_NAMES,
)

app = FastAPI(title="NCIIPC Cyber World Model Defense API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).parent
SCENARIOS_PATH = BASE_DIR / "scenarios.json"
CHECKPOINT_PATH = BASE_DIR / "lstm_world_model.pth"

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ─── Load trained checkpoint once at startup ───────────────────────────────
_checkpoint = None
_model: Optional[TGAT_WorldModel] = None
_scaler: Optional[ManualScaler] = None
_feature_cols: List[str] = []
_seq_len: int = 5
_best_threshold: float = 0.55
_benign_mse_baseline: Optional[dict] = None
_k_steps: int = 5
_window_size: str = "1min"
_agg_names: List[str] = []

_live_state: Dict = {}
_uploaded_scenarios: Dict = {}

# ─── MITRE ATT&CK RAG (loaded once at startup) ────────────────────────────
_rag_service = None

def _load_checkpoint():
    global _checkpoint, _model, _scaler, _feature_cols, _seq_len
    global _best_threshold, _benign_mse_baseline, _k_steps, _window_size, _agg_names

    if not CHECKPOINT_PATH.exists():
        # Server can still run in "static scenarios only" mode.
        print(f"[warn] {CHECKPOINT_PATH} not found — /api/upload-csv will be disabled.")
        return

    ckpt = torch.load(CHECKPOINT_PATH, map_location=device, weights_only=False)
    _feature_cols = ckpt["feature_cols"]
    state_dim = ckpt["state_dim"]
    _seq_len = ckpt["seq_len"]
    _best_threshold = float(ckpt["best_threshold"])
    _benign_mse_baseline = ckpt.get("benign_mse_baseline")
    cfg = ckpt.get("config", {})
    _k_steps = cfg.get("k_steps", 5)
    _window_size = cfg.get("window_size", "1min")
    _agg_names = build_agg_names(_feature_cols)

    model = TGAT_WorldModel(
        state_dim=state_dim,
        hidden_size=ckpt["hidden_size"],
        num_layers=ckpt["num_layers"],
    )
    model.load_state_dict(ckpt["model_state_dict"])
    model.to(device)
    model.eval()

    scaler = ManualScaler(ckpt["scaler_mean"], ckpt["scaler_scale"])

    globals()["_checkpoint"] = ckpt
    globals()["_model"] = model
    globals()["_scaler"] = scaler
    print(
        f"[ok] Loaded checkpoint: {len(_feature_cols)} features, seq_len={_seq_len}, "
        f"threshold={_best_threshold:.4f}"
    )


_load_checkpoint()


def _init_rag():
    """Initialize the MITRE ATT&CK RAG service (best-effort, never crashes server)."""
    global _rag_service
    try:
        from mitre_rag.service import MitreRAGService
        _rag_service = MitreRAGService()
        if _rag_service.is_ready:
            print("[RAG] MITRE ATT&CK RAG initialized successfully.")
        else:
            print("[RAG] RAG service created but index not ready. "
                  "Run 'python -m mitre_rag.scripts.build_index' to build the index.")
    except Exception as e:
        print(f"[RAG] Failed to initialize RAG service: {e}")
        print("[RAG] RAG features will be unavailable. The server continues without RAG.")
        _rag_service = None


_init_rag()

# ─── scenarios.json persistence (static scenarios + ingested uploads) ──────



# ─── Live Redis Stream Consumer ────────────────────────────────────────────

async def redis_stream_consumer():
    import redis.asyncio as aioredis
    import dateutil.parser
    import time
    import traceback
    import pandas as pd
    import asyncio
    from config.config import NETWORK_INTERFACE

    r = aioredis.Redis(host="127.0.0.1", port=6379, db=0, decode_responses=True)

    # 1. Establish precise Redis Stream startup boundary
    last_id = "$"
    recent_flows = []

    try:
        # Fetch the very last ID to safely start without processing old data
        info = await r.xinfo_stream("cic:flows:stream")
        last_id = info.get("last-generated-id", "$")
    except Exception as e:
        print(f"[Live Inference] Failed to establish stream boundary: {e}")
        last_id = "$"

    # Wait for model to load
    while _model is None:
        await asyncio.sleep(1)

    print(f"[Live Inference] Starting Redis stream consumer... (last_id={last_id})", flush=True)


    # Reset in-memory live runtime state upon backend restart
    global _live_state
    _live_state = {
        "metadata": {
            "name": "Live Telemetry",
            "target_asset": f"{NETWORK_INTERFACE} (Live Capture)",
            "total_windows": 0,
            "detected_features": [],
            "rows_ingested": 0,
            "attack_windows_detected": 0,
            "telemetry_status": "WARMING_UP",
            "telemetry_lag_seconds": 0,
            "warmup_count": 0,
        },
        "windows": []
    }

    last_inferred_ts = None


    while True:
        try:
            # Block for up to 2 seconds waiting for new stream entries
            response = await r.xread({"cic:flows:stream": last_id}, count=1000, block=2000)
            new_entries = 0
            if response:
                for stream_key, entries in response:
                    for entry_id, fields in entries:
                        last_id = entry_id
                        flow = dict(fields)
                        recent_flows.append(flow)
                        new_entries += 1

            if new_entries > 0:
                print(f"[Live Inference] Received {new_entries} new flows. last_id={last_id}", flush=True)

            max_dt = pd.NaT
            for f in recent_flows:
                ts_str = f.get("timestamp", "")
                if ts_str:
                    try:
                        dt = pd.to_datetime(ts_str)
                        if pd.isna(max_dt) or dt > max_dt:
                            max_dt = dt
                    except Exception:
                        pass

            is_disconnected = False
            if pd.isna(max_dt):
                is_disconnected = True
                max_dt = pd.Timestamp.now()

            cutoff = max_dt - pd.Timedelta(seconds=400)

            valid_flows = []
            for f in recent_flows:
                ts_str = f.get("timestamp", "")
                if not ts_str:
                    continue
                try:
                    if pd.to_datetime(ts_str) > cutoff:
                        valid_flows.append(f)
                except Exception:
                    pass

            recent_flows = valid_flows

            # Stale logic
            now_dt = pd.Timestamp.now()
            lag_seconds = (now_dt - max_dt).total_seconds()
            if is_disconnected:
                telemetry_status = "DISCONNECTED"
            elif lag_seconds > 120:
                telemetry_status = "STALE"
            else:
                telemetry_status = "LIVE"

            scenario_entry = _live_state

            scenario_entry["metadata"]["telemetry_status"] = telemetry_status
            scenario_entry["metadata"]["telemetry_lag_seconds"] = int(lag_seconds)
            # Ensure metadata always reflects correct interface
            scenario_entry["metadata"]["target_asset"] = f"{NETWORK_INTERFACE} (Live Capture)"

            if len(recent_flows) > 0:
                df = pd.DataFrame(recent_flows)
                try:
                    states, timestamps, counts, missing_idx = _aggregate_windows(df)

                    # Enforce Rule 5: A network state is considered complete only after
                    # its corresponding 1-minute window has closed.
                    if len(timestamps) > 0:
                        max_window = timestamps[-1]
                        complete_idx = [i for i, ts in enumerate(timestamps) if ts < max_window]
                        if complete_idx:
                            states = states[complete_idx]
                            timestamps = [timestamps[i] for i in complete_idx]
                            counts = [counts[i] for i in complete_idx]
                        else:
                            states, timestamps, counts = [], [], []

                    num_complete = len(states)
                    scenario_entry["metadata"]["warmup_count"] = min(num_complete, _seq_len)

                    if num_complete > 0:
                        # Prevent duplicate inference
                        latest_window_ts = timestamps[-1]

                        if last_inferred_ts == latest_window_ts:
                            # We have already inferred this exact minute, skip!
                            pass
                        else:
                            # Wrap synchronous inference in thread
                            windows = await asyncio.to_thread(
                                _run_model_inference, states, timestamps, counts, missing_idx, True
                            )
                            if windows:
                                last_inferred_ts = latest_window_ts

                                # Merge historical live windows
                                existing_windows = scenario_entry.get("windows", [])
                                existing_dict = {w["timestamp"]: w for w in existing_windows}
                                for w in windows:
                                    existing_dict[w["timestamp"]] = w

                                merged_windows = list(existing_dict.values())
                                merged_windows.sort(key=lambda x: x["timestamp"])

                                # Bound backend prediction history to 60 windows
                                merged_windows = merged_windows[-60:]

                                # Reassign step_index sequentially
                                for idx, w in enumerate(merged_windows):
                                    w["step_index"] = idx

                                n_attack = sum(1 for w in merged_windows if w.get("current_risk") is not None and w["current_risk"] >= _best_threshold)
                                scenario_entry["metadata"]["total_windows"] = len(merged_windows)
                                scenario_entry["metadata"]["detected_features"] = list(df.columns)[:8]
                                scenario_entry["metadata"]["rows_ingested"] = len(recent_flows)
                                scenario_entry["metadata"]["attack_windows_detected"] = n_attack
                                scenario_entry["windows"] = merged_windows

                                print(f"[Live Inference] Inferred windows. Total history: {len(merged_windows)}", flush=True)
                    else:
                        if new_entries > 0:
                            print(f"[Live Inference] Warming up... (States: {num_complete}/{_seq_len})", flush=True)
                        if telemetry_status == "LIVE":
                            scenario_entry["metadata"]["telemetry_status"] = "WARMING_UP"

                        # Expose the completed warmup windows to the frontend without inference data
                        warmup_windows = []
                        for i in range(num_complete):
                            warmup_windows.append({
                                "step_index": i,
                                "timestamp": timestamps[i].strftime("%H:%M:%S"),
                                "flow_count": int(counts[i]),
                                "current_risk": None,
                                "current_stage": "Collecting Context...",
                                "trajectory": [],
                                "shap_features": [],
                                "is_warmup": True
                            })

                        scenario_entry["windows"] = warmup_windows
                        scenario_entry["metadata"]["total_windows"] = len(warmup_windows)
                        scenario_entry["metadata"]["detected_features"] = list(df.columns)[:8]
                        scenario_entry["metadata"]["rows_ingested"] = len(recent_flows)

                    # ADD TEMPORARY STRUCTURED DEBUG LOGGING HERE
                    last_event_id = last_id
                    current_bucket_str = max_dt.floor('1min').strftime('%H:%M:%S')
                    cw = scenario_entry.get("windows", [])
                    cw_latest = cw[-1] if len(cw) > 0 else None
                    print("\n[DEBUG LOG]")
                    print(f"  session_id: live")
                    print(f"  telemetry timestamp: {max_dt.strftime('%H:%M:%S')}")
                    print(f"  flow/event ID if available: {last_event_id}")
                    print(f"  current minute bucket: {current_bucket_str}")
                    print(f"  number of flows in that minute: {len([f for f in recent_flows if pd.to_datetime(f.get('timestamp')).floor('1min') == max_dt.floor('1min')])}")
                    print(f"  completed window number: {scenario_entry['metadata'].get('total_windows', 0)}")
                    print(f"  warmup_count: {scenario_entry['metadata'].get('warmup_count', 0)}")
                    print(f"  current rolling state flow_count: {cw_latest['flow_count'] if cw_latest else 0}")
                    print(f"  API values returned for flow throughput/live monitor: {cw_latest['flow_count'] if cw_latest else scenario_entry['metadata']['rows_ingested']} / {scenario_entry['metadata'].get('total_windows', 0)}")
                    print("[/DEBUG LOG]\n", flush=True)

                except Exception as e:
                    print(f"[Live Inference] Error in processing: {e}", flush=True)
                    import traceback
                    traceback.print_exc()

            # _live_state is updated in-place via scenario_entry. No disk save needed.

        except Exception as e:
            print(f"[Live Inference] Critical consumer error: {e}", flush=True)
            import traceback
            traceback.print_exc()
            await asyncio.sleep(2)


@app.on_event("startup")
async def startup_event():
    global _consumer_task
    _consumer_task = asyncio.create_task(redis_stream_consumer())

def _load_static_scenarios() -> Dict:
    if not SCENARIOS_PATH.exists():
        return {}
    with open(SCENARIOS_PATH, "r") as f:
        return json.load(f)

def load_data() -> Dict:
    data = _load_static_scenarios()
    data.update(_uploaded_scenarios)
    if _live_state:
        data["live"] = _live_state
    return data


@app.get("/api/scenarios")
def list_scenarios():
    data = load_data()
    return [
        {
            "id": k,
            "name": v["metadata"]["name"],
            "target": v["metadata"].get("target_asset", "Unknown"),
        }
        for k, v in data.items()
    ]


@app.get("/api/scenario/{scenario_id}/step/{step_idx}")
def get_scenario_step(scenario_id: str, step_idx: int):
    data = load_data()
    if scenario_id not in data:
        raise HTTPException(status_code=404, detail="Scenario not found")

    windows = data[scenario_id]["windows"]

    # Safely handle empty live sessions (warming up)
    if len(windows) == 0:
        return {
            "metadata": data[scenario_id]["metadata"],
            "current_window": None,
            "total_steps": 0,
        }

    if step_idx < 0 or step_idx >= len(windows):
        raise HTTPException(status_code=400, detail="Step out of range")

    return {
        "metadata": data[scenario_id]["metadata"],
        "current_window": windows[step_idx],
        "total_steps": len(windows),
    }


# ─── Real inference on an uploaded CICFlowMeter-style CSV ──────────────────


def _aggregate_windows(df: pd.DataFrame) -> tuple:
    """Reproduces the notebook's 1-minute aggregation (Cell 16) for a
    single in-memory dataframe. Returns (states, timestamps, counts,
    missing_feature_indices)."""

    n_feat = len(_feature_cols)
    norm_feat = [normalize_col(c) for c in _feature_cols]
    dst_port_idx = norm_feat.index("dstport") if "dstport" in norm_feat else None
    protocol_idx = norm_feat.index("protocol") if "protocol" in norm_feat else None

    # CICFlowMeter exports timing fields in seconds; the training data (and
    # this model) used microseconds — convert to match.
    time_keywords = ["iat", "active", "idle", "duration"]
    for c in df.columns:
        if any(kw in c.lower() for kw in time_keywords):
            df[c] = pd.to_numeric(df[c], errors="coerce") * 1_000_000.0

    model_col_map = {normalize_col(c): c for c in _feature_cols}
    model_col_map["timestamp"] = "Timestamp"
    rename_dict = {}
    for c in df.columns:
        norm_c = normalize_col(c)
        if norm_c == "cwrflagcount":
            norm_c = "cweflagcount"
        if norm_c in model_col_map:
            rename_dict[c] = model_col_map[norm_c]
    df = df.rename(columns=rename_dict)

    if "Timestamp" not in df.columns:
        raise HTTPException(
            status_code=400,
            detail="Uploaded CSV has no recognizable Timestamp column.",
        )

    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    df = df.dropna(subset=["Timestamp"])

    present = set(df.columns)
    missing_feature_indices = [
        i for i, col in enumerate(_feature_cols) if col not in present
    ]

    for col in _feature_cols:
        if col not in df.columns:
            df[col] = 0.0
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df[_feature_cols] = df[_feature_cols].replace([np.inf, -np.inf, np.nan], 0.0)

    df["_window"] = df["Timestamp"].dt.floor("1min")

    accumulators = {}
    for wkey, group in df.groupby("_window"):
        X = group[_feature_cols].values.astype(np.float64)
        n = len(X)
        acc = accumulators.setdefault(
            wkey,
            {
                "count": 0,
                "sum": np.zeros(n_feat),
                "sum_sq": np.zeros(n_feat),
                "min": np.full(n_feat, np.inf),
                "max": np.full(n_feat, -np.inf),
                "dst_ports": set(),
                "protocols": set(),
                "high_port_count": 0,
            },
        )
        acc["count"] += n
        acc["sum"] += X.sum(axis=0)
        acc["sum_sq"] += (X**2).sum(axis=0)
        acc["min"] = np.minimum(acc["min"], X.min(axis=0))
        acc["max"] = np.maximum(acc["max"], X.max(axis=0))
        if dst_port_idx is not None:
            acc["dst_ports"].update(X[:, dst_port_idx].astype(int).tolist())
            acc["high_port_count"] += int((X[:, dst_port_idx] > 1024).sum())
        if protocol_idx is not None:
            acc["protocols"].update(X[:, protocol_idx].astype(int).tolist())

    sorted_keys = sorted(accumulators.keys())
    states, timestamps, counts = [], [], []
    for wkey in sorted_keys:
        acc = accumulators[wkey]
        n = acc["count"]
        mean = acc["sum"] / n
        var = np.maximum((acc["sum_sq"] / n) - (mean**2), 0.0)
        states.append(
            np.concatenate(
                [
                    mean,
                    np.sqrt(var),
                    acc["min"],
                    acc["max"],
                    np.array(
                        [
                            np.log1p(n),
                            np.log1p(len(acc["dst_ports"])),
                            len(acc["protocols"]),
                            acc["high_port_count"] / n if n > 0 else 0.0,
                        ]
                    ),
                ]
            )
        )
        timestamps.append(wkey)
        counts.append(int(n))

    return np.array(states), timestamps, counts, missing_feature_indices


def _format_horizon(k: int) -> str:
    """Label a k-step-ahead forecast using the model's actual window size
    (e.g. '+3min' for WINDOW_SIZE='1min', k=3)."""
    try:
        delta = pd.Timedelta(_window_size) * k
    except Exception:
        return f"+{k} step(s)"
    total_seconds = delta.total_seconds()
    if total_seconds < 60:
        return f"+{int(total_seconds)}s"
    if total_seconds % 60 == 0:
        return f"+{int(total_seconds // 60)}min"
    return f"+{total_seconds / 60:.1f}min"


def _scale_sequence(seq: np.ndarray, missing_feature_indices: list) -> np.ndarray:
    seq_s = signed_log1p(seq.astype(np.float64))
    seq_sc = _scaler.transform(seq_s).astype(np.float32)
    # Crucial Fix: Zero out missing features AFTER scaling, so they don't get 
    # pushed to massive negative values by the scaler's mean subtraction.
    for idx in missing_feature_indices:
        seq_sc[:, idx] = 0.0
    seq_sc = np.clip(seq_sc, -3.0, 3.0)
    return seq_sc


def _gradient_attribution(X_t: torch.Tensor, top_k: int = 3):
    """Gradient-based attribution of the attack-risk head w.r.t. the input
    sequence — same method as notebook Cell 11, applied per-sequence rather
    than averaged over a sample, since this is a live single-window
    explanation. Returns (top features list, detached model outputs)."""
    X_t = X_t.clone().detach().requires_grad_(True)
    with torch.backends.cudnn.flags(enabled=False):
        pred_state, atk_log, mitre_log, (h_n, c_n) = _model(X_t)
        atk_log.squeeze().backward()

    grad_array = X_t.grad.detach().cpu().numpy().squeeze(0)
    input_array = X_t.detach().cpu().numpy().squeeze(0)
    grads = np.abs(grad_array * input_array)  # (seq_len, state_dim)
    per_dim = grads.mean(axis=0)  # importance per state dimension
    max_val = per_dim.max() if per_dim.max() > 0 else 1.0
    top_idx = np.argsort(per_dim)[::-1][:top_k]
    shap_features = [
        {
            "feature": _agg_names[idx] if idx < len(_agg_names) else f"dim_{idx}",
            "importance": round(float(per_dim[idx] / max_val), 4),
        }
        for idx in top_idx
    ]
    hc = (h_n.detach(), c_n.detach())
    return shap_features, pred_state.detach(), atk_log.detach(), mitre_log.detach(), hc


def _k_step_trajectory(pred_state, atk_log, mitre_log, h_c) -> List[Dict]:
    """Autoregressive K-step forecast, mirroring notebook Cell 10's
    k_step_forecast — chains the LSTM hidden state forward using the model's
    own predicted state as the next input."""
    trajectory = []
    h_n, c_n = h_c

    atk_prob = torch.sigmoid(atk_log).item()
    mt_cls = int(mitre_log.argmax(dim=1).item())
    if atk_prob < _best_threshold:
        mt_cls = 0

    trajectory.append(
        {
            "step_ahead": _format_horizon(1),
            "prob": round(float(atk_prob), 4),
            "stage": MITRE_NAMES.get(mt_cls, "Unknown"),
        }
    )

    with torch.no_grad():
        for step in range(1, _k_steps):
            next_input = pred_state.unsqueeze(1)
            pred_state, atk_log, mitre_log, (h_n, c_n) = _model(next_input, (h_n, c_n))
            atk_prob = torch.sigmoid(atk_log).item()
            mt_cls = int(mitre_log.argmax(dim=1).item())
            if atk_prob < _best_threshold:
                mt_cls = 0

            trajectory.append(
                {
                    "step_ahead": _format_horizon(step + 1),
                    "prob": round(float(atk_prob), 4),
                    "stage": MITRE_NAMES.get(mt_cls, "Unknown"),
                }
            )
    return trajectory


def _run_model_inference(
    states: np.ndarray, timestamps: list, counts: list, missing_feature_indices: list,
    is_live: bool = False
) -> List[Dict]:
    windows_out = []

    for i in range(len(states)):
        # To get the prediction for window i, we use the sequence up to i.
        start_idx = max(0, i - _seq_len + 1)
        seq = states[start_idx : i + 1]
        
        has_enough_history = (len(seq) == _seq_len)
        
        if len(seq) < _seq_len:
            pad_size = _seq_len - len(seq)
            pad_states = np.repeat(seq[0:1], pad_size, axis=0)
            seq = np.vstack([pad_states, seq])
            
        seq_sc = _scale_sequence(seq, missing_feature_indices)
        X_t = torch.tensor(seq_sc).unsqueeze(0).to(device)

        # Single forward+backward pass gives us the attack/mitre/state
        # predictions, the hidden state (for trajectory chaining), and the
        # gradient-based feature attribution all together.
        shap_features, pred_state, atk_log, mitre_log, hc = _gradient_attribution(X_t)
        attack_head_prob = torch.sigmoid(atk_log).item()
        mitre_cls = int(mitre_log.argmax(dim=1).item())

        current_risk = attack_head_prob
        anomaly_score = None
        mse_val = None
        z_val = None

        has_true_future = (i + 1 < len(states))

        if _benign_mse_baseline is not None and has_true_future:
            true_future = states[i + 1].astype(np.float64)
            true_future_sc = _scaler.transform(
                signed_log1p(true_future).reshape(1, -1)
            )[0]
            true_future_sc = np.clip(true_future_sc, -3.0, 3.0)
            mse_val = float(
                np.mean((pred_state.cpu().numpy().flatten() - true_future_sc) ** 2)
            )
            z_val = (mse_val - _benign_mse_baseline["mean"]) / (
                _benign_mse_baseline["std"] + 1e-8
            )
            anomaly_score = 1 / (1 + np.exp(-(z_val - 3.0)))
            # Removed current_risk = max(attack_head_prob, anomaly_score)

        if current_risk < _best_threshold:
            mitre_cls = 0

        # Only generate a genuine k-step trajectory forecast if we have the required 5-window context
        if has_enough_history:
            trajectory = _k_step_trajectory(pred_state, atk_log, mitre_log, hc)
        else:
            trajectory = []

        ts_str = timestamps[i].strftime("%H:%M:%S")
        fl_count = counts[i]

        # ─── MITRE RAG enrichment ────────────────────────────────────
        rag_result = None
        if _rag_service is not None:
            try:
                rag_result = _rag_service.query(
                    predicted_stage=MITRE_NAMES.get(mitre_cls, "Unknown"),
                    attack_probability=float(current_risk),
                    important_features=shap_features,
                    flow_count=fl_count,
                )
            except Exception as e:
                print(f"[RAG] Query error: {e}")
                rag_result = None

        windows_out.append(
            {
                "step_index": len(windows_out),
                "timestamp": ts_str,
                "flow_count": fl_count,
                "current_risk": round(float(current_risk), 4),
                "anomaly_score": round(float(anomaly_score), 4) if anomaly_score is not None else None,
                "current_stage": MITRE_NAMES.get(mitre_cls, "Unknown"),
                "trajectory": trajectory,
                "shap_features": shap_features,
                "rag": rag_result,
                # TEMPORARY diagnostics — remove once current_risk is verified.
                "_debug": {
                    "attack_head_prob": round(float(attack_head_prob), 4),
                    "raw_mse": round(mse_val, 6) if mse_val is not None else None,
                    "z": round(float(z_val), 4) if z_val is not None else None,
                    "anomaly_score": (
                        round(float(anomaly_score), 4)
                        if anomaly_score is not None
                        else None
                    ),
                    "current_risk": round(float(current_risk), 4),
                    "benign_mse_baseline": _benign_mse_baseline,
                },
            }
        )

    return windows_out


@app.post("/api/upload-csv")
async def upload_csv(file: UploadFile = File(...)):
    if _model is None:
        raise HTTPException(
            status_code=503,
            detail="No trained model checkpoint loaded on the server "
            "(lstm_world_model.pth missing).",
        )

    content = await file.read()
    decoded = content.decode("utf-8", errors="ignore")
    try:
        df = pd.read_csv(io.StringIO(decoded), low_memory=False)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not parse CSV: {exc}")

    if len(df) == 0:
        raise HTTPException(status_code=400, detail="Uploaded CSV has no rows.")

    states, timestamps, counts, missing_idx = _aggregate_windows(df)

    if len(states) < _seq_len + 1:
        raise HTTPException(
            status_code=422,
            detail=f"Need at least {_seq_len + 1} one-minute traffic windows "
            f"to run inference, only got {len(states)}. Upload a "
            f"longer capture.",
        )

    windows = _run_model_inference(states, timestamps, counts, missing_idx)

    scenario_id = f"upload_{uuid.uuid4().hex[:10]}"
    n_attack = sum(1 for w in windows if w["current_risk"] >= _best_threshold)

    # Flat detection log — mirrors the notebook's test_csv_file() console
    # output ("Time | P(Attack) | Is Attack" + anomalous-window summary) so
    # the frontend can render the same log/verdict view, not just the
    # richer trajectory/SHAP view used for the story-mode scenarios.
    detection_log = [
        {
            "timestamp": w["timestamp"],
            "attack_prob": w["current_risk"],
            "is_attack": w["current_risk"] >= _best_threshold,
        }
        for w in windows
    ]
    detection_summary = {
        "model_threshold": _best_threshold,
        "total_windows_evaluated": len(windows),
        "anomalous_windows_detected": n_attack,
        "verdict": (
            "ATTACK DETECTED - malicious traffic flagged in this capture."
            if n_attack > 0
            else "No attack detected in this capture."
        ),
    }

    scenario_entry = {
        "metadata": {
            "name": f"Ingested Dataset: {file.filename}",
            "target_asset": f"Uploaded capture ({file.filename})",
            "total_windows": len(windows),
            "detected_features": list(df.columns)[:8],
            "rows_ingested": len(df),
            "attack_windows_detected": n_attack,
        },
        "windows": windows,
    }

    # Persist so the frontend can page through it via the normal
    # /api/scenario/{id}/step/{idx} endpoint, same as the static scenarios.
    global _uploaded_scenarios
    _uploaded_scenarios[scenario_id] = scenario_entry

    return {
        "status": "success",
        "scenario_id": scenario_id,
        "filename": file.filename,
        "detection_log": detection_log,
        "detection_summary": detection_summary,
        **scenario_entry,
    }


@app.get("/api/rag/status")
def rag_status():
    """Diagnostic endpoint for the MITRE ATT&CK RAG service."""
    if _rag_service is None:
        return {"ready": False, "index_size": 0, "embedding_model_loaded": False}
    return _rag_service.status()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
