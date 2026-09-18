"""
LSTM World Model architecture + preprocessing helpers.

This mirrors the exact code from the training notebook (Cells 2 and 7) so
that inference in the API produces results consistent with training.
Any drift between this file and the notebook will silently corrupt
predictions, so if you change the notebook's clean_chunk / signed_log1p /
LSTMWorldModel, mirror the change here too.
"""

import re
import numpy as np
import torch
import torch.nn as nn

# ─── MITRE ATT&CK Mapping (must match notebook Cell 1) ─────────────────────
MITRE_NAMES = {
    0: "Benign",
    1: "Credential Access (TA0006)",
    2: "DoS Impact (TA0040)",
    3: "DDoS Impact (TA0040)",
    4: "Web Exploit (TA0001)",
    5: "Lateral Movement (TA0008)",
    6: "C2 / Botnet (TA0011)",
}
NUM_MITRE = len(MITRE_NAMES)


def signed_log1p(x: np.ndarray) -> np.ndarray:
    """Sign-preserving log1p: sign(x) * log1p(|x|)."""
    return np.sign(x) * np.log1p(np.abs(x))


def normalize_col(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


class TGAT_WorldModel(nn.Module):
    """TGAT World Model architecture (Temporal Graph Attention Network).
    Identical to notebook Cell 7 — required to load the saved state_dict.
    """

    def __init__(
        self,
        state_dim: int,
        hidden_size: int = 256,
        num_layers: int = 2,
        dropout: float = 0.3,
        num_mitre: int = NUM_MITRE,
    ):
        super().__init__()
        self.state_dim = state_dim
        self.hidden_size = hidden_size
        self.num_layers = num_layers

        # 1. Temporal Backbone (Extracts raw node features)
        self.lstm = nn.LSTM(
            input_size=state_dim,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )
        
        # 2. Graph Attention Network (GAT) Layer
        # Projects node features into Graph space
        self.W_query = nn.Linear(hidden_size, hidden_size)
        self.W_key = nn.Linear(hidden_size, hidden_size)
        self.W_value = nn.Linear(hidden_size, hidden_size)
        
        self.ln = nn.LayerNorm(hidden_size)
        self.backbone_drop = nn.Dropout(dropout)

        # 3. Prediction Heads
        self.state_head = nn.Sequential(
            nn.Linear(hidden_size, hidden_size),
            nn.ReLU(),
            nn.Dropout(dropout * 0.5),
            nn.Linear(hidden_size, state_dim),
        )

        self.attack_head = nn.Sequential(
            nn.Linear(hidden_size, 64),
            nn.ReLU(),
            nn.Dropout(dropout * 0.5),
            nn.Linear(64, 1),
        )

        self.mitre_head = nn.Sequential(
            nn.Linear(hidden_size, 64),
            nn.ReLU(),
            nn.Dropout(dropout * 0.5),
            nn.Linear(64, num_mitre),
        )

    def forward(self, x, hc=None):
        import math
        if hc is not None:
            hc = (hc[0].transpose(0, 1).contiguous(), hc[1].transpose(0, 1).contiguous())

        # --- STEP 1: NODE FEATURE EXTRACTION ---
        node_features, (h_n, c_n) = self.lstm(x, hc)
        
        # --- STEP 2: DYNAMIC GRAPH CONSTRUCTION (Adjacency Matrix) ---
        Q = self.W_query(node_features)
        K = self.W_key(node_features)
        V = self.W_value(node_features)
        
        adj_matrix = torch.bmm(Q, K.transpose(1, 2)) / math.sqrt(self.hidden_size)
        adj_matrix = torch.softmax(adj_matrix, dim=-1) 
        
        # --- STEP 3: GRAPH CONVOLUTION (Message Passing) ---
        gcn_out = torch.bmm(adj_matrix, V) 
        
        # --- STEP 4: GRAPH READOUT ---
        graph_embedding = torch.mean(gcn_out, dim=1) 
        
        h_fused = self.ln(graph_embedding)
        h_fused = self.backbone_drop(h_fused)

        # --- STEP 5: PREDICTIONS ---
        pred_state = self.state_head(h_fused)
        attack_logit = self.attack_head(h_fused)
        mitre_logit = self.mitre_head(h_fused)

        h_n = h_n.transpose(0, 1)
        c_n = c_n.transpose(0, 1)

        return pred_state, attack_logit, mitre_logit, (h_n, c_n)


def build_agg_names(feature_cols):
    """State-vector dimension names: mean_<f>, std_<f>, min_<f>, max_<f> for
    each feature, then the 4 meta dims. Must match notebook Cell 11 ordering."""
    names = []
    for agg in ["mean", "std", "min", "max"]:
        for f in feature_cols:
            names.append(f"{agg}_{f}")
    names.extend(
        [
            "meta_log_flow_count",
            "meta_log_unique_ports",
            "meta_unique_protocols",
            "meta_high_port_ratio",
        ]
    )
    return names


class ManualScaler:
    """Re-applies a fitted sklearn StandardScaler from its saved mean_/scale_
    arrays, without needing sklearn or the original fitted object at
    inference time."""

    def __init__(self, mean: np.ndarray, scale: np.ndarray):
        self.mean_ = np.asarray(mean, dtype=np.float64)
        self.scale_ = np.asarray(scale, dtype=np.float64)

    def transform(self, x: np.ndarray) -> np.ndarray:
        return (x - self.mean_) / self.scale_
