# Network Attack Forecast

A predictive cyber-defense "World Model" that captures raw network traffic, buffers it via Redis, and uses a pre-trained LSTM (Long Short-Term Memory) model to forecast future attacks. 

## Current Architecture

The project consists of a telemetry pipeline (Zeek/CICFlowMeter), a Redis rolling buffer, a backend API (FastAPI) which evaluates the LSTM world model, and a React Dashboard.

```text
Network Traffic (Live / PCAP)
      ↓
CICFlowMeter (Feature extraction) / Zeek (Event logging)
      ↓
Redis (5-minute rolling buffer) / CSV (Archive)
      ↓
LSTM World Model (Pre-trained on CSE-CIC-IDS2018)
      ↓
FastAPI Backend (Forecast, Anomaly detection)
      ↓
React Dashboard (Vite + Recharts)
```

## Repository Structure

- `backend/`: FastAPI application, LSTM inference logic, and the pre-trained model.
- `frontend/`: React + Vite dashboard application for visualizing forecasts and alerts.
- `mitre_rag/`: MITRE ATT&CK RAG subsystem (STIX ingestion, FAISS vector store, evidence-grounded retriever).
- `src/`: Python source code for the telemetry collectors and normalizers.
- `scripts/`: Shell scripts for managing live packet capture (CICFlowMeter/Zeek).
- `config/`: Application configuration loading.
- `tests/`: Pytest suite covering the telemetry pipeline and Redis integration.
- `data/`: Local storage for generated CSV flows and Zeek logs (not version controlled).
- `logs/`: Application logs (not version controlled).

## Technology Stack

- **Data Pipeline**: Zeek, CICFlowMeter (via Scapy), Redis
- **Model**: PyTorch (CPU-only), Scikit-Learn
- **RAG & Retrieval**: Sentence-Transformers (`all-MiniLM-L6-v2`), FAISS-CPU, STIX 2.1
- **Backend API**: FastAPI, Uvicorn, Pandas, NumPy
- **Frontend**: React 19, Vite, Tailwind CSS, Recharts, Lucide Icons

## Prerequisites

- Python 3.x
- Node.js & npm
- Redis Server (`sudo apt-get install redis-server`)
- Zeek (`sudo apt-get install zeek`)
- Linux / WSL (Required for native raw socket packet capture)

## Environment Setup

### 1. Redis
Ensure Redis is running:
```bash
sudo systemctl start redis-server
```
Verify connectivity:
```bash
redis-cli ping
# Expected output: PONG
```

### 2. Python Environment (Backend & Telemetry)
Create a virtual environment and install dependencies:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
> **Note:** The `requirements.txt` specifically requests the CPU-only version of PyTorch (`torch 2.14.0+cpu`). CUDA is intentionally unsupported in this environment.

### 3. MITRE ATT&CK RAG Index Building
Build the persistent FAISS index from official MITRE Enterprise STIX data:
```bash
python -m mitre_rag.scripts.build_index
```
*This downloads the latest STIX bundle, extracts 800+ active techniques, computes 384-dimensional embeddings, and saves the vector store to `mitre_rag/vectorstore/mitre_techniques.index`.*

### 4. Frontend Dashboard
Install Node dependencies:
```bash
cd frontend
npm install
```

### 5. Configuration
Copy the example environment file:
```bash
cp .env.example .env
```
Ensure `NETWORK_INTERFACE` matches your active interface (e.g., `eth0` or `lo`).

## Running the Application

### 1. Telemetry Capture
The telemetry pipeline captures traffic and buffers it in Redis. Live capture requires `sudo` privileges or `CAP_NET_RAW` on the python binary.
```bash
# Start Zeek
./scripts/start_zeek.sh

# Start CICFlowMeter
sudo ./scripts/start_cic.sh
```
*Flows are written to `data/cic/flows/` and pushed to the Redis key `cic:flows` with a 300-second retention.*

### 2. Backend API
The backend loads `lstm_world_model.pth` and initializes the MITRE RAG service automatically on startup.
```bash
cd backend
source ../.venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
*API available at http://localhost:8000 (RAG status endpoint: `GET /api/rag/status`)*

### 3. Frontend Dashboard
```bash
cd frontend
npm run dev
```
*Dashboard available at http://localhost:5173 (Navigate to the **MITRE** tab for live RAG technique mappings)*

## Testing

Run the full pytest suite (including RAG unit, evaluation, and e2e integration tests):
```bash
python -m pytest mitre_rag/tests/ -v
```

To test the live Redis buffer:
```bash
./scripts/test_redis_buffer.sh
```

## Current Limitations

While the core architecture and MITRE ATT&CK RAG are established, the following features are **NOT** yet integrated into this repository:
- Live streaming of real-time Redis flows directly into the LSTM model.
- CALDERA Sandcat / n8n workflow integration.
- Production-grade WSGI deployment.
