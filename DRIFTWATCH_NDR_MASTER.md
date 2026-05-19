# DRIFTWATCH NDR — Master Technical Reference
## Adversarial Drift Detection Engine
### Project: BSc Computer Engineering Honors — University of Zimbabwe

---

## 1. PROJECT OVERVIEW
- **What DRIFTWATCH NDR is:** A Network Detection and Response (NDR) platform designed to detect "Adversarial Drift" — the subtle, slow-acting deviations in network behaviour indicative of advanced persistent threats (APTs) or internal compromise.
- **The Boiling Frog Problem it solves:** Traditional IDS/IPS systems trigger on high-velocity attacks (spikes). DRIFTWATCH focuses on "slow and low" indicators that accumulate over time, preventing attackers from slowly normalising malicious behaviour into the network baseline.
- **Dissertation Mapping:** 
  - *Chapter 1 & 2:* Problem statement and Literature review on anomaly detection.
  - *Chapter 3:* Implementation of the HDT (Hybrid Drift Tracking) architecture.
  - *Chapter 4:* Prototype development and feature engineering.
  - *Chapter 5:* Evaluation against benchmark datasets (CIC-IDS2017/2018).
- **The 4-layer HDT detection architecture:**
  - **Layer 1: GMM Adaptive Behavioural Baseline:** Models per-node session patterns using Gaussian Mixture Models.
  - **Layer 2: KDE Global Density Analysis:** Measures global network density to identify outliers in the aggregate traffic space.
  - **Layer 3: LOWESS Temporal Trend Monitoring:** Uses locally weighted scatterplot smoothing to detect sustained directional shifts in metrics like inter-arrival times or packet size distribution.
  - **Layer 4: Decision Fusion Engine:** A weighted voting system that synthesises scores from Layers 1-3 to produce a high-confidence alert.

---

## 2. CURRENT IMPLEMENTATION STATUS

| Feature | Status | Where Built | Notes |
|---------|--------|-------------|-------|
| Live Metrics Dashboard | ✅ COMPLETE | `server.ts` + `App.tsx` | CPU, RAM, Network I/O via `systeminformation` |
| Process & Connection Tracking | ✅ COMPLETE | `server.ts` + `App.tsx` | Real-time monitoring of host processes and network sockets |
| Discovery / Devices Tab | ✅ COMPLETE | `sensor.py` + `App.tsx` | Device profiling and sentinel mode integration |
| Traffic Matrix & Visualizer | ✅ COMPLETE | `sensor.py` + `App.tsx` | UI logic for matrix and activity sparklines implemented |
| Alerts & MITRE ATT&CK Mapping | ✅ COMPLETE | `sensor.py` + `App.tsx` | Full heatmap matrix, coverage card, and technique detail side-panel integrated. |
| Security Actions (Block/Isolate) | ✅ COMPLETE | `sensor.py` + `App.tsx` | Full state management, validation modal, and audit trail UI implemented |
| Kill Chain Visualizer | ✅ COMPLETE | `sensor.py` + `App.tsx` | Horizonatal 7-stage attack pipeline & network-wide matrix |
| Behavioural Baseline Viewer | ✅ COMPLETE | `App.tsx` + `server.ts` | Bayesian baseline profiles, variance band charts, and ADS drift sentinels |
| Reports Generator | ✅ COMPLETE | `App.tsx` | Automated multi-format HTML/PDF intelligence reports with full forensic context |
| Sensor Health & System Monitor | ✅ COMPLETE | `App.tsx` + `server.ts` | Detailed sub-layer telemetry, FP tracker, backend capability hub, and ADS sentinel status |
| Auto-Action Rules Engine | ✅ INTEGRATED | `sensor.py` + `App.tsx` | Policy configuration UI complete; logic integrated with sensor state |
| Forensic Investigation Hub | 🔧 NEEDS BACKEND | `App.tsx` | Deep packet inspection mock UI; needs real flow capture feed |
| WebSocket Live Feed | ✅ COMPLETE | `sensor.py` + `server.ts` | Bi-directional updates for metrics and connections |
| VM & Hypervisor Detection | ✅ COMPLETE | `sensor.py` | Backend detects environment segments and VM markers |

---

## 3. ARCHITECTURE — WHAT NEEDS TO BE BUILT FOR PRODUCTION

### 3.1 Backend Stack (not yet built)
Exact specification:
- **Language:** Python 3.11
- **Framework:** Flask 3.0 (Dissertation requirement)
- **ML Libraries:** scikit-learn 1.4, statsmodels 0.14, numpy, pandas
- **Packet Capture:** Scapy 2.5, PyShark 0.6
- **Database:** PostgreSQL 16 (Alerts, audit trail, device profiles)
- **Cache/Buffer:** Redis 7.2 (Time-series packet buffer)
- **API:** REST + WebSocket (Flask-SocketIO)
- **Auth:** JWT tokens for analyst login

### 3.2 Frontend Stack (built in AI Studio)
- React 18 + TypeScript
- Recharts for all charts (Line, Area, Bar, Scatter)
- Tailwind CSS v4 (Modern JIT styling)
- WebSocket client for live data streaming
- Framer Motion for high-fidelity route and tab transitions

### 3.3 Infrastructure for Production
- Docker container per service:
  - `driftwatch-backend`: Flask + ML engine
  - `driftwatch-frontend`: React, served via nginx
  - `driftwatch-db`: PostgreSQL
  - `driftwatch-cache`: Redis
  - `driftwatch-capture`: Scapy packet capture (Requires `NET_ADMIN`)
- `docker-compose.yml` orchestration
- Environment variables for DB/Redis secrets
- **Network configuration:** bridge mode for general containers, `host` mode for capture container to allow indiscriminate packet sniffing.
- **Required Linux capabilities:** `NET_ADMIN`, `NET_RAW` for promiscuous mode operation.

### 3.4 Docker Compose specification

```yaml
version: '3.8'
services:
  backend:
    build: ./backend
    ports: ["8001:8001"]
    environment:
      - DB_URL=postgresql://analyst:secret@db:5432/driftwatch
      - REDIS_URL=redis://cache:6379
    cap_add:
      - NET_ADMIN
      - NET_RAW
    network_mode: host  # required for packet capture on physical interfaces
    
  frontend:
    build: ./frontend
    ports: ["3000:80"]
    depends_on: [backend]
    
  db:
    image: postgres:16
    volumes: [postgres_data:/var/lib/postgresql/data]
    environment:
      - POSTGRES_PASSWORD=secret
    
  cache:
    image: redis:7.2-alpine

volumes:
  postgres_data:
```

---

## 4. EVERY API ENDPOINT NEEDED

### GET /api/devices
Returns all discovered network devices.
**Response:** Array of Device objects.
**Called by:** `DevicesTab`, `NetworkMap`, TopBar threat counter.
**Status:** 🔧 NEEDS BUILDING — frontend expects this exact shape:
```json
{
  "devices": [
    {
      "id": "uuid",
      "hostname": "string",
      "ip": "string", 
      "mac": "string",
      "first_seen": "ISO timestamp",
      "last_seen": "ISO timestamp",
      "bytes_sent": number,
      "bytes_recv": number,
      "protocols": ["TCP", "UDP"],
      "threat_score": number,
      "beacon_score": number,
      "drift_score": number,
      "recon_score": number,
      "exfil_score": number,
      "baseline_status": "LEARNING|ESTABLISHED|DRIFTING",
      "is_watched": boolean,
      "is_armed": boolean,
      "is_blocked": boolean,
      "vm_info": null | { "hypervisor": "string", "vm_name": "string" }
    }
  ]
}
```

### Authentication & Sessions
- `POST /api/auth/login`: Issue JWT.
- `GET /api/auth/me`: Validate session.

### Device Analysis
- `GET /api/devices/{id}/connections`: Recent flows for specific device.
- `GET /api/devices/{id}/domains`: DNS history and domain reputation hits.
- `GET /api/devices/{id}/beacon`: Beaconing frequency analysis data (for `BeaconChart`).
- `GET /api/devices/{id}/drift`: Drift gradient history (for `DriftChart`).

### Flow & Alerts
- `GET /api/flows`: Network-wide flow records (NetFlow-style).
- `GET /api/alerts`: All alerts with MITRE context.
- `POST /api/alerts/{id}/acknowledge`: Mark alert as read/reviewed.

### Security Actions
- `GET /api/actions`: List active/pending/deleted actions.
- `POST /api/actions/create`: Initiate manual action.
- `PUT /api/actions/{id}/confirm`: Confirm a pending auto-action.
- `PUT /api/actions/{id}/extend`: Extend TTL of an active block.
- `DELETE /api/actions/{id}/revoke`: Manual revocation of a block.

### System & Policy
- `GET /api/rules`: Active auto-detection policy rules.
- `POST /api/rules`: Create new detection rule.
- `GET /api/capabilities`: Check for `NET_ADMIN` / Promiscuous mode support.
- `GET /api/health`: Backend/DB/Redis health status.
- `WebSocket /ws/live`: Real-time telemetry stream.

---

## 5. FEATURE IMPLEMENTATION GUIDE

### 5.1 Kill Chain Visualizer
**Browser:** ✅ UI complete. Staggers nodes based on detected alert severity.
**Backend needs:**
  - **Function:** `classify_kill_chain_stage(device_id)` → stage string.
  - **Logic:** Maps alert types (e.g., Recon, C2, Exfil) to MITRE kill chain stages.
  - **Dissertation:** Chapter 3.3.6 Decision Fusion Engine.

### 5.2 MITRE ATT&CK Mapping
**Browser:** ✅ UI complete. Technique IDs mapped to descriptions.
**Backend needs:**
  - Mapping table: `alert_type` → MITRE ID + Technique Name.
  - **Function:** `get_mitre_technique(alert_type)` → `{id, name, tactic}`.
  - **Dissertation:** Chapter 5 (Evaluation against threat frameworks).

### 5.3 Automated Response (Actions)
**Browser:** ✅ Confirmation modal and "Undo" state logic implemented.
**Backend needs:**
  - Enforcement via `iptables` or `nftables` commands (Requires shell execution).
  - Cron job/Scheduler for TTL-based expiry of blocks.

---

## 6. ML ALGORITHM IMPLEMENTATION GUIDE

### 6.1 GMM Baseline (Layer 1)
**File:** `backend/detection/gmm_baseline.py`
```python
from sklearn.mixture import GaussianMixture
import numpy as np

class AdaptiveGMMBaseline:
    def __init__(self, n_components=None, decay_factor=0.05):
        self.decay_factor = decay_factor  # λ for online adaptation
        self.model = None
        
    def fit(self, feature_matrix: np.ndarray):
        # BIC/AIC to find optimal clusters (e.g., distinct work-hours activity)
        pass
        
    def score(self, feature_vector: np.ndarray) -> float:
        # Returns negative log-likelihood
        pass
```

### 6.2 KDE Global Density (Layer 2)  
**File:** `backend/detection/kde_density.py`
```python
from sklearn.neighbors import KernelDensity

class GlobalKDEDensity:
    def fit(self, observations: np.ndarray):
        # Multivariate Gaussian kernel density estimation
        pass
```

### 6.3 LOWESS Trend Monitor (Layer 3)
**File:** `backend/detection/lowess_trend.py`
```python
from statsmodels.nonparametric.smoothers_lowess import lowess

class LOWESSTrendMonitor:
    def compute_gradient(self, time_series: np.ndarray) -> float:
        # Smooth window and return slope at T-0
        pass
```

### 6.4 Decision Fusion Engine (Layer 4)
**File:** `backend/detection/fusion_engine.py`
```python
class DecisionFusionEngine:
    W_GMM = 0.35
    W_KDE = 0.30  
    W_LOWESS = 0.35
    
    def fuse(self, scores: list) -> float:
        # Weighted sum of L1-L3 scores
        pass
```

---

## 7. FEATURE ENGINEERING SPECIFICATION

Extract from dissertation Table 3.1:
- **Connection Dynamics:** `unique_dst_ips_per_hour`, `connection_success_ratio`.
- **Protocol Metrics:** `dns_query_frequency`, `avg_payload_size`.
- **Temporal Stats:** `inter_arrival_time_cv`, `burst_coefficient`.
- **Drift Indicators:** `window_byte_ratio_7d_vs_24h`.

---

## 8. DATABASE SCHEMA

Refer to the SQL definitions in the project instructions for initializing the PostgreSQL instance, covering `devices`, `alerts`, `actions`, `baseline_snapshots`, and `cases`.

---

## 9. DEPLOYMENT CHECKLIST

1. **Local VM:** Clone AI Studio output → Set up Python Venv → Install requirements → Build Flask routes → Connect real Scapy capture → Run `sudo`.
2. **Dockerization:** Containerize Frontend (Nginx/React) and Backend (Flask).
3. **Network:** Enable `NET_ADMIN` in Docker.
4. **Cloud:** Mirror traffic to instance VPC interface.

---

## 10. DISSERTATION CHAPTER MAPPING

| Feature | Chapter | Dissertation Section |
|---------|---------|-----------------------|
| Packet Capture Subsystem | Ch3 | 3.3.1 |
| HDT Feature Extraction | Ch3 | 3.3.2 |
| GMM Implementation | Ch3 | 3.3.3 |
| KDE Implementation | Ch3 | 3.3.4 |
| LOWESS Implementation | Ch3 | 3.3.5 |
| Fusion Logic | Ch3 | 3.3.6 |
| Kill Chain Evaluation | Ch5 | Evaluation Results |

---
**Last Updated:** 2026-05-18
**System:** DRIFTWATCH NDR v1.0
