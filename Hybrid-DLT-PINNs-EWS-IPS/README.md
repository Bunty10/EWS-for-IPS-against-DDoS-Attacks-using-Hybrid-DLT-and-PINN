# Hybrid DLT-PINNs EWS IPS

An **Early Warning System / Intrusion Prevention System (EWS/IPS)** that detects
Distributed Denial-of-Service (DDoS) attacks by scoring network traffic
**second by second** against a learned benign baseline, raising graded
`LOW` / `MED` / `HIGH` warnings before an attack fully develops.

**Detection engine.** A small neural network (a *DLT-NN*, see
`backend/model.py`) is trained **only on benign traffic** to reconstruct the
expected per-second feature vector. Each second is scored by the **Euclidean
distance** between its normalised features and that reconstruction — the larger
the distance, the more anomalous the second. Distances that cross the learned
benign-baseline thresholds (`mean + k·std`) become early warnings. A pre-trained
network and its thresholds ship per workflow, so the app runs out of the box.

The project ships as two parts:

- A **Flask backend** that runs the engine over uploaded CSVs or live-captured
  packets, persists graded alerts to SQLite, sends email notifications, and
  exposes everything as a polled JSON API on port `5001`.
- A **React + Vite frontend** — a full security dashboard that visualises live
  traffic, alerts, statistics, network topology and detection performance in
  real time.

The same backend can also be packaged into a **standalone Windows desktop app +
installer** (see [`BUILD.md`](BUILD.md)).

> **Per-workflow baselines.** Each workflow uses its own benign baseline and
> never the other's: **Live capture → VNRVJIET**, **CSV upload → CICDDoS2019**.
> Pre-trained artifacts live under `backend/models/hybrid/`.

---

## Architecture

```
                 ┌─────────────────────────────────────────────┐
                 │                Frontend (Vite)               │
                 │   React SPA · Recharts · AG Grid · Tailwind  │
                 │                                              │
                 │   usePolling / useDltAnalysis                │
                 │      └── poll /status, /dashboard, /live ──┐ │
                 └───────────────┬─────────────────────────────┼┘
                                 │ /api/dlt/*                   │
                     Vite dev proxy (or same-origin in prod/desktop)
                                 │
                 ┌───────────────▼─────────────────────────────┐
                 │          Backend — dlt_app.py (:5001)        │
                 │                                              │
                 │  dlt/routes.py      Flask blueprint /api/dlt │
                 │  dlt/service.py     job + live session state │
                 │  dlt/pipeline.py    engine facade            │
                 │  dlt/approach_hybrid.py   DLT-NN scoring     │
                 │  dlt/preprocessing.py     shared feature pipe│
                 │  dlt/live_capture.py      scapy packet sniff │
                 │  dlt/db.py          SQLite alert persistence │
                 │  dlt/notifier.py    HIGH-alert email (SMTP)  │
                 │  dlt/reports.py     CSV / Excel / PDF export │
                 │  model.py           the DLT-NN definition    │
                 │  models/hybrid/     pre-trained artifacts    │
                 │  dlt_results/       alerts.db · results · csv│
                 └──────────────────────────────────────────────┘
```

**How the pieces fit together**

1. Live capture starts automatically when the desktop app launches (in dev you
   can also start it from the Live page), or the user uploads a CSV on the Upload
   page.
2. The backend runs the pipeline: it aggregates flows into 1-second bins,
   normalises each second, reconstructs the expected benign vector with the
   trained network, and scores each second by the Euclidean distance between the
   two. Scores above the trained thresholds become `LOW` / `MED` / `HIGH` alerts.
3. **Each capture second's alert is decided once and then frozen** — later
   re-analysis over more data never re-grades a past timestamp. This is the IPS
   early-warning rule: the alert for "now" is what matters, and past decisions
   are immutable. Every graded second is persisted to SQLite as at most one alert.
4. The frontend polls the backend (`/status` at ~1 Hz, `/dashboard` and
   `/live/monitor` every few seconds) and renders live metrics, charts, an alert
   history, a source→network topology, and detection performance.

---

## Repository layout

```
.
├── backend/            Flask engine + IPS (see backend/README.md)
│   ├── dlt_app.py         API entrypoint (dev); also serves the built SPA (prod)
│   ├── launch.py          desktop-app entrypoint (native window + auto-capture)
│   ├── dlt/               pipeline facade + approach_hybrid + shared preprocessing,
│   │                      routes, service, capture, db, notifier, reports
│   ├── model.py           the DLT-NN (neural network) definition
│   ├── models/hybrid/     pre-trained network + thresholds (one baseline per workflow)
│   └── dlt_results/       SQLite alerts.db, results.json, exported CSVs (runtime)
├── frontend/           React + Vite SPA (see frontend/README.md)
├── installer/          Inno Setup script for the Windows installer
├── packaging/          app icon + icon generator
├── ews.spec            PyInstaller spec (windowed one-folder build)
├── build.bat / build.sh   one-shot desktop build scripts
└── BUILD.md            desktop app + installer build guide
```

---

## Getting started (development)

### Prerequisites

- **Python 3.10+** (backend) and **Node.js 18+** with npm (frontend)
- **PyTorch** (installed via `requirements.txt`) — the detection network runs on it
- Pre-trained artifacts ship with the repo under `backend/models/hybrid/`

### 1. Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

python dlt_app.py                 # serves http://127.0.0.1:5001/api/dlt/*
```

The port can be overridden with `DLT_PORT` (defaults to `5001`).

### 2. Frontend

In a second terminal:

```bash
cd frontend
npm install
npm run dev                       # Vite dev server, usually http://localhost:5173
```

The Vite dev server proxies `/api/dlt/*` to `http://localhost:5001`, so the two
processes talk with no CORS setup and no hard-coded host in the frontend.

### 3. Use the app

Open the Vite URL. The homepage is the live **Dashboard**. Use the navbar to
reach the Upload (dataset analysis), Live, Alerts, Statistics, Topology and Admin
pages.

---

## Usage examples

**Analyse a CSV** — from **Upload** (`/flow-analysis`), upload a traffic CSV
containing the expected flow-feature columns plus `Timestamp` and `Label`. The
per-second charts and alert summary build up progressively as the result is
revealed.

**Live monitoring** — the **Dashboard** and **Live** pages track live-captured
traffic; a `HIGH` alert can trigger an audible beep and (if configured) an email.

**Talk to the API directly:**

```bash
curl -F "file=@traffic.csv" http://127.0.0.1:5001/api/dlt/upload   # analyse a CSV
curl http://127.0.0.1:5001/api/dlt/status                          # poll progress
curl http://127.0.0.1:5001/api/dlt/dashboard                       # live metrics
curl http://127.0.0.1:5001/api/dlt/alerts                          # alert history
curl -OJ "http://127.0.0.1:5001/api/dlt/admin/report?format=csv"   # export log
```

### Production build

```bash
cd frontend
npm run build       # emits static assets to frontend/dist/
```

Serve `frontend/dist/` behind any static host and reverse-proxy `/api/dlt/*` to
the running `dlt_app.py` process — or bundle the build into the desktop app so a
single Flask process serves both (see [`BUILD.md`](BUILD.md)).

---

## Dependencies

**Backend:** Flask, flask-cors, numpy, pandas, scikit-learn, scapy, **torch**
(the detection network), plus optional openpyxl/reportlab (reports),
python-dotenv, waitress, pywebview, certifi (desktop packaging). See
`backend/requirements.txt`.

**Frontend:** React, React Router, Vite, Tailwind CSS, Recharts, AG Grid, axios,
Heroicons / react-icons. See `frontend/package.json`.

---

## Notes

- **Live capture requires scapy and OS-level packet-capture privileges.** On
  Linux/macOS run the backend with sufficient permissions (e.g. `sudo`); on
  Windows, install the **Npcap** driver and run as Administrator. The packaged
  Windows installer can bundle and install Npcap automatically (see
  [`BUILD.md`](BUILD.md)).
- The backend keeps job/live-session state **in memory** (single process), so it
  serves one analysis session at a time; graded alerts are persisted to a
  **SQLite** database (`dlt_results/alerts.db`).
- **Email notifications** (HIGH alerts only) are configured via SMTP environment
  variables and toggled from the Admin panel — see `backend/README.md`.

---

## License

Released for academic and evaluation use. See the repository owner for reuse terms.
