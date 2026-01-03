# cyberguard
CyberGuard is a real-time workstation network monitoring app that combines traditional telemetry with a local LLM (Ollama) to produce human-readable security insights. It continuously observes the machine’s active network behavior, detects notable changes, and summarizes risk in a stable, low-noise way.

# CyberGuard

Local AI-powered network health monitor  
Python + Ollama + Pygame

CyberGuard is a real-time workstation monitoring application that combines
traditional network telemetry with a local large language model (LLM)
running via Ollama. It continuously observes network behavior on the local
machine, converts changes into structured events, computes a stable risk
score, and presents everything in a live dashboard UI.

The goal of the project is to demonstrate a full defensive monitoring
pipeline:
telemetry → detection → risk scoring → analyst narrative → visualization
— all running locally.

---

## What CyberGuard Monitors (local machine only)

- Active network connections (remote IPs and ports)
- Listening sockets / open ports
- Per-process context (PID, process name, executable path when available)
- DNS cache entries (lightweight suspicious-domain heuristics)
- ARP table (devices observed on the local network)
- Hosts file integrity (detects changes between loops)

CyberGuard is passive and does not scan or interact with other hosts.

---

## Detection and Risk Scoring

CyberGuard uses a hybrid risk model:

1. Heuristic risk
   - Evidence-based scoring from concrete signals
   - Examples:
     - Suspicious ports
     - Unusual DNS patterns
     - Hosts file changes
     - Excessive or unusual listeners

2. AI-assisted risk (local LLM)
   - A local Ollama model generates:
     - A structured risk estimate
     - Key findings with evidence
     - Recommended next steps
   - The AI is explicitly constrained to be conservative and evidence-based

3. Stabilization layer
   - Weighted blending (heuristics lead, AI assists)
   - Exponential moving average (EMA) smoothing
   - Hysteresis to prevent oscillation (risk rises faster than it falls)

This prevents the “0 → 100 → 0” false-positive behavior common in naive
LLM-driven tools.

---

## UI / Visualization

CyberGuard includes a real-time Pygame dashboard with:

- Live gauges:
  - Active connections
  - Listening ports
  - Unique remote IPs
  - Stable risk score
- Time-series graphs:
  - Connections history
  - Stable risk over time
  - Heuristic risk component
  - AI raw risk component
- Scrolling event feed
- AI commentary panel (analyst-style notes)

---

## Data Storage

CyberGuard persists data for auditability and analysis:

- SQLite database:
  - Observations
  - Events
  - AI reports
- JSONL logs:
  - observations.jsonl
  - events.jsonl
  - ai_reports.jsonl
- Saved AI report snapshots (JSON)

All data is stored locally.

---

## Why This Project Matters

CyberGuard demonstrates practical defensive engineering skills:

- Network telemetry collection and normalization
- Event detection and classification
- Evidence-based risk modeling
- Local LLM inference using Ollama (no cloud APIs)
- Noise reduction and signal stabilization
- Logging, persistence, and audit-friendly design
- Real-time visualization and operator controls

This is not a toy demo — it is structured like a real monitoring system.

---

## Requirements

- Python 3.10+
- Ollama installed and running locally
- A local Ollama model (tested with: dolphin-mistral:latest)

---

## Python Dependencies

Install via pip:

pip install pygame psutil requests

Required packages:
- pygame
- psutil
- requests

---

## Setup

1. Install dependencies

pip install pygame psutil requests

2. Verify Ollama is running

ollama list

You should see a model such as:
- dolphin-mistral:latest

If Ollama is not running:

ollama serve

3. Run CyberGuard

python cyberguard.py

---

## Controls

- Space      Pause / Resume monitoring
- Up Arrow   Increase monitoring interval
- Down Arrow Decrease monitoring interval
- A          Force AI analysis immediately
- Esc        Quit application

---

## Output Files

CyberGuard creates a directory:

cyberguard_data/

Contents include:
- cyberguard.sqlite3        SQLite database
- logs/observations.jsonl
- logs/events.jsonl
- logs/ai_reports.jsonl
- reports/                 Saved AI report snapshots

---

## Safety and Scope

- Passive monitoring only
- Local machine only
- No port scanning
- No exploitation
- No external network interaction

Designed for learning, portfolio demonstration, and defensive monitoring
experiments.

---

## License

MIT
