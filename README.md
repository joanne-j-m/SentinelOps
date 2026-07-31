# 🛡️ Sentinel-Ops

**Autonomous Multi-Agent Threat Hunting Pipeline**

> Powered by LangGraph · Llama 3 via Groq · FastAPI · React · Omium

Sentinel-Ops is a stateful multi-agent cybersecurity pipeline that autonomously investigates security alerts. Submit a threat description, and watch four specialized AI agents collaborate in real time to classify, investigate, enrich, and report on the threat — complete with MITRE ATT&CK mapping, threat intel lookups, Discord notifications, and live website monitoring.

---

## Demo

![Sentinel-Ops Dashboard](https://img.shields.io/badge/UI-Neural%20Threat%20Command-00e5ff?style=for-the-badge)
![Tests](https://img.shields.io/badge/Tests-104%20Passing-00ff88?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.14-blue?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-0.7.0-orange?style=for-the-badge)

---

## Architecture

```
                        ┌─────────────────────────────────┐
                        │         FastAPI Backend          │
                        │  POST /jobs  ·  GET /jobs/{id}  │
                        │  X-API-Key auth on mutations     │
                        └────────────┬────────────────────┘
                                     │
                        ┌────────────▼────────────────────┐
                        │      LangGraph State Machine      │
                        │                                  │
                        │   ┌────────────┐                 │
                        │   │ Supervisor │ classify alert   │
                        │   └─────┬──────┘                 │
                        │         │                        │
                        │   ┌─────▼──────┐                 │
                        │   │   Scout    │ extract IOCs    │
                        │   └─────┬──────┘                 │
                        │         │                        │
                        │   ┌─────▼──────┐                 │
                        │   │  Analyst   │ enrich + score  │
                        │   └─────┬──────┘                 │
                        │         │  confidence < 0.6?     │
                        │         ├──────────────► Scout   │
                        │         │  (autonomy loop)       │
                        │   ┌─────▼──────┐                 │
                        │   │  Reporter  │ compile + notify│
                        │   └────────────┘                 │
                        └─────────────────────────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
       ┌──────▼──────┐      ┌────────▼───────┐    ┌────────▼───────┐
       │   Discord   │      │ Omium Tracing  │    │  React Dashboard│
       │  Webhook    │      │   (spans)      │    │  localhost:8000 │
       └─────────────┘      └────────────────┘    └────────────────┘
                                     ▲
                            ┌────────┴───────┐
                            │  monitor.py    │
                            │ (proxy/detect) │
                            └────────────────┘
```

---

## Agents

| Agent | Role | Technology |
|---|---|---|
| **Supervisor** | Classifies alert type and severity, decomposes task | Llama 3 via Groq |
| **Scout** | Extracts IOCs (IPs, hashes, CVEs), reconstructs logs | Regex + Llama 3 |
| **Analyst** | Enriches evidence with threat intel, scores confidence | Tavily Search + Llama 3 |
| **Reporter** | Compiles Threat Fact Sheet, sends notifications | Llama 3 + Discord/Slack |

---

## Features

- **Autonomous loop** — Analyst loops back to Scout if confidence < 60%
- **Real IOC extraction** — IPs, MD5/SHA1/SHA256 hashes, CVEs, domains
- **IP classification** — Separates attacker IPs from victim hosts
- **Threat intel** — Tavily web search for live IP/CVE reputation
- **MITRE ATT&CK mapping** — Auto-inferred tactics per threat type
- **Discord/Slack notifications** — Rich embeds on job completion
- **Omium trace viewer** — Full pipeline observability with automatic LangGraph tracing + checkpoints
- **Live website monitor** — `monitor.py` proxy detects SQLi, XSS, path traversal, brute force in real time
- **Auto-submit alerts** — Monitor pushes detected threats directly to the dashboard
- **API key authentication** — `X-API-Key` header on all mutating endpoints
- **Input sanitization** — Control character stripping and 5000-char length cap before LLM ingestion
- **Thread-safe job store** — Deep-copy isolation prevents race conditions between polling and graph threads
- **Lazy graph initialization** — Pipeline compiles on first use, not at import time
- **Exponential backoff** — Automatic retry on Groq rate limits
- **Robust JSON parsing** — Bracket-balanced extractor + retry logic for malformed LLM responses
- **SentinelAdapter** — P&E bench compatible adapter pattern

---

## Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI + Python 3.14 |
| Agent Framework | LangGraph 1.2+ |
| LLM | Llama 3.3 70B via Groq |
| Threat Intel | Tavily Search API |
| Frontend | React 18 (no build step) |
| Notifications | Discord + Slack Webhooks |
| Tracing | Omium (auto LangGraph instrumentation + checkpoints) |
| Live Monitor | monitor.py (Flask reverse proxy + attack detector) |
| Testing | pytest (104 tests) |

---

## Project Structure

```
sentinel-ops/
├── main.py                          # Entry point
├── monitor.py                       # Live website monitor + attack simulator
├── requirements.txt
├── .env.example                     # Environment variable template
├── frontend/
│   └── index.html                   # React dashboard (no npm needed)
├── backend/
│   ├── core/
│   │   ├── state.py                 # Shared LangGraph state schema
│   │   ├── job_store.py             # Thread-safe in-memory job registry
│   │   ├── llm.py                   # Groq client with retry + backoff
│   │   ├── ioc_parser.py            # Regex IOC extractor
│   │   ├── ip_classifier.py         # Attacker vs victim IP classifier
│   │   ├── search.py                # Tavily threat intel search
│   │   ├── notify.py                # Discord + Slack dispatcher
│   │   ├── omium.py                 # Omium trace + checkpoint integration
│   │   └── tracing.py               # Trace span context manager
│   ├── agents/
│   │   ├── supervisor.py            # Alert classification agent
│   │   ├── scout.py                 # IOC extraction agent
│   │   ├── analyst.py               # Threat enrichment agent
│   │   └── reporter.py              # Fact sheet + notification agent
│   ├── graph/
│   │   └── pipeline.py              # LangGraph StateGraph definition (lazy init)
│   ├── adapters/
│   │   └── sentinel.py              # SentinelAdapter (P&E bench)
│   └── api/
│       ├── app.py                   # FastAPI factory + CORS config
│       └── routes.py                # API endpoints + auth middleware
└── tests/
    ├── test_phase1.py               # Graph wiring + adapter tests
    ├── test_phase2.py               # IOC parser + search tests
    ├── test_phase3.py               # Notification + tracing tests
    ├── test_phase5.py               # JSON retry + IP classifier tests
    └── test_phase7_fixes.py         # Security, correctness, and type-safety tests
```

---

## Quick Start

### 1. Clone and set up

```bash
git clone https://github.com/vpadival/sentinel-ops.git
cd sentinel-ops

python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Mac/Linux

pip install -r requirements.txt
pip install pytest
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and fill in:

```env
GROQ_API_KEY=gsk_...           #  https://console.groq.com
TAVILY_API_KEY=tvly-...        # https://app.tavily.com
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...  # Optional
OMIUM_API_KEY=...              #  https://omium.ai
```

### 3. Run tests

```bash
python -m pytest tests/ -v
# 104 passed
```

### 4. Start the server

```bash
python main.py
```

### 5. Open the dashboard

```
http://localhost:8000
```

---

## Live Website Monitor

`monitor.py` sits as a reverse proxy in front of any website and automatically detects attacks — SQL injection, XSS, path traversal, command injection, brute force, and scanner bots. Detected threats are pushed directly to the Sentinel-Ops dashboard.

### Run as proxy (monitors real traffic)

```bash
# Terminal 1 — start the proxy in front of your website
python monitor.py --target http://localhost:3000 --port 9000

# Visit your website via the monitor:
# http://localhost:9000
```

### Run attack simulator (demo mode)

```bash
# Terminal 1 — start proxy
python monitor.py --target http://localhost:8000 --port 9000

# Terminal 2 — simulate attacks
python monitor.py --simulate
```

Watch the Sentinel-Ops dashboard at `http://localhost:8000` — alerts auto-appear and agents investigate in real time.

### Detected attack types

| Attack | Detection Method |
|---|---|
| SQL Injection | Regex on URL + body (UNION SELECT, DROP TABLE, etc.) |
| XSS | Script tags, javascript: URIs, event handlers |
| Path Traversal | `../` sequences, `/etc/passwd`, `/windows/system32` |
| Command Injection | Shell metacharacters, backticks, `$(...)` |
| Brute Force | Rate limiting — 30 req/60s threshold |
| Scanner/Bot | User-agent matching (nikto, sqlmap, nmap, etc.) |
| Sensitive Paths | `/.env`, `/.git`, `/admin`, `/wp-admin`, etc. |

---

## API Reference

### Submit a job
```bash
POST /api/v1/jobs
Content-Type: application/json
X-API-Key: your-key-here      # required if SENTINEL_API_KEY is set

{
  "problem_statement": "SSH brute-force from 203.0.113.42, 10 failed attempts. CVE-2023-38408 detected."
}
```

Response:
```json
{
  "job_id": "7bb1f521-...",
  "status": "pending",
  "message": "Job accepted. Poll GET /jobs/{job_id} for status."
}
```

### Poll job status
```bash
GET /api/v1/jobs/{job_id}
```

### Push alert from monitor
```bash
POST /api/v1/queue
Content-Type: application/json
X-API-Key: your-key-here

{
  "problem_statement": "SQL injection detected from 1.2.3.4..."
}
```

### Poll queue (frontend auto-submit)
```bash
GET /api/v1/queue
```

### Ingest webhook alert
```bash
POST /api/v1/webhook/alert
Content-Type: application/json
X-API-Key: your-key-here

{
  "source": "falco",
  "severity": "WARNING",
  "rule": "Terminal shell in container",
  "output": "A shell was spawned in a container..."
}
```

### Health check
```bash
GET /api/v1/health
```

Response:
```json
{
  "status": "ok",
  "version": "0.7.0",
  "models": { "primary": "llama-3.3-70b-versatile", "fallback": "llama-3.1-8b-instant" },
  "keys": { "groq": true, "tavily": true, "discord": true, "omium": true },
  "jobs": { "total": 12, "complete": 10, "pending": 2 }
}
```

---

## Adapter Pattern (P&E Bench)

```python
from backend.adapters.sentinel import SentinelAdapter

adapter = SentinelAdapter()
result = adapter.execute_task(
    "SSH brute-force from 203.0.113.42, CVE-2023-38408 detected."
)

print(result["fact_sheet"]["severity"])        # HIGH
print(result["fact_sheet"]["recommendations"]) # ["Block 203.0.113.42...", ...]
print(result["fact_sheet"]["mitre_tactics"])   # ["T1110", "T1190"]
```

---

## Sample Alerts to Test

```
# Brute Force
SSH brute-force from 203.0.113.42, 10 failed login attempts on root account. CVE-2023-38408 detected.

# Ransomware + C2
Ransomware detected on host 10.0.0.5. Outbound C2 connection to 185.220.101.47 on port 443. 2GB data exfiltrated.

# Privilege Escalation
Unusual sudo activity on prod-server-01. User jenkins executed chmod 777 /etc/passwd. CVE-2021-4034 polkit exploit detected.

# Phishing
User clicked suspicious link from ceo@comp4ny.com. Credential harvesting page at 45.33.32.156/login detected.

# Malware Hash
File hash 3c4b2a1d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b quarantined on WIN-DC-04. Outbound to 91.108.4.1:1337.
```

---

## Implementation Phases

| Phase | What was built |
|---|---|
| 1 | LangGraph skeleton, state schema, stub agents, FastAPI, SentinelAdapter |
| 2 | Real Groq/Llama 3 LLM calls, IOC parser, Tavily search |
| 3 | Discord/Slack notifications, Omium tracing + checkpoints, analyst message fix |
| 4 | React Mission Control dashboard with live agent pipeline visualization |
| 5 | JSON retry logic, IP classifier, exponential backoff, health endpoint |
| 6 | Omium SDK integration, live website monitor (monitor.py), auto-alert queue |
| 7 | API key auth, CORS hardening, thread-safe job store, input sanitization, lazy graph init, full type annotations, 30 new tests |

---

## Security

| Control | Implementation |
|---|---|
| API authentication | `X-API-Key` header — set `SENTINEL_API_KEY` in `.env` to enable |
| CORS | Locked to `localhost:8000` and `localhost:9000` — no wildcard |
| Input sanitization | Control characters stripped, 5000-char hard cap before LLM ingestion |
| Thread safety | `JobStore.get()` and `create()` return deep copies — graph thread cannot corrupt poll thread reads |
| Dependency safety | `monitor.py` no longer auto-installs packages via subprocess |

---

## Dependencies

All dependencies are listed in `requirements.txt`. Key ones:
_____

fastapi>=0.111.0
uvicorn[standard]>=0.29.0
langgraph>=0.2.0
langchain-core>=0.2.19
groq>=0.8.0
python-dotenv>=1.0.1
httpx>=0.27.0
pydantic>=2.7.1
tavily-python>=0.3.0
aiofiles>=23.0.0
omium
flask>=3.0.0
flask-cors>=4.0.0
```
(empty line)
(testing webhook)
(third test webhook)
(test webhook)
(test webhook)
(test webhook)