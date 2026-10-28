# Firewall Rule Simulation and Traffic Filtering System

A simulated firewall: packets are checked against ordered rules (source/destination IP or subnet,
port or range, protocol) and get an ALLOW or BLOCK decision. Unmatched traffic is blocked by default.
It never touches your real firewall.

## Structure
- `backend/engine.py`: rule matching, validation, default deny (pure Python)
- `backend/database.py`: SQLite storage for rules and traffic logs, seeded with the 4 example rules
- `backend/main.py`: FastAPI endpoints (`/api/rules`, `/api/simulate`, `/api/logs`, `/api/stats`)
- `backend/test_engine.py`: pytest test cases
- `frontend/`: React (Vite) dashboard: packet tester, rule manager, stats, log

## Run
Backend (port 8000):
    cd backend
    pip install -r requirements.txt
    uvicorn main:app --reload

Frontend (port 5173):
    cd frontend
    npm install
    npm run dev

Open http://localhost:5173. API docs: http://localhost:8000/docs

## Tests
    cd backend && pytest

## Try these (with the default rules)
| Source | Port | Protocol | Result | Why |
|---|---|---|---|---|
| 192.168.1.10 | 443 | TCP | BLOCK | Rule 1 matches before the HTTPS allow |
| 203.0.113.7 | 443 | TCP | ALLOW | Rule 2 |
| 203.0.113.7 | 22 | TCP | BLOCK | Rule 4 |
| 203.0.113.7 | 3306 | TCP | BLOCK | Default deny |
| 203.0.113.7 | n/a | ICMP | BLOCK | Default deny |

## Report ideas
Test cases for allowed, blocked, conflicting-priority, invalid-IP and unmatched packets are in
`test_engine.py`. Screenshots: dashboard, a rule edit, and a log after running the table above.
Possible extensions: rule import/export, stateful connection tracking, analyzing captured traffic from an authorized lab.
