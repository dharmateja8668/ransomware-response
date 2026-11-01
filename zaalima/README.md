# ZAALIMA – Automated Ransomware Containment & Incident Response Orchestrator

A professional enterprise-grade **Security Operations Center (SOC)** platform for ransomware detection, containment, forensic investigation, and incident response automation.

---

## Architecture

```
zaalima/
├── frontend/          # Next.js 14 + TypeScript + Tailwind CSS (Port 3000)
└── backend/           # Python FastAPI + PostgreSQL (Port 8000)
```

---

## Quick Start

### Prerequisites
- Node.js 18+ / npm
- Python 3.11+
- PostgreSQL 15+

---

### 1. Database Setup

```sql
-- Create the PostgreSQL database
CREATE DATABASE zaalima;
```

---

### 2. Backend Setup

```bash
cd zaalima/backend

# Create virtual environment
python -m venv venv

# Activate (Windows)
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment variables
copy .env.example .env
# Edit .env with your database credentials and API tokens

# Start the backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The backend will:
- Auto-create all database tables on startup
- Seed the database with realistic simulated security data
- Expose the REST API at http://localhost:8000
- Interactive API docs at http://localhost:8000/docs

---

### 3. Frontend Setup

```bash
cd zaalima/frontend

# Install dependencies
npm install

# Copy environment file
copy .env.local.example .env.local

# Start development server
npm run dev
```

Visit: **http://localhost:3000**

---

## Demo Credentials

| Role | Username | Password |
|------|----------|----------|
| Admin | `admin` | `Admin@123!` |
| SOC Analyst | `soc_analyst1` | `Analyst@123!` |
| SOC Analyst | `soc_analyst2` | `Analyst@123!` |
| Viewer | `viewer` | `Viewer@123!` |

---

## Modules

| # | Module | Description |
|---|--------|-------------|
| 1 | **Login** | JWT authentication, role-based access |
| 2 | **SOC Dashboard** | Real-time threat stats, charts, alert feed |
| 3 | **Threat Detection** | Searchable/filterable threat alert table |
| 4 | **Incident Management** | Create, assign, update, resolve incidents |
| 5 | **Endpoint Management** | Monitor, isolate, restore endpoints |
| 6 | **Automated Playbooks** | Step-by-step ransomware response workflow |
| 7 | **Digital Forensics** | Evidence collection, chain-of-custody |
| 8 | **User & Identity** | User management, session revocation |
| 9 | **Jira Tickets** | Jira Cloud REST API v3 integration |
| 10 | **Audit Logs** | Full action audit trail |
| 11 | **Reports** | Security summary reports |
| 12 | **Settings** | Integration configuration status |

---

## Backend API Reference

| Endpoint | Description |
|----------|-------------|
| `POST /api/auth/login` | Authenticate user |
| `GET /api/dashboard/stats` | Dashboard statistics |
| `GET /api/threats/` | List threats with search/filter |
| `GET /api/incidents/` | List incidents |
| `POST /api/incidents/` | Create incident |
| `GET /api/endpoints/` | List endpoints |
| `POST /api/endpoints/{hostname}/isolate` | [SIMULATED] Isolate endpoint |
| `POST /api/playbooks/execute` | Execute automated playbook |
| `GET /api/forensics/` | List forensic evidence |
| `POST /api/jira/ticket` | Create Jira incident ticket |
| `GET /api/audit/` | Audit log entries |
| `GET /api/reports/summary` | Report summary |
| `WS /ws/notifications` | Real-time WebSocket feed |

Full interactive docs: **http://localhost:8000/docs**

---

## Security Notes

> ⚠️ **IMPORTANT:** All endpoint isolation, account suspension, and response actions are **SIMULATED**.
> No real EDR commands, Active Directory changes, or network modifications are performed without proper authorization.

- All API credentials stored in `.env` (never committed to git)
- JWT authentication with configurable expiry
- Role-based access control (Admin, SOC Analyst, Viewer)
- Confirmation dialogs for all destructive actions
- All simulated actions clearly labeled `[SIMULATED]`

---

## Integrations (Architecture Ready)

| Integration | Status |
|-------------|--------|
| Jira Cloud REST API v3 | ✅ Implemented |
| CrowdStrike Falcon | 🔧 Stub (requires credentials) |
| Microsoft Defender | 🔧 Stub (requires credentials) |
| AWS S3 Evidence Storage | 🔧 Stub (requires credentials) |
| Active Directory | 🔧 Stub (requires credentials) |
| KAPE / Volatility | 🔧 Stub (simulated output) |

---

## Tech Stack

**Frontend:** Next.js 14, TypeScript, Tailwind CSS, Recharts, Lucide React

**Backend:** Python 3.13, FastAPI, SQLAlchemy 2.0, Pydantic v2, python-jose

**Database:** PostgreSQL 15

**Auth:** JWT Bearer tokens with bcrypt password hashing

