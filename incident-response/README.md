# Incident Response API — Docker / FastAPI Edition

Migrated from AWS Lambda + SQS to a self-contained Docker service.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                Docker Container                      │
│                                                      │
│  FastAPI (uvicorn)                                   │
│  ├── POST /incidents          → create + enqueue     │
│  ├── GET  /incidents          → list                 │
│  ├── GET  /incidents/{id}     → detail               │
│  ├── POST /queue/enqueue      → frontend trigger ←── │── Frontend team calls this
│  ├── GET  /queue/stats        → queue depth          │
│  └── GET  /health             → health check         │
│                                                      │
│  In-Memory Queue (asyncio.Queue)                     │
│  └── replaces AWS SQS                                │
│                                                      │
│  Background Worker (asyncio task)                    │
│  └── consumes queue → runs process_incident()        │
│      ├── EC2 describe                                │
│      ├── CloudWatch metrics                          │
│      ├── CloudWatch Logs (two-phase strategy)        │
│      └── Bedrock RCA                                 │
└─────────────────────────────────────────────────────┘
           │
           ▼
      RDS / Postgres
```

---

## Flow

### Option A — via `POST /incidents` (your existing testing endpoint)
```
POST /incidents  →  DB insert (status=queued)  →  internal queue  →  worker  →  process_incident
```

### Option B — Frontend team triggers directly (new flow)
```
Frontend creates incident on their side
        ↓
POST /queue/enqueue  (frontend calls this)
        ↓
internal queue  →  worker  →  process_incident
```

---

## Quick Start

```bash
# 1. Clone / copy the project
cd incident-response

# 2. Set up env
cp .env.example .env
# edit .env with your DB + AWS credentials

# 3. Run DB migration (once)
pip install psycopg2-binary python-dotenv
python run_migration.py

# 4. Build & run
docker compose up --build

# API is live at http://localhost:8000
# Swagger docs at http://localhost:8000/docs
```

---

## API Reference

### Incidents

| Method | Path                    | Description                      |
|--------|-------------------------|----------------------------------|
| POST   | `/incidents`            | Create incident + auto-enqueue   |
| GET    | `/incidents`            | List incidents (paginated)       |
| GET    | `/incidents/{event_id}` | Get incident detail + RCA        |

### Queue (for frontend team)

| Method | Path              | Description                              |
|--------|-------------------|------------------------------------------|
| POST   | `/queue/enqueue`  | Enqueue incident for RCA processing      |
| GET    | `/queue/stats`    | Queue depth and processing counters      |

### Health

| Method | Path      | Description                         |
|--------|-----------|-------------------------------------|
| GET    | `/health` | Service health + queue stats        |

---

### POST /queue/enqueue — Request body

```json
{
  "event_id":            "uuid-of-incident",
  "instance_id":         "i-0abc123",
  "issue":               "High CPU causing 502s",
  "severity":            "high",
  "incident_start_time": "2024-01-15T10:00:00Z",
  "incident_end_time":   "2024-01-15T10:30:00Z",
  "log_group_name":      "/aws/ec2/myapp",
  "region":              "ap-south-1",
  "dependency_context":  {},
  "incident_down_time":  "2024-01-15T10:05:00Z"
}
```

Response `202 Accepted`:
```json
{
  "accepted": true,
  "event_id": "uuid-of-incident",
  "queue_position": 1,
  "message": "Incident queued for RCA processing."
}
```

---

## Environment Variables

| Variable                  | Description                              | Default                          |
|---------------------------|------------------------------------------|----------------------------------|
| `DB_HOST`                 | Postgres host                            | required                         |
| `DB_PORT`                 | Postgres port                            | `5432`                           |
| `DB_NAME`                 | Database name                            | required                         |
| `DB_USER`                 | Database user                            | required                         |
| `DB_PASSWORD`             | Database password                        | required                         |
| `DB_SSL_MODE`             | SSL mode (`require` / `disable`)         | `require`                        |
| `AWS_REGION`              | Default AWS region                       | `ap-south-1`                     |
| `AWS_ACCESS_KEY_ID`       | AWS credentials                          | required                         |
| `AWS_SECRET_ACCESS_KEY`   | AWS credentials                          | required                         |
| `BEDROCK_MODEL_ID`        | Bedrock model                            | `meta.llama3-8b-instruct-v1:0`   |
| `LOG_FETCH_LIMIT`         | Max log events per CW query              | `100`                            |
| `ERROR_SCAN_WINDOW_MINUTES` | Phase-A scan window around downtime    | `30`                             |
| `AI_LOG_LINE_LIMIT`       | Max log lines sent to Bedrock            | `200`                            |

---

## What was removed

- `serverless.yml` — no longer needed
- `lambdas/api/lambda_function.py` — replaced by FastAPI router
- AWS SQS — replaced by `app/queue/manager.py` (asyncio.Queue)
- SQS Lambda trigger for `process_incident` — replaced by `app/processor/worker.py`
