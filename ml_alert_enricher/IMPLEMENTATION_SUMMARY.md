# Wazuh Alert Enrichment System - Implementation Summary

## Overview

Cybersecurity AI system integrating Wazuh, Elasticsearch, and Okta for identity-aware alert enrichment. Enhanced with SQLite-based agent-to-user mapping and confidence-based anomaly detection.

---

## Changes Implemented

### 1. **ML Models Enhancement** (`fastapi_app/ml_models.py`)

#### Feature Extraction Update
- **Message Fallback**: If `full_log` field is missing, system now falls back to `message` field (Wazuh version compatibility for newer versions that use `message` instead of `full_log`).
- **Code Change**:
  ```python
  full_log = alert_source.get("full_log") or alert_source.get("message") or "[no log]"
  ```

#### AI Confidence Addition
- **New Return Field**: Added `ai_confidence` (float) to prediction output.
- **Logic**: 
  - `1.0` if anomaly detected (raw_anomaly == -1)
  - `0.0` if normal
- **Code Change**:
  ```python
  ai_confidence = 1.0 if raw_anomaly == -1 else 0.0
  return {
      "severity_level": int(round(prediction)),
      "severity_label": get_severity_label(prediction),
      "is_anomaly": bool(is_anomaly),
      "ai_confidence": float(ai_confidence)
  }
  ```

---

### 2. **SQLite Database Setup** (`fastapi_app/db.py`)

#### Schema: `agent_user_mapping` Table
```sql
CREATE TABLE agent_user_mapping (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    okta_user_email VARCHAR(255) NOT NULL,
    wazuh_agent_id VARCHAR(100) NOT NULL UNIQUE,
    cloud_pc_id VARCHAR(255),
    is_vip BOOLEAN DEFAULT FALSE
);

CREATE INDEX ix_agent_id ON agent_user_mapping(wazuh_agent_id);
```

#### Features
- **SQLAlchemy ORM Model**: `AgentUserMapping` class with all fields
- **Database Operations**:
  - `init_db()`: Initialize database tables
  - `create_mapping()`: Insert new agent-user mapping
  - `get_mapping_by_agent_id()`: Lookup user by Wazuh agent ID
  - `update_mapping()`: Update existing mapping
  - `delete_mapping()`: Remove mapping
- **Path**: SQLite database stored at `mappings.db` (or `$DATABASE_PATH` env var)

---

### 3. **API Endpoint for Mapping Management** (`fastapi_app/main.py`)

#### Endpoint: `POST /add-mapping`
- **Method**: POST
- **Request Body** (Pydantic Model):
  ```json
  {
    "okta_user_email": "user@example.com",
    "wazuh_agent_id": "001",
    "cloud_pc_id": "DEV-PC-001",
    "is_vip": false
  }
  ```
- **Response** (201 Created):
  ```json
  {
    "id": 1,
    "okta_user_email": "user@example.com",
    "wazuh_agent_id": "001",
    "cloud_pc_id": "DEV-PC-001",
    "is_vip": false
  }
  ```
- **Features**:
  - Upsert logic (creates if new, updates if exists)
  - Logging on success/failure
  - Error handling with descriptive messages

---

### 4. **Alert Enrichment Pipeline Enhancement** (`fastapi_app/main.py`)

#### Process Flow
1. **Extract Agent ID**: From `alert['_source']['agent']['id']`
2. **Query SQLite**: Lookup mapping for agent ID
3. **Retrieve User Info**: 
   - `affected_user` = email or "unknown"
   - `cloud_pc_id` = PC identifier or ""
   - `is_vip` = flag value
4. **Enrich Alert**: Add new fields to reclassified alert

#### New Enriched Alert Fields
```json
{
  "alert_id": "DT30N50BPD84AR3l5lyr",
  "affected_user": "user@kamlewa.org",
  "ai_severity": 6,
  "ai_confidence": 0.95,
  "is_anomaly": true,
  "severity_label": "High",
  "ioc_matches": false,
  "is_vip": false,
  "rule_description": "CIS Distribution...",
  "processed": false,
  "@timestamp": "2026-03-29T05:06:33.300Z",
  "risk_score": 12,
  "cloud_pc_id": "DEV-PC-001",
  "wazuh_agent_id": "001",
  "alert_source": "wazuh",
  "original_alert": {...},
  "original_alert_ref_id": "DT30N50BPD84AR3l5lyr"
}
```

#### Risk Score Computation
```python
risk_score = ai_severity * 2 if is_anomaly else ai_severity
```

---

### 5. **Testing** (`fastapi_app/test_ml_models.py`)

#### Test Classes
- **TestFeatureExtraction**:
  - `test_extract_with_full_log()`: Verify extraction with `full_log` present
  - `test_extract_with_message_fallback()`: Verify `message` fallback when `full_log` missing
  - `test_extract_with_no_log_or_message()`: Verify default "[no log]" handling
  - `test_extract_with_nested_groups()`: Verify JSON-encoded groups parsing

- **TestPredictionConfidence**:
  - `test_predict_returns_confidence()`: Verify `ai_confidence` in results
  - `test_predict_with_message_fallback_confidence()`: Confidence with message field

#### Run Tests
```bash
pytest fastapi_app/test_ml_models.py -v
```

---

### 6. **Dependencies** (`requirements.txt`)

Added:
- `sqlalchemy`: ORM for SQLite database
- Existing: `fastapi`, `uvicorn`, `scikit-learn`, `elasticsearch`, `jinja2`, `aiofiles`, `joblib`, `pydantic`, etc.

---

### 7. **Docker Configuration**

#### Docker Compose Update (`compose.yaml`)
- **Volume**: `./data:/app/data` for SQLite persistence
- **Environment**: `DATABASE_PATH=/app/data/mappings.db`

#### Docker Ignore (`.dockerignore`)
- Excludes: `__pycache__`, `*.pyc`, `.pytest_cache`, `*.db` (build cache, not runtime)

---

## Deployment Instructions

### Prerequisites
1. Elasticsearch running (configured via web UI)
2. Docker & Docker Compose installed

### Build & Deploy
```bash
# Build image with new dependencies
docker compose build --no-cache

# Start services
docker compose up -d

# Verify startup (check logs)
docker compose logs -f python-fastapi_app
```

### Expected Startup Output
```
✓ Database initialized at /app/data/mappings.db
Application starting up...
ML models loaded successfully.
Uvicorn running on http://0.0.0.0:8000
```

---

## API Usage Examples

### 1. Add Agent-User Mapping
```bash
curl -X POST http://localhost:8000/add-mapping \
  -H "Content-Type: application/json" \
  -d '{
    "okta_user_email": "alice@company.com",
    "wazuh_agent_id": "001",
    "cloud_pc_id": "ALICE-PC-001",
    "is_vip": true
  }'
```

### 2. Check Reclassified Alerts
```bash
# Query Elasticsearch for enriched alerts with ai_confidence
curl http://elasticsearch:9200/reclassified-alerts/_search?pretty
```

---

## Verification Checklist

- [x] `full_log` fallback to `message` implemented
- [x] `ai_confidence` float added to predictions
- [x] SQLite mapping database with proper schema
- [x] CRUD operations for agent-user mappings
- [x] POST `/add-mapping` endpoint functional
- [x] Alert enrichment with user/PC lookup
- [x] Risk score computation based on severity + anomaly
- [x] Tests for feature extraction and confidence
- [x] Docker persistence for SQLite
- [x] Requirements.txt updated with sqlalchemy
- [x] `.dockerignore` excludes build artifacts

---

## File Structure
```
ml_alert_enricher/
├── fastapi_app/
│   ├── main.py                 # Updated: db init, /add-mapping endpoint, alert enrichment
│   ├── ml_models.py            # Updated: message fallback, ai_confidence
│   ├── models.py               # (unchanged)
│   ├── db.py                   # NEW: SQLAlchemy models, CRUD functions
│   ├── test_ml_models.py       # NEW: Feature extraction & confidence tests
│   ├── Dockerfile              # (unchanged)
│   ├── templates/
│   ├── static/
│   └── models/
├── requirements.txt            # Updated: added sqlalchemy
├── compose.yaml                # Updated: volume + env for SQLite
├── .dockerignore               # NEW: excludes caches
└── README.md
```

---

## Future Enhancements

1. **IOC Module**: Implement `ioc_matches` field with threat intelligence lookup
2. **Authentication**: Add token-based auth to `/add-mapping` endpoint
3. **Batch Mapping Import**: CSV upload endpoint for bulk user-agent mappings
4. **Metrics**: Prometheus endpoints for monitoring alert processing
5. **Retry Logic**: Resilient SQLite lookup with caching for failed queries

---

## Support

For questions or issues:
1. Check Docker logs: `docker compose logs python-fastapi_app`
2. Verify Elasticsearch connectivity: `curl http://elasticsearch:9200/_health`
3. Test SQLite: `sqlite3 /app/data/mappings.db ".tables"`
