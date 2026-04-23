# Wazuh Alert Enrichment System - API Documentation

## Base URL
```
http://localhost:8000
```

---

## Endpoints

### 1. Web UI
- **Path**: `GET /`
- **Description**: Load Elasticsearch configuration web interface
- **Response**: HTML dashboard
- **Status Code**: 200

---

### 2. Save Elasticsearch Configuration
- **Path**: `POST /config`
- **Description**: Save Elasticsearch connection settings
- **Request Body**:
  ```json
  {
    "auth_method": "no_security|ssl|api_key",
    "host": "elasticsearch.example.com",
    "port": 9200,
    "username": "elastic",
    "password": "password",
    "api_key": "api_key_string"
  }
  ```
- **Response Success (200)**:
  ```json
  {
    "message": "Configuration saved and connection successful."
  }
  ```
- **Response Error (503)**:
  ```json
  {
    "detail": "Configuration saved, but could not connect to Elasticsearch."
  }
  ```
- **Status Codes**: 200, 503, 500

---

### 3. Add/Update Agent-User Mapping ⭐ NEW
- **Path**: `POST /add-mapping`
- **Description**: Create or update mapping between Wazuh agent ID and Okta user
- **Request Body**:
  ```json
  {
    "okta_user_email": "alice@kamlewa.org",
    "wazuh_agent_id": "001",
    "cloud_pc_id": "ALICE-PC-001",
    "is_vip": true
  }
  ```
- **Field Descriptions**:
  - `okta_user_email` (string, required): Okta user email
  - `wazuh_agent_id` (string, required): Wazuh agent identifier
  - `cloud_pc_id` (string, optional): Cloud PC identifier
  - `is_vip` (boolean, optional): Flag for VIP users (higher priority)

- **Response Success (201 Created)**:
  ```json
  {
    "id": 1,
    "okta_user_email": "alice@kamlewa.org",
    "wazuh_agent_id": "001",
    "cloud_pc_id": "ALICE-PC-001",
    "is_vip": true
  }
  ```

- **Response Error (400)**:
  ```json
  {
    "detail": "Failed to save mapping: <error message>"
  }
  ```

- **Status Codes**: 201, 400

---

### 4. Mappings Management UI ⭐ NEW
- **Path**: `GET /mappings-ui`
- **Description**: Load web interface for managing agent-user mappings
- **Response**: HTML interface with forms and tables
- **Status Code**: 200

---

### 5. List All Mappings ⭐ NEW
- **Path**: `GET /mappings`
- **Description**: Retrieve all agent-user mappings
- **Response Success (200)**:
  ```json
  [
    {
      "id": 1,
      "okta_user_email": "alice@kamlewa.org",
      "wazuh_agent_id": "001",
      "cloud_pc_id": "ALICE-PC-001",
      "is_vip": true
    },
    {
      "id": 2,
      "okta_user_email": "bob@kamlewa.org",
      "wazuh_agent_id": "002",
      "cloud_pc_id": null,
      "is_vip": false
    }
  ]
  ```
- **Status Codes**: 200, 500

---

### 6. Get Specific Mapping ⭐ NEW
- **Path**: `GET /mappings/{agent_id}`
- **Description**: Retrieve mapping for specific agent ID
- **Path Parameters**:
  - `agent_id` (string): Wazuh agent identifier
- **Response Success (200)**: Same format as single mapping above
- **Response Error (404)**:
  ```json
  {
    "detail": "Mapping not found for agent 001"
  }
  ```
- **Status Codes**: 200, 404, 500

---

### 7. Update Mapping ⭐ NEW
- **Path**: `PUT /mappings/{agent_id}`
- **Description**: Update existing agent-user mapping
- **Path Parameters**:
  - `agent_id` (string): Wazuh agent identifier
- **Request Body**: Same as POST /add-mapping (partial updates allowed)
- **Response Success (200)**: Updated mapping object
- **Response Error (404)**:
  ```json
  {
    "detail": "Mapping not found for agent 001"
  }
  ```
- **Status Codes**: 200, 400, 404, 500

---

### 8. Delete Mapping ⭐ NEW
- **Path**: `DELETE /mappings/{agent_id}`
- **Description**: Delete agent-user mapping
- **Path Parameters**:
  - `agent_id` (string): Wazuh agent identifier
- **Response Success (200)**:
  ```json
  {
    "message": "Mapping for agent 001 deleted successfully"
  }
  ```
- **Response Error (404)**:
  ```json
  {
    "detail": "Mapping not found for agent 001"
  }
  ```
- **Status Codes**: 200, 404, 500

---

## Example Workflows

### Workflow 1: Configure Elasticsearch + Add User Mapping

#### Step 1: Save ES Configuration
```bash
curl -X POST http://localhost:8000/config \
  -H "Content-Type: application/json" \
  -d '{
    "auth_method": "no_security",
    "host": "192.168.2.100",
    "port": 9200
  }'
```

#### Step 2: Add User-Agent Mapping
```bash
curl -X POST http://localhost:8000/add-mapping \
  -H "Content-Type: application/json" \
  -d '{
    "okta_user_email": "ceo@kamlewa.org",
    "wazuh_agent_id": "001",
    "cloud_pc_id": "CEO-PC-001",
    "is_vip": true
  }'
```

#### Step 3: Verify in Elasticsearch
```bash
# Query reclassified alerts with enriched user data
curl http://192.168.2.100:9200/reclassified-alerts/_search?pretty \
  -d '{
    "query": {
      "match": {
        "affected_user": "ceo@kamlewa.org"
      }
    }
  }'
```

### Workflow 2: Bulk Add Multiple Mappings

```bash
# User 1 - CEO
curl -X POST http://localhost:8000/add-mapping \
  -H "Content-Type: application/json" \
  -d '{
    "okta_user_email": "ceo@kamlewa.org",
    "wazuh_agent_id": "001",
    "cloud_pc_id": "CEO-PC-001",
    "is_vip": true
  }'

# User 2 - Dev
curl -X POST http://localhost:8000/add-mapping \
  -H "Content-Type: application/json" \
  -d '{
    "okta_user_email": "dev@kamlewa.org",
    "wazuh_agent_id": "002",
    "cloud_pc_id": "DEV-PC-001",
    "is_vip": false
  }'

# User 3 - Ops
curl -X POST http://localhost:8000/add-mapping \
  -H "Content-Type: application/json" \
  -d '{
    "okta_user_email": "ops@kamlewa.org",
    "wazuh_agent_id": "003",
    "cloud_pc_id": "OPS-PC-001",
    "is_vip": false
  }'
```

---

## Response Models

### AgentUserMappingRequest
```python
{
  "okta_user_email": str,           # e.g., "user@company.com"
  "wazuh_agent_id": str,            # e.g., "001"
  "cloud_pc_id": str | None,        # e.g., "LAPTOP-ABC123"
  "is_vip": bool                    # default: False
}
```

### AgentUserMappingResponse
```python
{
  "id": int,                        # Primary key
  "okta_user_email": str,           # User email
  "wazuh_agent_id": str,            # Agent ID (unique)
  "cloud_pc_id": str | None,        # PC identifier
  "is_vip": bool                    # VIP flag
}
```

---

## Enriched Alert Structure

All alerts in `reclassified-alerts` index now include:

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
  "rule_description": "CIS Distribution Independent Linux Benchmark...",
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

### Field Reference
- `alert_id`: Original Elasticsearch document ID
- `affected_user`: Okta user email (from mapping) or "unknown"
- `ai_severity`: ML model severity level (0-15)
- `ai_confidence`: Anomaly detection confidence (0.0 or 1.0)
- `is_anomaly`: Boolean anomaly flag
- `severity_label`: Human-readable label (Low/Medium/High/Critical)
- `ioc_matches`: IOC threat intelligence match (placeholder)
- `is_vip`: VIP user flag (from mapping)
- `rule_description`: Wazuh rule text
- `risk_score`: Computed as `severity * 2` if anomaly, else `severity`
- `cloud_pc_id`: Cloud PC identifier (from mapping)
- `wazuh_agent_id`: Wazuh agent ID
- `alert_source`: Always "wazuh"

---

## Error Handling

### Common Errors

#### 400 Bad Request
- Invalid request body format
- Missing required fields
- Duplicate wazuh_agent_id (for initial creation)

```json
{
  "detail": "Failed to save mapping: value error, <field> is required"
}
```

#### 503 Service Unavailable
- Elasticsearch connection failed
- Configuration saved but ES unreachable

```json
{
  "detail": "Configuration saved, but could not connect to Elasticsearch."
}
```

#### 500 Internal Server Error
- Unexpected server error
- Database operation failure

```json
{
  "detail": "Failed to save configuration: <error details>"
}
```

---

## Database Queries (SQLite)

### View All Mappings
```sql
SELECT * FROM agent_user_mapping;
```

### Find User by Agent ID
```sql
SELECT okta_user_email, cloud_pc_id, is_vip 
FROM agent_user_mapping 
WHERE wazuh_agent_id = '001';
```

### Find All VIP Users
```sql
SELECT * FROM agent_user_mapping WHERE is_vip = TRUE;
```

### Update User Mapping
```sql
UPDATE agent_user_mapping 
SET okta_user_email = 'newemail@company.com'
WHERE wazuh_agent_id = '001';
```

### Delete Mapping
```sql
DELETE FROM agent_user_mapping 
WHERE wazuh_agent_id = '001';
```

---

## Performance Notes

- **Agent Lookup**: O(1) with indexed `wazuh_agent_id` column
- **Database Path**: `/app/data/mappings.db` (persistent volume in Docker)
- **Max Alerts Per Cycle**: 1000 (configurable in `PROCESSING_INTERVAL_SECONDS`)
- **Background Processing**: Every 60 seconds

---

## Testing

### Unit Tests
```bash
# Run pytest from fastapi_app directory
pytest test_ml_models.py -v
```

### Integration Test
```bash
# Start system
docker compose up -d

# Test ES connection
curl http://localhost:8000/

# Add mapping
curl -X POST http://localhost:8000/add-mapping \
  -H "Content-Type: application/json" \
  -d '{"okta_user_email":"test@test.com","wazuh_agent_id":"999"}'

# Check logs
docker compose logs python-fastapi_app | grep "Created mapping"
```

---

## Troubleshooting

### Alerts show `affected_user: "unknown"`
- **Cause**: No mapping exists for agent ID
- **Solution**: Add mapping via `/add-mapping` endpoint

### DB file not persisting
- **Cause**: Volume not mounted correctly
- **Solution**: Check `compose.yaml` has `./data:/app/data` volume

### `ai_confidence` is always 0.0
- **Cause**: Model not detecting anomalies
- **Solution**: Check model training data and threshold configuration

### Database locked error
- **Cause**: Concurrent write operations
- **Solution**: SQLite handles this; check for processes holding connection

---

## Support & Documentation

- API Docs (auto-generated): `http://localhost:8000/docs`
- Implementation Guide: See `IMPLEMENTATION_SUMMARY.md`
- Model Info: See `fastapi_app/ml_models.py`
