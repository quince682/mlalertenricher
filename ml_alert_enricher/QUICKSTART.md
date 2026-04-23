# Quick Start Guide - Wazuh Alert Enrichment System

## 🚀 5-Minute Setup

### 1. Start the System
```bash
cd ml_alert_enricher
docker compose build --no-cache
docker compose up -d
```

### 2. Access Web UI
Open browser: `http://localhost:8000`

### 3. Configure Elasticsearch
Fill in Elasticsearch connection details (host, port, auth method).

### 4. Add User-Agent Mappings
Use the API to map Wazuh agents to Okta users:

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

### 5. Wait for Alert Processing
- System automatically fetches alerts every 60 seconds
- Enriched alerts appear in `reclassified-alerts` index

---

## 📊 Key Features

✅ **Message Field Fallback**: If Wazuh removes `full_log`, system uses `message`  
✅ **AI Confidence**: Each alert gets confidence score (0.0-1.0)  
✅ **User Mapping**: SQLite database links agents to Okta users  
✅ **Risk Scoring**: Auto-calculated from severity + anomaly status  
✅ **VIP Tracking**: Mark important users for priority handling  

---

## 🔍 Check Status

```bash
# View logs
docker compose logs -f python-fastapi_app

# Check database
sqlite3 data/mappings.db ".schema"

# Query Elasticsearch
curl http://localhost:9200/reclassified-alerts/_search?pretty | head -50
```

---

## 📝 Sample Enriched Alert

```json
{
  "alert_id": "DT30N50BPD84AR3l5lyr",
  "affected_user": "alice@company.com",
  "ai_severity": 8,
  "ai_confidence": 1.0,
  "is_anomaly": true,
  "severity_label": "High",
  "risk_score": 16,
  "cloud_pc_id": "ALICE-PC-001",
  "is_vip": true,
  "@timestamp": "2026-04-02T10:30:00.000Z"
}
```

---

## 🛠️ API Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/` | Elasticsearch Configuration UI |
| POST | `/config` | Configure Elasticsearch |
| GET | `/mappings-ui` | Agent-User Mappings Management UI |
| POST | `/add-mapping` | Add/update user-agent mapping |
| GET | `/mappings` | List all mappings |
| GET | `/mappings/{agent_id}` | Get specific mapping |
| PUT | `/mappings/{agent_id}` | Update mapping |
| DELETE | `/mappings/{agent_id}` | Delete mapping |

---

## 🎯 Managing Agent-User Mappings

### Web Interface
1. **Access**: Visit `http://localhost:8000/mappings-ui`
2. **Add Mapping**: Fill form with Okta email, Agent ID, Cloud PC ID (optional), VIP status
3. **Edit Mapping**: Click "Edit" button on any row, modify in modal, click "Update"
4. **Delete Mapping**: Click "Delete" button, confirm deletion
5. **View All**: Table shows all current mappings with actions

### API Usage
```bash
# Add mapping
curl -X POST http://localhost:8000/add-mapping \
  -H "Content-Type: application/json" \
  -d '{"okta_user_email":"user@company.com","wazuh_agent_id":"001","cloud_pc_id":"PC-123","is_vip":false}'

# List all mappings
curl http://localhost:8000/mappings

# Get specific mapping
curl http://localhost:8000/mappings/001

# Update mapping
curl -X PUT http://localhost:8000/mappings/001 \
  -H "Content-Type: application/json" \
  -d '{"okta_user_email":"newuser@company.com","is_vip":true}'

# Delete mapping
curl -X DELETE http://localhost:8000/mappings/001
```

## 💾 Persistence

Database stored at: `./data/mappings.db`  
Persists across container restarts via Docker volume.

---

## ❓ Troubleshooting

| Issue | Solution |
|-------|----------|
| Alerts show `affected_user: "unknown"` | Add mapping for that agent ID |
| `ai_confidence` always 0.0 | Check ML model output in logs |
| Connection error to ES | Verify ES config via web UI |
| Database locked | Restart container: `docker compose restart` |

---

## 📚 Documentation

- **Full API Docs**: [API_DOCUMENTATION.md](API_DOCUMENTATION.md)
- **Implementation Details**: [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)
- **Auto-generated Swagger UI**: `http://localhost:8000/docs`

---

## 🔐 Security Notes

- Store ES credentials securely (not in code)
- Use `.env` file for sensitive data
- In production: Add authentication to `/add-mapping` endpoint
- Regularly backup SQLite database

---

## 📞 Support

For detailed setup or integration help, refer to:
1. [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) - Architecture overview
2. [API_DOCUMENTATION.md](API_DOCUMENTATION.md) - Endpoint reference
3. Docker logs: `docker compose logs python-fastapi_app`

---

**Status**: ✅ Ready for deployment
