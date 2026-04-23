# fastapi_app/main.py
import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

import aiofiles
from elasticsearch import AsyncElasticsearch, NotFoundError
from fastapi import FastAPI, BackgroundTasks, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from models import ESConfig
from ml_models import predict
from db import init_db, get_db, get_mapping_by_agent_id, create_mapping, update_mapping

# --- Constants ---
CONFIG_FILE = "config.json"
ORIGINAL_ALERTS_INDEX = "wazuh-alerts"
RECLASSIFIED_ALERTS_INDEX = "reclassified-alerts"
PROCESSING_INTERVAL_SECONDS = 60
LAST_PROCESSED_TIMESTAMP_FILE = "last_processed_timestamp.txt"

# --- Global State ---
es_client: AsyncElasticsearch | None = None
background_task_active = False

# --- Lifespan Management ---
async def startup_event():
    global background_task_active
    print("Application starting up...")
    init_db()  # Initialize database tables
    await load_es_client()
    if es_client and not background_task_active:
        asyncio.create_task(periodic_alert_processing())
        background_task_active = True

async def shutdown_event():
    print("Application shutting down...")
    if es_client:
        await es_client.close()
    print("Elasticsearch client closed.")

@asynccontextmanager
async def lifespan(app: FastAPI):
    await startup_event()
    yield
    await shutdown_event()

# --- App Initialization ---
app = FastAPI(title="Intelligent Alert Triage System", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# --- Helper Functions ---
async def load_es_client():
    global es_client
    if not os.path.exists(CONFIG_FILE):
        print("Configuration file not found. Please configure via the web UI.")
        return

    async with aiofiles.open(CONFIG_FILE, "r") as f:
        config_data = json.loads(await f.read())
        config = ESConfig(**config_data)

    es_args = {}
    if config.auth_method == 'api_key':
        es_args['hosts'] = [config.host]
        es_args['api_key'] = config.api_key
    elif config.auth_method == 'ssl':
        es_args['hosts'] = [f"https://{config.host}:{config.port}"]
        es_args['basic_auth'] = (config.username, config.password)
    else:
        es_args['hosts'] = [f"http://{config.host}:{config.port}"]

    es_args['verify_certs'] = False
    es_args['request_timeout'] = 30

    try:
        if es_client:
            await es_client.close()
        es_client = AsyncElasticsearch(**es_args)
        if await es_client.ping():
            print(f"Successfully connected to Elasticsearch using '{config.auth_method}' method.")
            await ensure_indices_exist()
        else:
            es_client = None
            print("Could not connect to Elasticsearch.")
    except Exception as e:
        es_client = None
        print(f"Error connecting to Elasticsearch: {e}")

async def ensure_indices_exist():
    if not es_client:
        return
    try:
        if not await es_client.indices.exists(index=RECLASSIFIED_ALERTS_INDEX):
            await es_client.indices.create(index=RECLASSIFIED_ALERTS_INDEX)
            print(f"Created index: {RECLASSIFIED_ALERTS_INDEX}")
    except Exception as e:
        print(f"Error creating index '{RECLASSIFIED_ALERTS_INDEX}': {e}")

# --- Background Processing Task ---
async def process_alerts():
    if not es_client:
        print("Skipping processing: Elasticsearch client not available.")
        return

    last_timestamp = await get_last_processed_timestamp()
    print(f"Fetching new alerts since: {last_timestamp}")

    try:
        query = {"range": {"@timestamp": {"gt": last_timestamp}}}
        response = await es_client.search(
            index=ORIGINAL_ALERTS_INDEX,
            query=query,
            sort=[{"@timestamp": {"order": "asc", "unmapped_type": "date"}}],
            size=1000
        )

        alerts = response['hits']['hits']
        if not alerts:
            print("No new alerts to process.")
            return

        print(f"Found {len(alerts)} new alerts to process.")

        newest_timestamp = last_timestamp
        for alert in alerts:
            original_alert = alert['_source']
            original_alert_id = alert['_id']

            try:
                result = predict(original_alert)
            except Exception as e:
                print(f"Skipping alert due to prediction error: {e}")
                continue

            # Extract wazuh agent ID from alert
            wazuh_agent_id = original_alert.get("agent", {}).get("id", "unknown")
            
            # Query SQLite mapping for user and PC info
            from db import SessionLocal
            db = SessionLocal()
            try:
                mapping = get_mapping_by_agent_id(db, wazuh_agent_id)
                if mapping:
                    affected_user = mapping.okta_user_email
                    cloud_pc_id = mapping.cloud_pc_id or ""
                    is_vip = mapping.is_vip
                else:
                    affected_user = "unknown"
                    cloud_pc_id = ""
                    is_vip = False
                    print(f"⚠ Warning: No mapping found for agent ID {wazuh_agent_id}")
            except Exception as e:
                print(f"⚠ Warning: Failed to query mapping for agent {wazuh_agent_id}: {e}")
                affected_user = "unknown"
                cloud_pc_id = ""
                is_vip = False
            finally:
                db.close()
            
            # Extract rule description from original alert
            rule_description = original_alert.get("rule", {}).get("description", "")
            
            # Compute risk score as combination of severity and anomaly flag
            ai_severity = result["severity_level"]
            risk_score = ai_severity * 2 if result["is_anomaly"] else ai_severity
            
            # Build enriched alert with all required fields
            enriched_alert = {
                "alert_id": original_alert_id,
                "affected_user": affected_user,
                "ai_severity": ai_severity,
                "ai_confidence": result.get("ai_confidence", 0.0),
                "is_anomaly": result["is_anomaly"],
                "severity_label": result["severity_label"],
                "ioc_matches": True,  # Placeholder for IOC module integration
                "is_vip": is_vip,
                "rule_description": rule_description,
                "processed": False,
                "@timestamp": original_alert.get("@timestamp"),
                "risk_score": risk_score,
                "cloud_pc_id": cloud_pc_id,
                "wazuh_agent_id": wazuh_agent_id,
                "alert_source": "wazuh",
                "original_alert": original_alert,
                "original_alert_ref_id": original_alert_id
            }
            await es_client.index(index=RECLASSIFIED_ALERTS_INDEX, document=enriched_alert)
            newest_timestamp = original_alert.get("@timestamp", newest_timestamp)

        await set_last_processed_timestamp(newest_timestamp)
        print(f"Successfully processed {len(alerts)} alerts. Newest timestamp: {newest_timestamp}")

    except NotFoundError:
        print(f"Warning: Index '{ORIGINAL_ALERTS_INDEX}' not found.")
    except Exception as e:
        print(f"An error occurred during alert processing: {e}")

async def get_last_processed_timestamp():
    if not os.path.exists(LAST_PROCESSED_TIMESTAMP_FILE):
        return (datetime.utcnow() - timedelta(days=1)).isoformat() + "Z"
    async with aiofiles.open(LAST_PROCESSED_TIMESTAMP_FILE, "r") as f:
        return await f.read()

async def set_last_processed_timestamp(timestamp: str):
    async with aiofiles.open(LAST_PROCESSED_TIMESTAMP_FILE, "w") as f:
        await f.write(timestamp)

async def periodic_alert_processing():
    while True:
        await process_alerts()
        await asyncio.sleep(PROCESSING_INTERVAL_SECONDS)

# --- API Endpoints ---
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse(request, "index.html")

@app.post("/config")
async def save_config(config: ESConfig):
    try:
        async with aiofiles.open(CONFIG_FILE, "w") as f:
            await f.write(config.model_dump_json(indent=4))
        await load_es_client()
        if es_client:
            return JSONResponse(content={"message": "Configuration saved and connection successful."}, status_code=200)
        else:
            raise HTTPException(status_code=503, detail="Configuration saved, but could not connect to Elasticsearch.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save configuration: {str(e)}")


# --- Database Models ---
class AgentUserMappingRequest(BaseModel):
    """Request model for adding/updating user-agent mappings."""
    okta_user_email: str
    wazuh_agent_id: str
    cloud_pc_id: str | None = None
    is_vip: bool = False


class AgentUserMappingResponse(BaseModel):
    """Response model for user-agent mappings."""
    id: int
    okta_user_email: str
    wazuh_agent_id: str
    cloud_pc_id: str | None
    is_vip: bool

    class Config:
        from_attributes = True


# --- User-Agent Mapping Endpoints ---
@app.post("/add-mapping", response_model=AgentUserMappingResponse, status_code=201)
async def add_mapping(mapping_data: AgentUserMappingRequest, db=Depends(get_db)):
    """
    Add or update an agent-to-user mapping.
    
    Args:
        mapping_data: Mapping details (okta_user_email, wazuh_agent_id, cloud_pc_id, is_vip)
        db: Database session
    
    Returns:
        Created/updated AgentUserMapping record
    """
    try:
        # Check if mapping already exists
        existing = get_mapping_by_agent_id(db, mapping_data.wazuh_agent_id)
        
        if existing:
            # Update existing mapping
            updated = update_mapping(
                db,
                mapping_data.wazuh_agent_id,
                okta_user_email=mapping_data.okta_user_email,
                cloud_pc_id=mapping_data.cloud_pc_id,
                is_vip=mapping_data.is_vip
            )
            print(f"✓ Updated mapping for agent {mapping_data.wazuh_agent_id}: {mapping_data.okta_user_email}")
            return updated
        else:
            # Create new mapping
            new_mapping = create_mapping(
                db,
                mapping_data.okta_user_email,
                mapping_data.wazuh_agent_id,
                mapping_data.cloud_pc_id,
                mapping_data.is_vip
            )
            print(f"✓ Created mapping for agent {mapping_data.wazuh_agent_id}: {mapping_data.okta_user_email}")
            return new_mapping
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to save mapping: {str(e)}")


@app.get("/mappings", response_model=list[AgentUserMappingResponse])
async def get_mappings(db=Depends(get_db)):
    """
    Get all agent-to-user mappings.
    
    Returns:
        List of all AgentUserMapping records
    """
    try:
        from db import get_all_mappings
        mappings = get_all_mappings(db)
        return mappings
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve mappings: {str(e)}")


@app.get("/mappings/{agent_id}", response_model=AgentUserMappingResponse)
async def get_mapping(agent_id: str, db=Depends(get_db)):
    """
    Get a specific agent-to-user mapping by agent ID.
    
    Args:
        agent_id: Wazuh agent ID
    
    Returns:
        AgentUserMapping record for the specified agent
    """
    try:
        from db import get_mapping_by_agent_id
        mapping = get_mapping_by_agent_id(db, agent_id)
        if not mapping:
            raise HTTPException(status_code=404, detail=f"Mapping not found for agent {agent_id}")
        return mapping
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve mapping: {str(e)}")


@app.put("/mappings/{agent_id}", response_model=AgentUserMappingResponse)
async def update_mapping_endpoint(agent_id: str, mapping_data: AgentUserMappingRequest, db=Depends(get_db)):
    """
    Update an existing agent-to-user mapping.
    
    Args:
        agent_id: Wazuh agent ID
        mapping_data: Updated mapping details
    
    Returns:
        Updated AgentUserMapping record
    """
    try:
        from db import update_mapping
        updated = update_mapping(
            db,
            agent_id,
            okta_user_email=mapping_data.okta_user_email,
            cloud_pc_id=mapping_data.cloud_pc_id,
            is_vip=mapping_data.is_vip
        )
        if not updated:
            raise HTTPException(status_code=404, detail=f"Mapping not found for agent {agent_id}")
        print(f"✓ Updated mapping for agent {agent_id}: {mapping_data.okta_user_email}")
        return updated
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to update mapping: {str(e)}")


@app.delete("/mappings/{agent_id}")
async def delete_mapping_endpoint(agent_id: str, db=Depends(get_db)):
    """
    Delete an agent-to-user mapping.
    
    Args:
        agent_id: Wazuh agent ID
    
    Returns:
        Success message
    """
    try:
        from db import delete_mapping
        deleted = delete_mapping(db, agent_id)
        if not deleted:
            raise HTTPException(status_code=404, detail=f"Mapping not found for agent {agent_id}")
        print(f"✓ Deleted mapping for agent {agent_id}")
        return {"message": f"Mapping for agent {agent_id} deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete mapping: {str(e)}")


@app.get("/mappings-ui", response_class=HTMLResponse)
async def mappings_ui(request: Request):
    """
    Serve the mappings management UI.
    
    Returns:
        HTML page for managing agent-user mappings
    """
    return templates.TemplateResponse("mappings.html", {"request": request})
