# fastapi_app/main.py
import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

import aiofiles
from elasticsearch import AsyncElasticsearch, NotFoundError
from fastapi import FastAPI, BackgroundTasks, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from models import ESConfig
from ml_models import predict

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
            sort=[{"@timestamp": "asc"}],
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

            enriched_alert = {
                "original_alert": original_alert,
                "ai_severity": result["severity_level"],
                "severity_label": result["severity_label"],
                "is_anomaly": result["is_anomaly"],
                "original_alert_ref_id": original_alert_id,
                "@timestamp": original_alert.get("@timestamp")
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
    return templates.TemplateResponse("index.html", {"request": request})

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
