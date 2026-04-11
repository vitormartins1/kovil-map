from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import uvicorn
import asyncio
import atexit
import os
from manuf import MacParser

from app.core.job_manager import job_manager
from app.core.auth import is_api_token_enabled, is_http_request_authorized, is_packaged_runtime
from app.api import deps
from app.api.routers import ALL_ROUTERS
from app.api.ws.handlers import router as ws_router, job_event_callback
from app.utils.responses import http_exception_handler, unhandled_exception_handler

# --- CLEANUP HANDLER ---

def cleanup_processes():
    print("Encerrando processos filhos...")
    job_manager.kill_all()


atexit.register(cleanup_processes)


def _env_flag_enabled(name: str) -> bool:
    value = str(os.environ.get(name, "") or "").strip().lower()
    return value in {"1", "true", "yes", "on"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Define o loop principal no JobManager para eventos thread-safe
    job_manager.set_main_loop(asyncio.get_running_loop())

    deps.app_state["status"] = "loading_db"

    try:
        deps.app_state["message"] = "Initializing MacLookup..."
        # deps.mac_lookup.update_vendors()
    except Exception as e:
        print(f"Erro MacLookup: {e}")

    try:
        deps.app_state["message"] = "Loading Wireshark Manuf DB..."
        try:
            deps.manuf_parser = MacParser(update=False)
        except FileNotFoundError:
            deps.app_state["message"] = "Downloading Manuf DB (First Run)..."
            deps.manuf_parser = MacParser(update=True)
    except Exception as e:
        print(f"Erro crítico no Manuf: {e}")
        deps.app_state["details"] = f"Manuf Error: {str(e)}"

    deps.app_state["message"] = "Building Data Cache..."
    try:
        from app.services.data_loader import reload_data
        reload_data()
        print("Cache de dados construído com sucesso.")
    except Exception as e:
        print(f"Erro ao construir cache inicial: {e}")

    deps.app_state["status"] = "ready"
    deps.app_state["message"] = "System Ready"
    print("Startup concluído.")

    yield
    print("Desligando...")


openapi_tags = [
    {"name": "Health", "description": "Healthcheck and backend status"},
    {"name": "Config", "description": "Configuration management"},
    {"name": "Sync", "description": "Pwnagotchi sync operations"},
    {"name": "Map", "description": "Map data"},
    {"name": "Zones", "description": "Zone generation"},
    {"name": "Vendors", "description": "MAC vendor lookup"},
    {"name": "Geolocation", "description": "Backend geolocation"},
    {"name": "Handshakes", "description": "Handshake file discovery"},
    {"name": "Files", "description": "File access"},
    {"name": "Wordlists", "description": "Custom wordlists"},
    {"name": "Hashcat", "description": "Hashcat resources and jobs"},
    {"name": "Aircrack", "description": "Aircrack-ng jobs"},
    {"name": "Convert", "description": "HCX conversions"},
    {"name": "Batches", "description": "Batch (multi) files"},
    {"name": "Jobs", "description": "Job management"},
    {"name": "History", "description": "History cleanup"},
    {"name": "Fingerprint", "description": "Passive fingerprint extraction from PCAPs"},
    {"name": "RawSniffer", "description": "Bruce raw sniffer PCAP analysis"},
    {"name": "DataHealth", "description": "Dataset quality and diagnostics summary"},
    {"name": "Insights", "description": "Attack score, recommendations and quality gate"},
    {"name": "Analytics", "description": "Geospatial tactical analytics and heatmaps"},
    {"name": "Maintenance", "description": "Maintenance cleanup operations"},
    {"name": "WarDrive", "description": "WarDrive regional hierarchy and zones"},
]

app = FastAPI(title="KOVIL MAP Desktop Backend", lifespan=lifespan, openapi_tags=openapi_tags)
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)
job_manager.set_event_callback(job_event_callback)


@app.middleware("http")
async def local_api_auth_middleware(request: Request, call_next):
    path = request.url.path

    if request.method == "OPTIONS":
        return await call_next(request)
    if not path.startswith("/api"):
        return await call_next(request)
    if path == "/api/health":
        return await call_next(request)
    if not is_api_token_enabled():
        return await call_next(request)
    if not is_http_request_authorized(request):
        return JSONResponse(
            status_code=401,
            content={"status": "error", "error": {"message": "Unauthorized"}},
        )

    return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["null"],
    allow_origin_regex=(
        r"^https?://(127\.0\.0\.1|localhost)(:\d+)?$"
        if (not is_packaged_runtime() or _env_flag_enabled("KOVIL_ALLOW_LOCALHOST_CORS"))
        else None
    ),
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ws_router)
for r in ALL_ROUTERS:
    app.include_router(r)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
