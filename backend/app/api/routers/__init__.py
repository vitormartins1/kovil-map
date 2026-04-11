from app.api.routers.health import router as health_router
from app.api.routers.config import router as config_router
from app.api.routers.sync import router as sync_router
from app.api.routers.map import router as map_router
from app.api.routers.zones import router as zones_router
from app.api.routers.vendors import router as vendors_router
from app.api.routers.handshakes import router as handshakes_router
from app.api.routers.files import router as files_router
from app.api.routers.wordlists import router as wordlists_router
from app.api.routers.hashcat import router as hashcat_router
from app.api.routers.aircrack import router as aircrack_router
from app.api.routers.convert import router as convert_router
from app.api.routers.batches import router as batches_router
from app.api.routers.jobs import router as jobs_router
from app.api.routers.history import router as history_router
from app.api.routers.fingerprint import router as fingerprint_router
from app.api.routers.rawsniffer import router as rawsniffer_router
from app.api.routers.data_health import router as data_health_router
from app.api.routers.insights import router as insights_router
from app.api.routers.analytics import router as analytics_router
from app.api.routers.maintenance import router as maintenance_router
from app.api.routers.wardrive import router as wardrive_router
from app.api.routers.recon import router as recon_router
from app.api.routers.probe import router as probe_router
from app.api.routers.analysis import router as analysis_router
from app.api.routers.pmk import router as pmk_router
from app.api.routers.wps import router as wps_router

ALL_ROUTERS = [
    health_router,
    config_router,
    sync_router,
    map_router,
    zones_router,
    vendors_router,
    handshakes_router,
    files_router,
    wordlists_router,
    hashcat_router,
    aircrack_router,
    convert_router,
    batches_router,
    jobs_router,
    history_router,
    fingerprint_router,
    rawsniffer_router,
    data_health_router,
    insights_router,
    analytics_router,
    maintenance_router,
    wardrive_router,
    recon_router,
    probe_router,
    analysis_router,
    pmk_router,
    wps_router,
]
