import glob
import os
import logging

from app.core.config import HANDSHAKES_DIR
from app.services.data_loader import reload_data
from app.services.rawsniffer_service import rawsniffer_service
from app.services.analytics_service import analytics_service
from app.services.demo_data_service import demo_data_service
from app.services.packet_analysis_service import packet_analysis_service
from app.services.probe_service import probe_service
from app.services.recon_runtime_service import clear_recon_runtime_cache
from app.services.wardrive_regions_service import wardrive_regions_service

logger = logging.getLogger(__name__)


def _clear_recon_runtime_cache() -> None:
    try:
        clear_recon_runtime_cache()
    except Exception:
        logger.exception("Failed to clear Recon runtime cache")


class MaintenanceService:
    def get_demo_status(self) -> dict:
        return demo_data_service.get_status()

    def start_demo_install(
        self,
        *,
        profile_id: str = "showcase-core-v1",
        frontend_state: dict | None = None
    ) -> dict:
        return demo_data_service.start_install(
            profile_id=profile_id,
            frontend_state=frontend_state,
        )

    def start_demo_remove(self) -> dict:
        return demo_data_service.start_remove()

    def clear_details_files(self) -> dict:
        deleted = 0
        failed = 0

        pattern = os.path.join(HANDSHAKES_DIR, "*.details")
        for details_path in glob.glob(pattern):
            try:
                os.remove(details_path)
                deleted += 1
            except Exception:
                failed += 1
                logger.exception("Failed to delete details file: %s", details_path)

        analytics_service.clear_cache()
        reload_data()
        wardrive_regions_service.clear_runtime_cache()
        _clear_recon_runtime_cache()
        return {
            "deleted_count": deleted,
            "failed_count": failed,
        }

    def clear_cache(self) -> dict:
        raw_meta = rawsniffer_service.clear_metadata_cache(remove_files=True)
        analytics_service.clear_cache()
        probe_service.invalidate_cache()
        packet_analysis_service.invalidate_cache()
        reload_data()
        wardrive_regions_service.clear_runtime_cache()
        _clear_recon_runtime_cache()
        return {
            "raw_metadata_deleted_count": int(raw_meta.get("deleted_count", 0)),
            "raw_metadata_failed_count": int(raw_meta.get("failed_count", 0)),
            "data_cache_reloaded": True,
            "analytics_cache_cleared": True,
            "probe_cache_cleared": True,
            "packet_analysis_cache_cleared": True,
            "recon_runtime_cache_cleared": True,
        }


maintenance_service = MaintenanceService()
