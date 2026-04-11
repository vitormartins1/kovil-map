from mac_vendor_lookup import MacLookup
import warnings
from app.services.sync_service import SyncService

app_state = {"status": "starting", "message": "Initializing system...", "details": ""}

sync_service = SyncService()
# mac_vendor_lookup currently triggers a Python 3.13 deprecation warning
# on init (asyncio.get_event_loop). Keep behavior and silence only this warning.
with warnings.catch_warnings():
    warnings.filterwarnings(
        "ignore",
        message="There is no current event loop",
        category=DeprecationWarning,
    )
    mac_lookup = MacLookup()
manuf_parser = None
