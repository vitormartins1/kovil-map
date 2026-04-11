from fastapi import APIRouter
from app.utils.responses import ok
from app.api import deps

router = APIRouter()


@router.get("/api/vendors/{mac}", tags=["Vendors"])
def get_vendor(mac: str, source: str = "maclookup"):
    if source == "manuf":
        if not deps.manuf_parser:
            return ok({"vendor": "Parser Error", "source": "manuf"})
        try:
            vendor = deps.manuf_parser.get_manuf(mac)
            return ok({"vendor": vendor or "Unknown", "source": "manuf"})
        except Exception:
            return ok({"vendor": "Error", "source": "manuf"})
    try:
        vendor = deps.mac_lookup.lookup(mac)
        return ok({"vendor": vendor, "source": "mac-vendor-lookup"})
    except KeyError:
        return ok({"vendor": "Unknown", "source": "mac-vendor-lookup"})
    except Exception:
        return ok({"vendor": "Unknown", "source": "mac-vendor-lookup"})
