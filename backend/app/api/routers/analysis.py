"""Advanced Packet Analysis router.

Exposes endpoints for deep PCAP analysis — deauthentication attacks,
disassociation frames, and 802.11 threat indicators.  Feeds the INTEL
tab's threat analysis section in the Recon Center.
"""

from __future__ import annotations

from fastapi import APIRouter, Query

from app.services.packet_analysis_service import packet_analysis_service
from app.jobs.recon_jobs import start_deep_analysis_job
from app.utils.responses import fail, ok

router = APIRouter()


@router.get("/api/recon/deep-analysis", tags=["Recon"])
def get_deep_analysis(
    limit: int = Query(default=200, ge=1, le=1000),
):
    """Aggregate deauth/disassoc threat intelligence across all PCAPs."""
    result = packet_analysis_service.analyse(limit=limit)
    return ok(result)


@router.get("/api/recon/deep-analysis/status", tags=["Recon"])
def get_deep_analysis_status():
    """Return cached deep-analysis result and staleness info (fast)."""
    status = packet_analysis_service.get_cache_status()
    return ok(status)


@router.post("/api/recon/deep-analysis/scan", tags=["Recon"])
def start_deep_analysis_scan(
    limit: int = Query(default=200, ge=1, le=1000),
):
    """Start a background deep-analysis scan job.  Returns job_id."""
    pcaps = packet_analysis_service._find_pcaps()
    if not pcaps:
        return ok({"job_id": None, "pcap_count": 0})
    job_id = start_deep_analysis_job(pcaps, limit=limit)
    return ok({"job_id": job_id, "pcap_count": len(pcaps)})


@router.get("/api/recon/deep-analysis/pcap", tags=["Recon"])
def get_deep_analysis_pcap(
    path: str = Query(..., min_length=1),
    limit: int = Query(default=200, ge=1, le=1000),
):
    """Deep analysis of a specific PCAP file."""
    import os

    if not os.path.isfile(path):
        return fail("PCAP file not found")
    result = packet_analysis_service.analyse_pcap(path, limit=limit)
    return ok(result)
