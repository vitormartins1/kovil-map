"""Background jobs for Recon Center heavy analysis.

Provides workers for probe-intel (SIGINT tab) and deep-analysis (INTEL tab)
that run via ``job_manager.start_multi_job`` with per-PCAP progress emission.
"""

from __future__ import annotations

from app.core.job_manager import job_manager
from app.services.probe_service import probe_service
from app.services.packet_analysis_service import packet_analysis_service


# ------------------------------------------------------------------
# Probe Intelligence (SIGINT tab)
# ------------------------------------------------------------------

def _probe_intel_worker(job, emit):
    """Process all PCAPs for probe-request intelligence."""
    pcaps = job.get("meta", {}).get("pcaps", [])
    limit = job.get("meta", {}).get("limit", 200)
    result = probe_service.analyse_with_progress(
        pcaps, limit=limit, emit=emit, job=job,
    )
    job["meta"]["result"] = result


def start_probe_intel_job(pcaps: list[str], limit: int = 200) -> str | None:
    """Launch a background probe-intel scan.  Returns job_id."""
    if not pcaps:
        return None
    return job_manager.start_multi_job(
        _probe_intel_worker,
        job_type="probe_intel_scan",
        total_steps=len(pcaps),
        meta={"pcaps": pcaps, "limit": limit},
    )


# ------------------------------------------------------------------
# Deep Analysis (INTEL tab)
# ------------------------------------------------------------------

def _deep_analysis_worker(job, emit):
    """Process all PCAPs for deauth/disassoc threat intelligence."""
    pcaps = job.get("meta", {}).get("pcaps", [])
    limit = job.get("meta", {}).get("limit", 200)
    result = packet_analysis_service.analyse_with_progress(
        pcaps, limit=limit, emit=emit, job=job,
    )
    job["meta"]["result"] = result


def start_deep_analysis_job(pcaps: list[str], limit: int = 200) -> str | None:
    """Launch a background deep-analysis scan.  Returns job_id."""
    if not pcaps:
        return None
    return job_manager.start_multi_job(
        _deep_analysis_worker,
        job_type="deep_analysis_scan",
        total_steps=len(pcaps),
        meta={"pcaps": pcaps, "limit": limit},
    )
