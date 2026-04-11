# Troubleshooting Guide

This guide summarizes the most common fixes for startup, cracking, sync, and cache issues.

## Frontend and Startup

- **Backend Busy / infinite loading** - the backend did not start correctly or the port is busy
- **Gray map** - base map tiles could not be loaded
- **HTTP 401** - token mismatch between the backend and the frontend

## Cracking and Tools

- **Hashcat fails to start** - check the executable path and GPU drivers
- **`.cracked` results do not appear** - check the output format and backend logs
- **Association mode produces no candidates** - preview candidates and provide better hints

## Sync

- **Connection refused or timeout** - check the remote host, USB networking, and firewall
- **Authentication failed** - verify the SSH credentials

## Data and Cache

- **Counters do not update** - run Sync and refresh the frontend
- **RAW files do not appear** - check the Processes panel and wait for extraction jobs
