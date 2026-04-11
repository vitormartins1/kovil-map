# Runtime Data

This directory is the local runtime data root used by KOVIL MAP.

## What is versioned

The public repository only keeps safe, reusable assets here, such as curated
map packs or other demo-safe resources that are intentionally published.

## What is not versioned

Operational artifacts should stay local and must not be committed, including:

- handshake captures and derived cracking artifacts
- RAW sniffer captures and metadata
- Wardrive CSV sessions and merge outputs
- cracked results, GPS sidecars, and sync caches
- personal notes, logs, and local analysis exports

## Publishing Rule

Before publishing or sharing a branch, verify that this directory does not
contain real captures, credentials, or other sensitive data in tracked files.
