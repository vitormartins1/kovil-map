# Batch Cracking

Batch Cracking is the high-throughput mode in KOVIL MAP. It lets you attack dozens or hundreds of WiFi networks without paying the startup cost of launching the cracking engine once per target.

## Goal

In wardriving or large pentest operations, you may collect hundreds of handshakes. Attacking them one by one is inefficient because Hashcat spends time initializing the GPU kernel for each job.

Batch Cracking solves this by aggregating many targets into one work package so Hashcat only starts once and attacks all hashes in parallel.

---

## Batch Architecture

The workflow follows three stages: **Aggregation → Execution → Distribution**.

### 1. Aggregation

The backend receives a list of `.pcap` or `.22000` files, extracts valid hashes with `hcxpcapngtool`, and concatenates them into a single master file such as `batch_TIMESTAMP_ID.22000`.

### 2. Manifest

To keep track of which hash belongs to which network, the system generates a companion manifest file.

```json
{
  "batch_id": "batch_1715000000_abc",
  "items": [
    {
      "original_filename": "Network_A.pcap",
      "mac": "11:22:33:44:55:66",
      "hash_line": "WPA*02*..."
    },
    {
      "original_filename": "Network_B.pcap",
      "mac": "AA:BB:CC:DD:EE:FF",
      "hash_line": "WPA*02*..."
    }
  ]
}
```

### 3. Atomic Execution

Hashcat runs against the `batch_*.22000` file. From the cracking engine's perspective, it is the same as cracking a single file with multiple hashes. Wordlists, masks, rules, and other modes work as expected.

### 4. Result Distribution

The `JobManager` monitors the output in real time. When a password is cracked (`HASH:PASSWORD`), the system:

1. Looks up the hash in the manifest
2. Identifies the original file
3. Stores the result next to the source capture
4. Updates the map status to **Pwned**

---

## Key Benefits

- **GPU efficiency:** avoids GPU warm-up between targets
- **Organization:** results stay separated by network even during group attacks
- **Resilience:** interrupted batches can be resumed later

---

## Cracking Operations Summary (Batch File Selected)

When a `batch_*.22000` file is selected inside Cracking Operations, the handshake summary is batch-content oriented and no longer mirrors source-family tags from single-network views.

Current summary focuses on manifest-derived counters:

- total items
- handshake OK
- EAPOL missing
- invalid
- cracked

This keeps the operator focused on batch quality and triage status before starting or retrying attacks.

---

## See Also

- Batch Cracking How-To
- TargetList & Favorites
- Cracking Engine
