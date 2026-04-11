# Demo Mode & Mock Data

KOVIL MAP includes a demo mode for developers and new users who want to explore the UI and cracking flows without a real Pwnagotchi or field captures.

## What Is Included

The demo dataset populates the local database with:

- **WiFi networks:** around 50 mock networks spread across a real geographic area for cluster and heatmap testing
- **Handshakes:** valid `.pcap` test files
- **Passwords:** weak passwords such as `password123` and `12345678` so cracking succeeds quickly with demo wordlists
- **Raw data:** `raw_*.pcap` files that simulate Bruce-style raw captures for Raw Sniffer testing

---

## How to Enable It

Use a local backup/restore workflow to switch safely without overwriting your real data.

Make sure the backend is not running, then:

1. Back up the current `backend/data/` directory to a timestamped folder such as `backend/data_backup_TIMESTAMP/`.
2. Clear the active `backend/data/` directory.
3. Copy `backend/mock_data/` into `backend/data/`.
4. Restore a test-friendly `config.json` if needed.

---

## Testing the Demo Data

After enabling demo mode and starting the app:

1. Check that the networks appear on the map and test zoom and clustering.
2. Open a locked network and start a cracking job with a small wordlist.
3. Use **Sync** to confirm the app behaves normally even when no device is connected.

---

## Restoring Your Real Data

1. Remove the contents of `backend/data/`.
2. Copy the most recent `backend/data_backup_XXX` folder back into place.
