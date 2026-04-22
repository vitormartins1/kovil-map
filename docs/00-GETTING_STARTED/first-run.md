# First Run & Initial Configuration

Welcome to **KOVIL MAP**. After installation, this guide helps you configure the app and complete your first data import.

## 1. First Launch

When you open the app for the first time:

1. You will see the splash screen while the backend starts.
2. The app creates the local directory structure under `backend/data/` if it does not already exist.
3. The map loads. It may start empty or centered on the default location if no data is available.

If you want to understand the full product loop before importing data, read [Product Overview and Operator Mental Model](product-overview.md).

---

## 2. Essential Settings

Before importing data, configure the external tools.

1. Open **Settings** from the sidebar or top bar.
2. Fill in the tool paths:
   - **Hashcat Path:** absolute path to `hashcat`
   - **HCX Tools Path:** path to `hcxpcapngtool`
   - **Aircrack Path:** optional `aircrack-ng` path
   - **Tshark Path:** optional `tshark` path for fingerprint extraction
3. Configure the remote device connection if you use a Pwnagotchi:
   - **Pwnagotchi Host:** default `10.0.0.2` over USB
   - **User/Pass:** SSH credentials, typically `pi` / `raspberry`
   - **Remote Path:** the folder containing handshakes, usually `/home/pi/handshakes`
4. Click **Save**.

> Tip: on Windows, enable the WSL option if your tools run inside WSL.

---

## 3. Your First Sync

Now import data into the map.

### Option A: Sync from a Pwnagotchi

1. Connect your Pwnagotchi via USB.
2. Wait for the device to finish booting.
3. Click **Sync** in KOVIL MAP.
4. The app will connect over SSH, download `.pcap` and related JSON files, and plot the networks on the map.

### Option B: Import Files Manually

If you already have captures or wardrive CSVs:

1. Copy files into the current source-specific folders:
   - classic Pwnagotchi-style handshakes: `backend/data/handshakes/`
   - Brucegotchi handshakes: `backend/data/BrucePCAP/handshakes/`
   - Bruce RAW captures: `backend/data/BrucePCAP/rawsniffer/`
   - M5 Evil handshakes: `backend/data/m5evil/handshakes/`
   - M5 Evil RAW captures: `backend/data/m5evil/rawsniffer/`
   - WarDrive CSV sessions: `backend/data/wardrive/`
2. Reload the relevant workflow in the app:
   - click **Sync** for handshake catalog reload
   - use the `RAW SNIFFER` panel to extract `raw_*.pcap`
   - refresh the WarDrive workspace for CSV sessions
3. Use [`manual-import-layout.md`](manual-import-layout.md) for the full current folder layout and examples.

---

## 4. Navigating the War Room

Once data is loaded, the map becomes interactive.

For the canonical naming of the current UI surfaces, see [Current Product Surface](current-product-surface.md).

### Tactical Map

- **Clusters:** colored groups represent nearby networks.
- **Pins:**
  - red shield: locked network with a handshake
  - black skull: cracked network
  - blue/green: open network or no handshake
  - purple: wardrive CSV import

### Supporting Panels

- **Zones:** conquered, to-conquer, discovered, and intelligence overlays.
- **Targets:** a temporary mission list for analysis, cracking, or batch work.
- **Favorites:** a persistent shortlist of networks or places worth revisiting.
- **Cracking Operations:** artifact-aware actions for PCAPs, RAW PCAPs, hashes, details, combined candidates, batches, and history.
- **Processes:** long-running sync, scan, analysis, conversion, and cracking progress.
- **Logs:** local feedback for troubleshooting.

### Example Workspace View

The Tactical Map is the default cockpit, but specialized workflows can take over the center view when needed.

![WarDrive workspace replaying a Rio de Janeiro session](../assets/screenshots/wardrive-sessions.gif)

This example shows the current `WARDRIVE` workspace with route replay, active-region context, and the workspace explorer.

---

## 5. Your First Attack

To verify everything works:

1. Find a locked network.
2. Open its popup.
3. Click **Crack**.
4. In the cracking panel:
   - choose **Straight** attack mode
   - pick a wordlist, such as `rockyou.txt`
   - click **Start Cracking**
5. If Hashcat starts and the progress bar moves, the setup is working.

---

## Next Steps

- [Product Overview and Operator Mental Model](product-overview.md)
- [Current Product Surface](current-product-surface.md)
- [Runtime Modes](runtime-modes.md)
- [Map Operations](../07-OPERATIONS/map-operations.md)
- [Workflows by Objective](../07-OPERATIONS/workflows-by-objective.md)
- [Cracking Workflow](../07-OPERATIONS/cracking-workflow.md)
- [Troubleshooting](../07-OPERATIONS/troubleshooting.md)
