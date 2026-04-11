# TargetList & Favorites

KOVIL MAP includes two lightweight organization tools that help you manage hundreds or thousands of networks without losing focus.

## Overview

In large wardriving or pentest operations, most discovered access points are not equally relevant.

- **Favorites (⭐):** a permanent shortcut list for networks or locations you want to revisit quickly
- **TargetList (🎯):** a temporary mission list for networks you plan to attack, analyze, or export in bulk

---

## Features

### Favorites

- **Persistence:** stored permanently in the user configuration
- **Visual marker:** shown as a star in lists and highlighted in the map UI where available
- **Purpose:** quick access and a lightweight safety net against accidental removal

### TargetList

- **Workflow-oriented:** add a network, run a batch action, then clear the list when finished
- **Cracking integration:** serves as the main source for Batch Cracking
- **Map emphasis:** targets can be highlighted visually on the map

---

## How to Use

### 1. Adding Networks

#### From the map popup

1. Click any network pin.
2. Use the **Favorite** or **Target** action in the popup.
3. The icon changes state immediately.

#### From side lists

1. Open the Networks, Handshakes, or Cracked list.
2. Hover or select a row.
3. Use the action buttons on the right side of the row.

### 2. Managing the Lists

Open the **Lists** area in the left sidebar or main menu.

- **Targets tab:** shows all selected targets
  - **Crack All** or **Create Batch** sends the selected networks to the cracking engine in one step
  - **Clear List** removes the target tag without deleting the underlying data
- **Favorites tab:** manages the permanent favorite list

---

## Integration with Batch Cracking

TargetList pairs naturally with [Batch Cracking](batch-cracking.md).

Typical workflow:

1. Browse the map or the Handshakes list.
2. Add 10-20 interesting networks to TargetList.
3. Open the TargetList tab.
4. Click **Create Batch from Targets**.
5. The system groups the matching handshakes into a single `.22000` file.
6. Start Hashcat once and attack them together.

---

## Data Persistence

- **Where is it stored?**
  - the frontend state is managed by `state.js`
  - the backend keeps the durable data in files such as `targets.json` and `favorites.json` under `backend/data/`
- **Backup:** backing up `backend/data/` preserves the lists
