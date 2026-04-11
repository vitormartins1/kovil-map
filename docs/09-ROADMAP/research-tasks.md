# Research Tasks & Investigations

This page lists technical spikes and proof-of-concept work that would unblock roadmap items.

## Performance and Scalability

### 1. Hashcat GPU clustering

- how to split keyspace with `--keyspace`, `--limit`, and `--skip`
- what the network overhead looks like for small versus large chunks
- target outcome: a script that splits a wordlist across three local terminals

### 2. Map rendering with WebGL

- evaluate `deck.gl` or `pixi.js` overlays
- compare Leaflet rendering to WebGL at high point counts

## AI and Intelligence

### 3. Password patterns by geolocation

- investigate whether SSID patterns correlate with password patterns
- prototype a lightweight model for mask suggestions

### 4. Automatic device classification

- determine which Beacon frame fields can identify device families beyond the OUI
- build a script that classifies devices from PCAPs with high accuracy

## Distributed Systems

### 5. State synchronization

- evaluate CRDTs such as Yjs or Automerge
- prototype collaborative state handling for map and list editing

### 6. P2P discovery and encryption

- evaluate mDNS/Zeroconf and WebRTC data channels for local discovery

## Mobile and Hardware

### 7. Bluetooth control for headless mode

- expose a Bluetooth control API on Linux
- measure the practical bandwidth for map updates

### 8. SDR integration

- evaluate SDR support for BLE or Zigbee mapping

## Security Research

### 9. Sandbox for Python plugins

- isolate third-party code without exposing the full filesystem or network
- compare WebAssembly and process isolation

## How to Contribute

1. Pick a topic
2. Open an issue with the `research` tag
3. Share findings in the issue
4. Help define the implementation spec
