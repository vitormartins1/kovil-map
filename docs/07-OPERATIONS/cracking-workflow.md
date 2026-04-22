# Cracking Workflow

This workflow covers the path from a captured handshake to a cracked password.

## Prerequisites

- Hashcat configured in Settings
- up-to-date GPU drivers
- one or more wordlists

## Workflow

1. Select a target from the map, No-GPS workspace, Targets, Batch, Raw Sniffer, or a handshake-set file list.
2. Open Cracking Operations.
3. Review source/device grouping, preferred capture quality, sidecars, attack hints, and history.
4. Let the app convert `.pcap` to `.22000` if needed.
5. Choose an attack mode:
   - Aircrack-ng for quick CPU validation
   - Hashcat Straight, Combinator, Mask, or Association
   - PMK database when you want precomputed SSID+wordlist acceleration
   - WPS attack when the target has WPS evidence and the required external tool is configured
6. Start the job and monitor progress in the Process panel.

## Success Path

When a password is found:

- the map marker updates
- the password is stored
- the popup shows the cracked result

## Special Modes

Use Association mode when the password likely comes from local context such as names, streets, or businesses.

## Batch Cracking

Use TargetList to group targets and create a batch job when you want to attack many networks at once.

## RAW and Combined Candidates

Cracking Operations can also target RAW-derived and combined artifacts:

- RAW PCAP rows expose details extraction, hash generation, and canonical WDRS preparation.
- RAW `.22000` rows can be cracked directly.
- Combined candidates merge eligible same-BSSID captures into a manual one-BSSID candidate without changing the default preferred capture.

## Troubleshooting

- no valid handshake: the capture is incomplete or corrupted
- Hashcat error 255: check drivers and paths
- exhausted: try a different wordlist or mask
