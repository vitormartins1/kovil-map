# Cracking Workflow

This workflow covers the path from a captured handshake to a cracked password.

## Prerequisites

- Hashcat configured in Settings
- up-to-date GPU drivers
- one or more wordlists

## Workflow

1. Select a target from the map or the Handshakes list.
2. Open the cracking panel.
3. Let the app convert `.pcap` to `.22000` if needed.
4. Review the attack hints and quality checks.
5. Choose an attack mode:
   - Aircrack-ng for quick CPU validation
   - Hashcat Straight, Combinator, Mask, or Association
6. Start the job and monitor progress in the active processes panel.

## Success Path

When a password is found:

- the map marker updates
- the password is stored
- the popup shows the cracked result

## Special Modes

Use Association mode when the password likely comes from local context such as names, streets, or businesses.

## Batch Cracking

Use TargetList to group targets and create a batch job when you want to attack many networks at once.

## Troubleshooting

- no valid handshake: the capture is incomplete or corrupted
- Hashcat error 255: check drivers and paths
- exhausted: try a different wordlist or mask
