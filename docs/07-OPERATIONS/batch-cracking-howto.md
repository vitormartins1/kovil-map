# Batch Cracking How-To

Batch Cracking lets you attack many networks in one Hashcat session.

## How It Works

1. Select multiple `.pcap` or `.22000` files.
2. The backend builds a unified batch file.
3. A manifest maps each hash back to the original network.
4. Hashcat runs once against the batch file.
5. Cracked results are written back to the matching source network.

## Creating a Batch

Use TargetList or multi-select in the frontend, then choose **Create Batch**.

The backend creates:

- a combined `.22000` file
- a companion manifest file

## Tips

- group similar captures when possible
- use TargetList to gather locked networks
- delete the batch file after the run if you no longer need it

## Troubleshooting

- if a network did not enter the batch, check the manifest
- if the batch is empty, the source captures may not contain valid handshake material
