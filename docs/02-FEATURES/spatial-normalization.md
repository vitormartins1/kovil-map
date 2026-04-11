# Spatial Normalization

Spatial normalization keeps networks that share the same GPS area readable on the map.

## Why It Exists

Wardrive imports often place many networks at the exact same coordinate. Without normalization they stack on top of each other and become hard to inspect.

## Cluster Jitter

The app spreads networks within a cluster using deterministic jitter so repeated imports stay stable.

- networks are ordered deterministically
- each network gets a slightly different offset
- the spread grows with cluster position

## Deterministic Accuracy

Wardrive CSV data often lacks reliable RSSI values, so the app generates a deterministic accuracy value from the MAC address.

- same MAC produces the same accuracy
- different MACs produce different accuracies
- the range is realistic for consumer GPS data

## Combined Effect

Cluster jitter and deterministic accuracy work together to keep dense wardrive data readable while preserving the original GPS coordinates in the raw fields.

This now applies at both levels used by the workspace:

- network-level display coordinates for the general map dataset
- session-observation display coordinates for session-filtered markers and zone generation

Replay tracks and distance calculations continue to use raw coordinates so the driven path is not visually distorted.

## Related Docs

- [Wardrive Import](wardrive-import.md)
- [Maps by Country Packs](../03-DEVELOPMENT/maps-country-packs.md)
