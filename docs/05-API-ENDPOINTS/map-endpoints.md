# Map and Supporting Data Endpoints

These endpoints feed the main map and its supporting overlays.

Base path:

```text
/api
```

## `GET /api/map/data`

Returns the main in-memory dataset used by the map.

This payload is the authoritative source for:

- network markers
- popup state inputs
- source flags
- GPS / display coordinates
- derived metadata merged by the backend

## `POST /api/zones`

Runs point clustering for generic zone generation.

Typical body:

```json
{
  "eps_m": 200,
  "min_samples": 3,
  "points": [
    { "lat": -22.9, "lng": -43.2, "acc": 12.5 }
  ]
}
```

## `POST /api/zones/to-conquer`

Builds the to-conquer overlay from conquered and unconquered point sets.

## `GET /api/vendors/{mac}`

Returns vendor/OUI information for a MAC address.

Query parameter:

- `source`: usually `maclookup` or `manuf`

## Notes

- the legacy public geolocation endpoint is not part of the current mounted map router surface
- WarDrive region overlays use their own router family under `/api/wardrive/*` rather than this generic map router
