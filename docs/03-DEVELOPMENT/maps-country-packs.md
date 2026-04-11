# Maps by Country Packs

WarDrive uses a country-pack layout for map datasets.

## Goal

The backend can discover countries, understand hierarchy levels, and choose the deepest available region without country-specific code.

## Expected Structure

```text
backend/data/maps/
  br/
    country.json
    layers/
      01-state/
        <dataset>/
          metadata.json
      02-city/
        <dataset>/
          metadata.json
      03-neighborhood/
        <dataset>/
          metadata.json
      04-sector/
        <dataset>/
          metadata.json
  _legacy/
```

## `country.json`

Defines the country code, display name, default locale, and labels for the hierarchy.

## `metadata.json`

Each dataset has its own manifest that declares:

- whether it is enabled
- its priority
- its level key and label
- the source and version
- the geometry format and CRS
- the fields used for IDs, names, and parent resolution

## Parent Resolution

Datasets can declare how they link to the parent level using `parent_resolvers`.

## Administrative vs Fallback Layers

- **Administrative** layers are the normal hierarchy shown in the UI.
- **Fallback** layers are deeper classifications used when a country or region does not have a better administrative match.

## Adding a New Country

1. Create `backend/data/maps/<country_code>/`.
2. Add `country.json`.
3. Add layered datasets under `layers/`.
4. Provide a `metadata.json` file for each dataset.
5. Keep legacy data outside the canonical structure.
