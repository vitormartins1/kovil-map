import csv

from app.tools import import_wigle_route_source


def test_sanitize_wigle_route_keeps_only_route_columns(tmp_path):
    source = tmp_path / "wigle.csv"
    source.write_text(
        "WigleWifi-1.4,appRelease=1.0\n"
        "MAC,SSID,AuthMode,FirstSeen,LastSeen,Channel,Frequency,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"
        "AA:BB:CC:DD:EE:FF,REAL_ONE,[WPA2-PSK-CCMP][ESS],2026-04-10 10:00:00,2026-04-10 10:00:03,6,2437,-55,-22.970000,-43.182000,8,4.2,WIFI\n"
        "AA:BB:CC:DD:EE:11,REAL_TWO,[WPA2-PSK-CCMP][ESS],2026-04-10 10:00:10,2026-04-10 10:00:14,11,2462,-52,-22.970800,-43.183200,8,4.4,WIFI\n",
        encoding="utf-8",
    )
    output = tmp_path / "route.csv"

    count = import_wigle_route_source.sanitize_wigle_route(source, output)

    assert count == 2
    with output.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["timestamp"] == "2026-04-10T10:00:03Z"
    assert rows[1]["timestamp"] == "2026-04-10T10:00:14Z"
    assert list(rows[0].keys()) == list(import_wigle_route_source.ROUTE_COLUMNS)
    assert rows[0]["lat"] == "-22.97"
    assert rows[0]["lng"] == "-43.182"
