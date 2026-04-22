import json

from app.tools import analyze_wardrive_density


def test_analyze_wardrive_density_builds_reference_profile(tmp_path):
    csv_path = tmp_path / "wardrive.csv"
    csv_path.write_text(
        (
            "WigleWifi-1.4,appRelease=v1.0,brand=Bruce\n"
            "MAC,SSID,AuthMode,FirstSeen,LastSeen,Channel,Frequency,RSSI,"
            "CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"
            "02:11:22:33:44:55,DEMO_1,[WPA2-PSK-CCMP][ESS],2026-04-11T00:00:00Z,"
            "2026-04-11T00:00:10Z,1,2412,-61,-22.900000,-43.180000,5,4,WIFI\n"
            "06:11:22:33:44:56,DEMO_2,[WPA2-PSK-CCMP][ESS],2026-04-11T00:00:00Z,"
            "2026-04-11T00:00:10Z,6,2437,-71,-22.900000,-43.180000,5,4,WIFI\n"
            "0A:11:22:33:44:57,DEMO_3,[WPA3-SAE-CCMP][ESS],2026-04-11T00:00:00Z,"
            "2026-04-11T00:00:10Z,11,2462,-81,-22.900000,-43.180000,5,4,WIFI\n"
            "0E:11:22:33:44:58,DEMO_4,[OPEN],2026-04-11T00:00:11Z,"
            "2026-04-11T00:00:21Z,1,2412,-67,-22.899970,-43.179970,5,4,WIFI\n"
            "12:11:22:33:44:59,DEMO_5,[OPEN],2026-04-11T00:00:22Z,"
            "2026-04-11T00:00:32Z,6,2437,-74,-22.899940,-43.179940,5,4,WIFI\n"
        ),
        encoding="utf-8",
    )

    payload = analyze_wardrive_density.analyze_wardrive_density(csv_path)

    assert payload["valid_rows"] == 5
    assert payload["valid_unique_points"] == 3
    assert payload["unique_bssids"] == 5
    assert payload["rows_per_point"] == 1.67
    assert payload["max_same_gps"] == 3
    assert payload["channels"] == {"1": 2, "6": 2, "11": 1}
    assert payload["bands"] == {"2.4GHz": 5}
    assert payload["step_distance_m"]["median"] > 0

    output_path = tmp_path / "density_profile.json"
    output_path.write_text(json.dumps(payload, ensure_ascii=True), encoding="utf-8")
    assert json.loads(output_path.read_text(encoding="utf-8"))["valid_rows"] == 5
