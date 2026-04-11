import json
from pathlib import Path

import pytest

from app.services import data_loader


class TestDataLoaderParsing:
    """
    Testes unitários dedicados à lógica de parsing e ingestão de arquivos do data_loader.
    Cobre arquivos .gps.json, .geo.json e CSV (Wardrive), incluindo casos de erro e edge cases.
    """

    @pytest.fixture
    def mock_env(self, monkeypatch, tmp_path):
        """Configura ambiente mockado para o módulo data_loader."""
        # Configura diretórios reais temporários
        handshakes_dir = tmp_path / "handshakes"
        wardrive_dir = tmp_path / "wardrive"
        bruce_dir = tmp_path / "bruce"

        handshakes_dir.mkdir()
        wardrive_dir.mkdir()
        bruce_dir.mkdir()

        # Mock de caminhos
        monkeypatch.setattr(data_loader, "HANDSHAKES_DIR", str(handshakes_dir))
        monkeypatch.setattr(data_loader, "WARDRIVE_DIR", str(wardrive_dir))
        monkeypatch.setattr(data_loader, "BRUCE_PCAP_DIR", str(bruce_dir))

        # Limpa cache global para evitar contaminação
        monkeypatch.setattr(data_loader, "_DATA_CACHE", None)
        return data_loader

    def test_parse_gps_json_success(self, mock_env):
        """Valida parsing bem-sucedido de arquivo .gps.json (Pwnagotchi)."""
        mac = "001122334455"
        mac_formatted = "00:11:22:33:44:55"
        filename = f"Net_{mac}.gps.json"

        handshakes_dir = Path(mock_env.HANDSHAKES_DIR)
        file_path = handshakes_dir / filename

        content = {
            "Latitude": -22.95,
            "Longitude": -43.18,
            "Altitude": 10,
            "Accuracy": 5.0,
            "Type": "WPA2",
        }
        file_path.write_text(json.dumps(content))

        data = mock_env.load_real_data()

        # Verifica se o ponto foi processado e armazenado
        assert mac_formatted in data
        ap = data[mac_formatted]
        assert ap["lat"] == -22.95
        assert ap["lng"] == -43.18
        assert ap.get("acc") == 5.0

    def test_parse_gps_json_malformed(self, mock_env):
        """Valida resiliência contra JSON malformado (não deve crashar)."""
        filename = "broken.gps.json"
        handshakes_dir = Path(mock_env.HANDSHAKES_DIR)
        file_path = handshakes_dir / filename
        file_path.write_text("{ broken_json: ")

        data = mock_env.load_real_data()

        # Não deve crashar
        # Se não houver outros arquivos, deve ser vazio
        assert "broken" not in str(data)

    def test_parse_geo_json_format(self, mock_env):
        """Valida parsing do formato .geo.json (alternativo do Pwnagotchi)."""
        mac_formatted = "AA:BB:CC:DD:EE:FF"
        mac = mac_formatted.replace(":", "").lower()
        filename = f"Net_{mac}.geo.json"

        handshakes_dir = Path(mock_env.HANDSHAKES_DIR)
        file_path = handshakes_dir / filename

        content = {"lat": -10.0, "lng": -50.0, "accuracy": 20.0}
        file_path.write_text(json.dumps(content))

        data = mock_env.load_real_data()

        assert mac_formatted in data
        ap = data[mac_formatted]
        # Verifica se mapeou corretamente a estrutura aninhada "location"
        assert ap["lat"] == -10.0

    def test_wardrive_csv_parsing(self, mock_env):
        """Valida ingestão de arquivos CSV WiGLE."""
        csv_content = (
            "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"
            "11:22:33:44:55:66,WardriveNet,WPA2,2023-01-01 12:00,11,-70,-23.00,-46.00,0,10,WIFI"
        )

        wardrive_dir = Path(mock_env.WARDRIVE_DIR)
        file_path = wardrive_dir / "wardrive.csv"
        file_path.write_text(csv_content)

        data = mock_env.load_real_data()

        assert "11:22:33:44:55:66" in data
        ap = data["11:22:33:44:55:66"]
        assert ap["ssid"] == "WardriveNet"

    def test_wardrive_csv_with_empty_ssid(self, mock_env):
        """Test CSV parsing with empty SSID field."""
        csv_content = (
            "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"
            "AA:BB:CC:DD:EE:FF,,WPA2,2023-01-01 12:00,11,-70,-23.00,-46.00,0,10,WIFI"
        )
        wardrive_dir = Path(mock_env.WARDRIVE_DIR)
        file_path = wardrive_dir / "wardrive.csv"
        file_path.write_text(csv_content)

        data = mock_env.load_real_data()
        assert "AA:BB:CC:DD:EE:FF" in data

    def test_wardrive_csv_with_invalid_coordinates(self, mock_env):
        """Test CSV parsing with invalid coordinate values."""
        csv_content = (
            "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"
            "11:11:11:11:11:11,InvalidNet,WPA2,2023-01-01 12:00,11,-70,invalid,invalid,0,10,WIFI"
        )
        wardrive_dir = Path(mock_env.WARDRIVE_DIR)
        file_path = wardrive_dir / "wardrive.csv"
        file_path.write_text(csv_content)

        data = mock_env.load_real_data()
        # Should handle gracefully without crashing
        assert isinstance(data, dict)
