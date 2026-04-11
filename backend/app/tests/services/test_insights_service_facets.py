import pytest
from app.services import insights_service as is_module
from app.services import history_service as hs_module
from app.core import config as config_module


class TestInsightsServiceHelpers:
    """Tests for insights_service helper methods."""

    def test_normalize_mac_various_formats(self):
        """_normalize_mac handles different MAC formats."""
        svc = is_module.insights_service
        assert svc._normalize_mac("aabb.ccdd.eeff") == "AA:BB:CC:DD:EE:FF"
        assert svc._normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
        assert svc._normalize_mac("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF"
        assert svc._normalize_mac("") is None
        assert svc._normalize_mac(None) is None
        assert svc._normalize_mac("invalid") is None

    def test_mac_to_clean(self):
        """_mac_to_clean converts MAC to clean lowercase without colons."""
        svc = is_module.insights_service
        assert svc._mac_to_clean("AA:BB:CC:DD:EE:FF") == "aabbccddeeff"
        assert svc._mac_to_clean(None) is None

    def test_extract_mac_from_filename(self):
        """_extract_mac_from_filename extracts MAC from various filenames."""
        svc = is_module.insights_service
        assert (
            svc._extract_mac_from_filename("HS_AABBCCDDEEFF_1.pcap")
            == "AA:BB:CC:DD:EE:FF"
        )
        assert (
            svc._extract_mac_from_filename("test_AABBCCDDEEFF.pcap")
            == "AA:BB:CC:DD:EE:FF"
        )
        assert svc._extract_mac_from_filename(None) is None
        assert svc._extract_mac_from_filename("no_mac_here.txt") is None

    def test_safe_load_json(self, tmp_path):
        """_safe_load_json handles valid and invalid JSON."""
        svc = is_module.insights_service
        valid = tmp_path / "valid.json"
        valid.write_text('{"key": "value"}', encoding="utf-8")
        assert svc._safe_load_json(str(valid)) == {"key": "value"}

        invalid = tmp_path / "invalid.json"
        invalid.write_text("{bad json", encoding="utf-8")
        assert svc._safe_load_json(str(invalid)) is None

        assert svc._safe_load_json("/nonexistent/path.json") is None

    def test_parse_sortable_iso(self):
        """_parse_sortable_iso parses various ISO formats."""
        svc = is_module.insights_service
        assert svc._parse_sortable_iso("2026-03-16T12:00:00Z") > 0
        assert svc._parse_sortable_iso("2026-03-16T12:00:00") > 0
        assert svc._parse_sortable_iso("") == 0.0
        assert svc._parse_sortable_iso(None) == 0.0
        assert svc._parse_sortable_iso("invalid") == 0.0

    def test_priority_from_score(self):
        """_priority_from_score returns correct priority."""
        svc = is_module.insights_service
        assert svc._priority_from_score(90) == "high"
        assert svc._priority_from_score(70) == "high"
        assert svc._priority_from_score(50) == "medium"
        assert svc._priority_from_score(45) == "medium"
        assert svc._priority_from_score(20) == "low"

    def test_is_hashcat_history_entry(self):
        """_is_hashcat_history_entry identifies hashcat entries."""
        svc = is_module.insights_service
        assert svc._is_hashcat_history_entry({"tool": "hashcat"}) is True
        assert svc._is_hashcat_history_entry({"tool": "aircrack"}) is False
        assert (
            svc._is_hashcat_history_entry({"command": ["hashcat", "-m", "22000"]})
            is True
        )
        assert svc._is_hashcat_history_entry({"command": "hashcat -m 22000"}) is True
        assert svc._is_hashcat_history_entry({}) is False

    def test_extract_attempt_mode(self):
        """_extract_attempt_mode extracts attack mode from entry."""
        svc = is_module.insights_service
        assert (
            svc._extract_attempt_mode({"params": {"attack_mode": "straight"}})
            == "straight"
        )
        assert (
            svc._extract_attempt_mode({"command": ["hashcat", "-a", "0", "hash"]})
            == "straight"
        )
        assert (
            svc._extract_attempt_mode({"command": ["hashcat", "-a", "3", "hash"]})
            == "mask"
        )
        assert svc._extract_attempt_mode({}) == "unknown"

    def test_normalize_attempt_outcome(self):
        """_normalize_attempt_outcome normalizes status strings."""
        svc = is_module.insights_service
        assert svc._normalize_attempt_outcome({"status": "CRACKED"}) == "cracked"
        assert svc._normalize_attempt_outcome({"status": "EXHAUSTED"}) == "exhausted"
        assert svc._normalize_attempt_outcome({"status": "FAILED"}) == "fatal"
        assert svc._normalize_attempt_outcome({"status": "RUNNING"}) == "running"
        assert (
            svc._normalize_attempt_outcome(
                {"status": "SUCCESS", "result": "password found"}
            )
            == "cracked"
        )
        assert (
            svc._normalize_attempt_outcome({"status": "SUCCESS", "result": "done"})
            == "other"
        )
        assert svc._normalize_attempt_outcome({}) == "other"

    def test_sanitize_attempt_param_value(self):
        """_sanitize_attempt_param_value sanitizes various values."""
        svc = is_module.insights_service
        assert svc._sanitize_attempt_param_value(None) is None
        assert svc._sanitize_attempt_param_value(True) is True
        assert svc._sanitize_attempt_param_value(42) == 42
        assert svc._sanitize_attempt_param_value("") is None
        assert svc._sanitize_attempt_param_value("/path/to/file.txt") == "file.txt"
        assert svc._sanitize_attempt_param_value("a;b;c") == "a;b;c"
        long_text = "x" * 100
        result = svc._sanitize_attempt_param_value(long_text)
        assert len(result) <= 90

    def test_compact_attempt_params(self):
        """_compact_attempt_params compacts and sanitizes params."""
        svc = is_module.insights_service
        assert svc._compact_attempt_params(None) == {}
        assert svc._compact_attempt_params({}) == {}
        result = svc._compact_attempt_params(
            {"workload": 1024, "wordlist": "/path/wordlist.txt"}
        )
        assert result["workload"] == 1024
        assert result["wordlist"] == "wordlist.txt"

    def test_build_attempt_tip(self):
        """_build_attempt_tip returns tips based on totals."""
        svc = is_module.insights_service
        assert svc._build_attempt_tip({"attempts": 0}, []) is None
        assert (
            "fatal"
            in svc._build_attempt_tip(
                {"attempts": 5, "fatal": 3, "exhausted": 0, "cracked": 0}, []
            ).lower()
        )
        assert (
            "exhausted"
            in svc._build_attempt_tip(
                {"attempts": 5, "fatal": 0, "exhausted": 3, "cracked": 0}, []
            ).lower()
        )
        assert (
            "no successful"
            in svc._build_attempt_tip(
                {"attempts": 5, "fatal": 0, "exhausted": 0, "cracked": 0}, []
            ).lower()
        )


class TestInsightsServiceContext:
    """Tests for insights_service context building."""

    def test_resolve_hash_path_nonexistent(self, tmp_path, monkeypatch):
        """_resolve_hash_path returns None for nonexistent files."""
        monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(tmp_path))
        svc = is_module.insights_service
        assert svc._resolve_hash_path("nonexistent.22000") is None
        assert svc._resolve_hash_path(None) is None

    def test_resolve_hash_path_absolute(self, tmp_path, monkeypatch):
        """_resolve_hash_path handles absolute paths."""
        monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(tmp_path))
        hash_file = tmp_path / "test.22000"
        hash_file.write_text("WPA*02*x*x*x*x*00", encoding="utf-8")
        svc = is_module.insights_service
        result = svc._resolve_hash_path(str(hash_file))
        assert result == str(hash_file)

    def test_find_matching_paths(self, tmp_path, monkeypatch):
        """_find_matching_paths finds files by token and suffix."""
        monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(tmp_path))
        (tmp_path / "test_aabbccddeeff.details").write_text("{}", encoding="utf-8")
        (tmp_path / "other_aabbccddeeff.details").write_text("{}", encoding="utf-8")
        svc = is_module.insights_service
        matches = svc._find_matching_paths("aabbccddeeff", ".details")
        assert len(matches) == 2

    def test_find_details_path_by_filename(self, tmp_path, monkeypatch):
        """_find_details_path finds details file by filename."""
        monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(tmp_path))
        (tmp_path / "test.details").write_text("{}", encoding="utf-8")
        svc = is_module.insights_service
        result = svc._find_details_path(None, "test.22000")
        assert result == str(tmp_path / "test.details")

    def test_is_already_cracked(self, tmp_path, monkeypatch):
        """_is_already_cracked checks for cracked artifacts."""
        monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(tmp_path))
        (tmp_path / "test.pcap.cracked").write_text("password", encoding="utf-8")
        svc = is_module.insights_service
        assert svc._is_already_cracked(None, "test.22000") is True
        assert svc._is_already_cracked(None, "other.22000") is False

    def test_resolve_network_context(self, monkeypatch):
        """_resolve_network_context resolves MAC and network data."""
        monkeypatch.setattr(
            is_module,
            "load_real_data",
            lambda: {"AA:BB:CC:DD:EE:FF": {"ssid": "TestNet"}},
        )
        svc = is_module.insights_service
        mac, network = svc._resolve_network_context("AA:BB:CC:DD:EE:FF", None)
        assert mac == "AA:BB:CC:DD:EE:FF"
        assert network["ssid"] == "TestNet"


class TestInsightsServiceReadiness:
    """Tests for handshake readiness."""

    def test_readiness_open_network(self, monkeypatch):
        """_build_handshake_readiness handles OPEN networks."""
        svc = is_module.insights_service
        context = {
            "network": {"encryption": "OPEN"},
            "hash": {"exists": False, "valid_hash_lines": 0},
            "already_cracked": False,
            "raw_aggregate": {"present": False},
        }
        readiness = svc._build_handshake_readiness(context)
        assert readiness["status"] == "open"
        assert readiness["score"] == 100

    def test_readiness_already_cracked(self, monkeypatch):
        """_build_handshake_readiness handles already cracked."""
        svc = is_module.insights_service
        context = {
            "network": {"encryption": "WPA2"},
            "hash": {"exists": False, "valid_hash_lines": 0},
            "already_cracked": True,
            "raw_aggregate": {"present": False},
        }
        readiness = svc._build_handshake_readiness(context)
        assert readiness["status"] == "already_cracked"
        assert readiness["score"] == 100

    def test_readiness_not_ready(self, monkeypatch):
        """_build_handshake_readiness handles not ready."""
        svc = is_module.insights_service
        context = {
            "network": {"encryption": "WPA2"},
            "hash": {"exists": False, "valid_hash_lines": 0},
            "already_cracked": False,
            "raw_aggregate": {"present": False},
        }
        readiness = svc._build_handshake_readiness(context)
        assert readiness["status"] == "not_ready"
        assert readiness["score"] == 5

    def test_readiness_weak_ready_with_raw_eapol(self, monkeypatch):
        """_build_handshake_readiness handles weak ready with RAW EAPOL."""
        svc = is_module.insights_service
        context = {
            "network": {"encryption": "WPA2", "raw_eapol_count": 5},
            "hash": {"exists": False, "valid_hash_lines": 0},
            "already_cracked": False,
            "raw_aggregate": {
                "present": True,
                "aggregate": {"eapol_count_total": 5, "warnings": []},
            },
        }
        readiness = svc._build_handshake_readiness(context)
        assert readiness["status"] == "weak_ready"
        assert readiness["score"] == 55

    def test_readiness_observed_only(self, monkeypatch):
        """_build_handshake_readiness handles observed only."""
        svc = is_module.insights_service
        context = {
            "network": {"encryption": "WPA2", "raw_beacon_count": 10},
            "hash": {"exists": False, "valid_hash_lines": 0},
            "already_cracked": False,
            "raw_aggregate": {
                "present": True,
                "aggregate": {"beacon_count_total": 10, "warnings": []},
            },
        }
        readiness = svc._build_handshake_readiness(context)
        assert readiness["status"] == "observed_only"
        assert readiness["score"] == 25


class TestInsightsServiceQualityAndReadinessRegression:
    """
    Testes adicionais para insights_service focando em branches de quality gate e readiness
    para garantir cobertura >90%.
    """

    @pytest.fixture
    def mock_env(self, monkeypatch, tmp_path):
        monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(config_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(is_module, "BRUCE_PCAP_DIR", str(tmp_path))
        return tmp_path

    def test_quality_gate_history_exhausted(self, mock_env, monkeypatch):
        """Quality Gate: Bloqueia se histórico mostra EXHAUSTED para o modo."""
        # Use a valid hash structure so it passes basic validation
        pmkid = "a" * 32
        filename = "test.22000"
        (mock_env / filename).write_text(
            f"WPA*02*{pmkid}*aabbccddeeff*112233445566*74657374*00", encoding="utf-8"
        )

        # Use history service to create entry to ensure format consistency
        entry_id = hs_module.history_service.add_entry(
            filename, "hashcat", ["hashcat", "cmd"], params={"attack_mode": "straight"}
        )
        hs_module.history_service.update_entry(filename, entry_id, "EXHAUSTED")

        monkeypatch.setattr(is_module, "load_real_data", lambda: {})
        monkeypatch.setattr(
            is_module.rawsniffer_service,
            "get_aggregated_metadata_for_bssid",
            lambda m: {"present": False},
        )

        # Deve bloquear 'straight'
        res = is_module.insights_service.evaluate_quality_gate(
            filename, attack_mode="straight"
        )
        assert res["passed"] is False
        assert res["code"] == "history_exhausted"

        # Deve permitir 'rules' (outro modo)
        res = is_module.insights_service.evaluate_quality_gate(
            filename, attack_mode="rules"
        )
        assert res["passed"] is True

    def test_readiness_observed_only(self, mock_env, monkeypatch):
        """Readiness: Identifica rede observada mas sem handshake."""
        monkeypatch.setattr(
            is_module,
            "load_real_data",
            lambda: {
                "AA:BB:CC:DD:EE:FF": {"mac": "AA:BB:CC:DD:EE:FF", "handshake": False}
            },
        )
        monkeypatch.setattr(
            is_module.rawsniffer_service,
            "get_aggregated_metadata_for_bssid",
            lambda m: {"present": True, "aggregate": {"eapol_count_total": 0}},
        )

        res = is_module.insights_service.get_handshake_readiness(
            mac="AA:BB:CC:DD:EE:FF"
        )
        assert res["readiness"]["status"] == "not_ready"


class TestInsightsServiceQualityGate:
    """Tests for quality gate evaluation."""

    def test_quality_gate_hash_not_found(self, tmp_path, monkeypatch):
        """Quality gate blocks when hash file not found."""
        monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(is_module, "load_real_data", lambda: {})
        monkeypatch.setattr(
            is_module.rawsniffer_service,
            "get_aggregated_metadata_for_bssid",
            lambda m: {"present": False},
        )
        res = is_module.insights_service.evaluate_quality_gate("nonexistent.22000")
        assert res["passed"] is False
        assert res["code"] == "quality_gate_blocked"

    def test_quality_gate_hash_empty(self, tmp_path, monkeypatch):
        """Quality gate blocks when hash file is empty."""
        monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(tmp_path))
        (tmp_path / "empty.22000").write_text("", encoding="utf-8")
        monkeypatch.setattr(is_module, "load_real_data", lambda: {})
        monkeypatch.setattr(
            is_module.rawsniffer_service,
            "get_aggregated_metadata_for_bssid",
            lambda m: {"present": False},
        )
        res = is_module.insights_service.evaluate_quality_gate("empty.22000")
        assert res["passed"] is False
        assert res["code"] == "quality_gate_blocked"

    def test_quality_gate_no_valid_hashes(self, tmp_path, monkeypatch):
        """Quality gate blocks when no valid WPA hash lines."""
        monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(tmp_path))
        (tmp_path / "invalid.22000").write_text("invalid line\n", encoding="utf-8")
        monkeypatch.setattr(is_module, "load_real_data", lambda: {})
        monkeypatch.setattr(
            is_module.rawsniffer_service,
            "get_aggregated_metadata_for_bssid",
            lambda m: {"present": False},
        )
        res = is_module.insights_service.evaluate_quality_gate("invalid.22000")
        assert res["passed"] is False
        assert res["code"] == "quality_gate_blocked"

    def test_quality_gate_already_cracked_overrideable(self, tmp_path, monkeypatch):
        """Quality gate warns when target already cracked."""
        monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(tmp_path))
        pmkid = "a" * 32
        filename = "test.22000"
        (tmp_path / filename).write_text(
            f"WPA*02*{pmkid}*aabbccddeeff*112233445566*74657374*00", encoding="utf-8"
        )
        (tmp_path / "test.pcap.cracked").write_text("password", encoding="utf-8")
        monkeypatch.setattr(is_module, "load_real_data", lambda: {})
        monkeypatch.setattr(
            is_module.rawsniffer_service,
            "get_aggregated_metadata_for_bssid",
            lambda m: {"present": False},
        )
        res = is_module.insights_service.evaluate_quality_gate(filename)
        assert res["passed"] is False
        assert res["code"] == "quality_gate_overrideable"

    def test_quality_gate_repeated_exhausted(self, tmp_path, monkeypatch):
        """Quality gate warns when many exhausted attempts."""
        monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(tmp_path))
        pmkid = "a" * 32
        filename = "test.22000"
        (tmp_path / filename).write_text(
            f"WPA*02*{pmkid}*aabbccddeeff*112233445566*74657374*00", encoding="utf-8"
        )
        monkeypatch.setattr(is_module, "load_real_data", lambda: {})
        monkeypatch.setattr(
            is_module.rawsniffer_service,
            "get_aggregated_metadata_for_bssid",
            lambda m: {"present": False},
        )
        monkeypatch.setattr(
            is_module.insights_service,
            "_count_history_statuses",
            lambda *a, **_k: {
                "total": 5,
                "exhausted": 3,
                "cracked": 0,
                "failed": 0,
                "running": 0,
            },
        )
        res = is_module.insights_service.evaluate_quality_gate(filename)
        assert res["passed"] is False
        assert res["code"] == "quality_gate_overrideable"

    def test_quality_gate_passed(self, tmp_path, monkeypatch):
        """Quality gate passes when all checks OK."""
        monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(tmp_path))
        pmkid = "a" * 32
        filename = "test.22000"
        (tmp_path / filename).write_text(
            f"WPA*02*{pmkid}*aabbccddeeff*112233445566*74657374*00", encoding="utf-8"
        )
        monkeypatch.setattr(is_module, "load_real_data", lambda: {})
        monkeypatch.setattr(
            is_module.rawsniffer_service,
            "get_aggregated_metadata_for_bssid",
            lambda m: {"present": False},
        )
        res = is_module.insights_service.evaluate_quality_gate(filename)
        assert res["passed"] is True
        assert res["code"] == "quality_gate_passed"


class TestInsightsServiceRecommendation:
    """Tests for attack recommendation."""

    def test_recommendation_already_cracked(self, monkeypatch):
        """Recommendation skips when already cracked."""
        monkeypatch.setattr(is_module, "load_real_data", lambda: {})
        monkeypatch.setattr(
            is_module.rawsniffer_service,
            "get_aggregated_metadata_for_bssid",
            lambda m: {"present": False},
        )
        monkeypatch.setattr(
            is_module.insights_service, "_is_already_cracked", lambda *a, **_k: True
        )
        res = is_module.insights_service.get_attack_recommendation(
            mac="AA:BB:CC:DD:EE:FF"
        )
        assert res["action"] == "skip"
        assert res["quality_gate"]["code"] == "already_cracked"

    def test_recommendation_open_network(self, monkeypatch):
        """Recommendation skips for OPEN network."""
        monkeypatch.setattr(
            is_module,
            "load_real_data",
            lambda: {"AA:BB:CC:DD:EE:FF": {"encryption": "OPEN"}},
        )
        monkeypatch.setattr(
            is_module.rawsniffer_service,
            "get_aggregated_metadata_for_bssid",
            lambda m: {"present": False},
        )
        monkeypatch.setattr(
            is_module.insights_service, "_is_already_cracked", lambda *a, **_k: False
        )
        res = is_module.insights_service.get_attack_recommendation(
            mac="AA:BB:CC:DD:EE:FF"
        )
        assert res["action"] == "skip"
        assert res["quality_gate"]["code"] == "open_network"

    def test_recommendation_no_valid_hashes(self, tmp_path, monkeypatch):
        """Recommendation prepares when no valid hashes."""
        monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(
            is_module,
            "load_real_data",
            lambda: {"AA:BB:CC:DD:EE:FF": {"encryption": "WPA2"}},
        )
        monkeypatch.setattr(
            is_module.rawsniffer_service,
            "get_aggregated_metadata_for_bssid",
            lambda m: {"present": False},
        )
        monkeypatch.setattr(
            is_module.insights_service, "_is_already_cracked", lambda *a, **_k: False
        )
        (tmp_path / "empty.22000").write_text("", encoding="utf-8")
        res = is_module.insights_service.get_attack_recommendation(
            filename="empty.22000"
        )
        assert res["action"] == "prepare"

    def test_recommendation_hidden_ssid(self, tmp_path, monkeypatch):
        """Recommendation uses association_hint_first for hidden SSID."""
        monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(tmp_path))
        pmkid = "a" * 32
        filename = "test.22000"
        (tmp_path / filename).write_text(
            f"WPA*02*{pmkid}*aabbccddeeff*112233445566*74657374*00", encoding="utf-8"
        )
        monkeypatch.setattr(
            is_module,
            "load_real_data",
            lambda: {"AA:BB:CC:DD:EE:FF": {"encryption": "WPA2", "ssid": ""}},
        )
        monkeypatch.setattr(
            is_module.rawsniffer_service,
            "get_aggregated_metadata_for_bssid",
            lambda m: {"present": False},
        )
        monkeypatch.setattr(
            is_module.insights_service, "_is_already_cracked", lambda *a, **_k: False
        )
        res = is_module.insights_service.get_attack_recommendation(filename=filename)
        assert res["recommended_mode"] == "association_hint_first"

    def test_recommendation_wps_present(self, tmp_path, monkeypatch):
        """Recommendation uses rules for WPS present."""
        monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(tmp_path))
        pmkid = "a" * 32
        filename = "test.22000"
        (tmp_path / filename).write_text(
            f"WPA*02*{pmkid}*aabbccddeeff*112233445566*74657374*00", encoding="utf-8"
        )
        (tmp_path / "test.details").write_text(
            '{"wps": {"present": true}}', encoding="utf-8"
        )
        monkeypatch.setattr(
            is_module,
            "load_real_data",
            lambda: {
                "AA:BB:CC:DD:EE:FF": {
                    "encryption": "WPA2",
                    "ssid": "TestNet",
                    "handshake": True,
                }
            },
        )
        monkeypatch.setattr(
            is_module.rawsniffer_service,
            "get_aggregated_metadata_for_bssid",
            lambda m: {"present": False},
        )
        monkeypatch.setattr(
            is_module.insights_service, "_is_already_cracked", lambda *a, **_k: False
        )
        monkeypatch.setattr(
            is_module.insights_service,
            "_extract_mac_from_filename",
            lambda *a, **_k: "AA:BB:CC:DD:EE:FF",
        )
        res = is_module.insights_service.get_attack_recommendation(filename=filename)
        assert res["recommended_mode"] == "rules"

    def test_recommendation_low_score(self, tmp_path, monkeypatch):
        """Recommendation uses straight for low score."""
        monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(tmp_path))
        pmkid = "a" * 32
        filename = "test.22000"
        (tmp_path / filename).write_text(
            f"WPA*02*{pmkid}*aabbccddeeff*112233445566*74657374*00", encoding="utf-8"
        )
        monkeypatch.setattr(
            is_module,
            "load_real_data",
            lambda: {
                "AA:BB:CC:DD:EE:FF": {
                    "encryption": "WPA2",
                    "ssid": "TestNet",
                    "handshake": True,
                }
            },
        )
        monkeypatch.setattr(
            is_module.rawsniffer_service,
            "get_aggregated_metadata_for_bssid",
            lambda m: {"present": False},
        )
        monkeypatch.setattr(
            is_module.insights_service, "_is_already_cracked", lambda *a, **_k: False
        )
        monkeypatch.setattr(
            is_module.insights_service, "_score_context", lambda *a, **_k: (20, [])
        )
        monkeypatch.setattr(
            is_module.insights_service,
            "_extract_mac_from_filename",
            lambda *a, **_k: "AA:BB:CC:DD:EE:FF",
        )
        res = is_module.insights_service.get_attack_recommendation(filename=filename)
        assert res["recommended_mode"] == "straight"

    def test_recommendation_good_score(self, tmp_path, monkeypatch):
        """Recommendation uses rules for good score."""
        monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(tmp_path))
        pmkid = "a" * 32
        filename = "test.22000"
        (tmp_path / filename).write_text(
            f"WPA*02*{pmkid}*aabbccddeeff*112233445566*74657374*00", encoding="utf-8"
        )
        monkeypatch.setattr(
            is_module,
            "load_real_data",
            lambda: {
                "AA:BB:CC:DD:EE:FF": {
                    "encryption": "WPA2",
                    "ssid": "TestNet",
                    "handshake": True,
                }
            },
        )
        monkeypatch.setattr(
            is_module.rawsniffer_service,
            "get_aggregated_metadata_for_bssid",
            lambda m: {"present": False},
        )
        monkeypatch.setattr(
            is_module.insights_service, "_is_already_cracked", lambda *a, **_k: False
        )
        monkeypatch.setattr(
            is_module.insights_service, "_score_context", lambda *a, **_k: (70, [])
        )
        monkeypatch.setattr(
            is_module.insights_service,
            "_extract_mac_from_filename",
            lambda *a, **_k: "AA:BB:CC:DD:EE:FF",
        )
        res = is_module.insights_service.get_attack_recommendation(filename=filename)
        assert res["recommended_mode"] == "rules"
