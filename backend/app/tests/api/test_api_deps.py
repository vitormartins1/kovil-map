from app.api import deps


def test_deps_defaults():
    assert isinstance(deps.app_state, dict)
    assert deps.sync_service is not None
    assert deps.mac_lookup is not None
