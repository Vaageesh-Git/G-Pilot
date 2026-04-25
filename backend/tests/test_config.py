import _test_bootstrap  # noqa: F401

from vuln_swarm.core.config import Settings


def test_resolved_cors_origins_include_common_local_vite_ports_in_development(tmp_path) -> None:
    settings = Settings(
        FRONTEND_ORIGIN="http://localhost:5178",
        VULN_SWARM_DATA_DIR=str(tmp_path / ".data"),
        CHROMA_DIR=str(tmp_path / ".data" / "chroma"),
    )

    assert "http://localhost:5173" in settings.resolved_cors_origins
    assert "http://127.0.0.1:5173" in settings.resolved_cors_origins
    assert "http://localhost:5178" in settings.resolved_cors_origins
    assert "http://127.0.0.1:5178" in settings.resolved_cors_origins


def test_explicit_cors_origins_stay_explicit_outside_development(tmp_path) -> None:
    settings = Settings(
        environment="production",
        cors_origins=["https://dashboard.example.com"],
        VULN_SWARM_DATA_DIR=str(tmp_path / ".data"),
        CHROMA_DIR=str(tmp_path / ".data" / "chroma"),
    )

    assert settings.resolved_cors_origins == ["https://dashboard.example.com"]
