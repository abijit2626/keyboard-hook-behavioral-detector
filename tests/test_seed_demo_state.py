"""seed_demo_state.py -- sample data for presentations."""
import json

import seed_demo_state as seed
from scanner.dashboard import app as dashboard
from scanner.report import render


def test_sample_data_covers_every_risk_level():
    state = seed.build_state()
    levels = {s["risk_level"] for k, s in state.items() if k != "_meta"}
    assert levels == {"HIGH", "MEDIUM", "LOW"}


def test_sample_levels_match_configured_thresholds():
    # The levels are derived from the scores, so they can't drift from config.
    state = seed.build_state()
    for key, s in state.items():
        if key == "_meta":
            continue
        assert s["risk_level"] == seed._level(s["risk_score"])


def test_writes_file_that_report_and_dashboard_can_read(tmp_path, monkeypatch, capsys):
    path = tmp_path / "temporal_state.json"
    assert seed.main([], path=str(path)) == 0

    state = json.loads(path.read_text(encoding="utf-8"))
    assert state["_meta"]["demo"] is True

    render(state)
    assert "6 process(es) tracked -- 2 HIGH, 1 MEDIUM." in capsys.readouterr().out

    monkeypatch.setattr(dashboard, "STATE_FILE", str(path))
    summary = dashboard.build_payload()["summary"]
    assert summary == {"total": 6, "high": 2, "medium": 1, "low": 3}


def test_refuses_to_overwrite_real_state(tmp_path):
    path = tmp_path / "temporal_state.json"
    path.write_text(json.dumps({"_meta": {"last_snapshot": "x"}, "a.exe|1": {}}), encoding="utf-8")
    assert seed.main([], path=str(path)) == 1
    assert "a.exe|1" in path.read_text(encoding="utf-8")


def test_force_overwrites_and_clear_only_removes_demo_data(tmp_path):
    path = tmp_path / "temporal_state.json"
    path.write_text("{}", encoding="utf-8")

    assert seed.main(["--clear"], path=str(path)) == 1  # real data: refused
    assert path.exists()

    assert seed.main(["--force"], path=str(path)) == 0
    assert seed.main(["--clear"], path=str(path)) == 0  # now demo data: removed
    assert not path.exists()
