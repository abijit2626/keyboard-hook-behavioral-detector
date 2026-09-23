"""scanner/report.py -- the terminal risk table."""
from scanner.report import render


def test_render_empty_state_prints_placeholder(capsys):
    render({})
    out = capsys.readouterr().out
    assert "No process risk data yet" in out


def test_render_shows_risk_levels_and_sorts_high_first(capsys):
    state = {
        "_meta": {"last_snapshot": "scan_1.json"},
        "low.exe|1": {
            "exe": "low.exe", "risk_level": "LOW", "risk_score": 5,
            "ml_risk_score": 0.05, "keylogger_api_score": 0.0,
        },
        "high.exe|2": {
            "exe": r"C:\Temp\high.exe", "risk_level": "HIGH", "risk_score": 90,
            "ml_risk_score": 0.95, "keylogger_api_score": 0.8,
            "keylogger_apis_matched": ["low_level_hook"],
        },
    }
    render(state)
    out = capsys.readouterr().out

    assert "HIGH" in out
    assert "LOW" in out
    assert "low_level_hook" in out
    assert "2 process(es) tracked -- 1 HIGH, 0 MEDIUM." in out
    # HIGH-risk row should be listed before the LOW-risk row.
    assert out.index("high.exe") < out.index("low.exe")
    # _meta must never be rendered as a process row.
    assert "_meta" not in out
