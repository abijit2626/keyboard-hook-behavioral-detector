"""
scanner/temporal_risk_engine.py -- the actual risk-scoring decision logic.
Encodes the manual scenarios used throughout development as permanent
regression tests: gating, decay, allowlisting, and the ML/keylogger bonus.
"""
import pytest

from scanner import temporal_risk_engine as tre


@pytest.fixture(autouse=True)
def isolated_state_file(tmp_path, monkeypatch):
    """Redirect STATE_FILE so tests never touch the real temporal_state.json."""
    monkeypatch.setattr(tre, "STATE_FILE", str(tmp_path / "temporal_state.json"))


def test_single_suspect_detected_event_is_low_risk():
    events = [
        {"event": "SUSPECT_DETECTED", "identity": "app.exe|1", "exe": "app.exe",
         "pid": 1, "time": "scan_1.json"},
    ]
    state = tre.update_temporal_risk(events)
    assert state["app.exe|1"]["risk_level"] == "LOW"


def test_persistent_new_hook_module_escalates_to_high():
    # SUSPECT_DETECTED (15) + two NEW_HOOK_MODULE (35 each, gated but
    # unlocked by the prior SUSPECT_DETECTED) = 85, minus one decay (5) = 80,
    # which clears RISK_HIGH_THRESHOLD (60) from rule-based weight alone.
    events = [
        {"event": "SUSPECT_DETECTED", "identity": "evil.exe|2", "exe": r"C:\Temp\evil.exe",
         "pid": 2, "time": "scan_1.json"},
        {"event": "NEW_HOOK_MODULE", "identity": "evil.exe|2", "exe": r"C:\Temp\evil.exe",
         "pid": 2, "time": "scan_2.json"},
        {"event": "NEW_HOOK_MODULE", "identity": "evil.exe|2", "exe": r"C:\Temp\evil.exe",
         "pid": 2, "time": "scan_3.json"},
    ]
    state = tre.update_temporal_risk(events)
    assert state["evil.exe|2"]["risk_score"] == 80
    assert state["evil.exe|2"]["risk_level"] == "HIGH"


def test_gated_event_without_base_suspicion_contributes_nothing():
    # HOOK_APPEARED/NEW_HOOK_MODULE are gated: they shouldn't fire before
    # a SUSPECT_DETECTED (or existing score) has established a base.
    events = [
        {"event": "NEW_HOOK_MODULE", "identity": "ghost.exe|3", "exe": "ghost.exe",
         "pid": 3, "time": "scan_1.json"},
    ]
    state = tre.update_temporal_risk(events)
    assert state["ghost.exe|3"]["risk_score"] == 0


def test_allowlisted_process_scores_zero_regardless_of_ml_scores():
    events = [
        {"event": "SUSPECT_DETECTED", "identity": "discord.exe|4", "exe": "discord.exe",
         "pid": 4, "time": "scan_1.json", "ml_risk_score": 0.99, "keylogger_api_score": 0.99,
         "keylogger_apis_matched": ["low_level_hook"]},
    ]
    state = tre.update_temporal_risk(events)
    assert state["discord.exe|4"]["risk_score"] == 0
    assert state["discord.exe|4"]["risk_level"] == "LOW"


def test_ml_and_keylogger_scores_add_bonus_on_top_of_rule_weight():
    # Distinct "time" values: update_temporal_risk() tracks a last-processed
    # watermark in state["_meta"], so a second call reusing the same "time"
    # as an already-processed event would be filtered out as stale.
    low_conf = tre.update_temporal_risk([
        {"event": "SUSPECT_DETECTED", "identity": "a.exe|5", "exe": "a.exe",
         "pid": 5, "time": "scan_1.json", "ml_risk_score": 0.0, "keylogger_api_score": 0.0},
    ])
    high_conf = tre.update_temporal_risk([
        {"event": "SUSPECT_DETECTED", "identity": "b.exe|6", "exe": "b.exe",
         "pid": 6, "time": "scan_2.json", "ml_risk_score": 1.0, "keylogger_api_score": 1.0},
    ])
    assert high_conf["b.exe|6"]["risk_score"] > low_conf["a.exe|5"]["risk_score"]


def test_risk_decays_when_behavior_stops():
    events = [
        {"event": "SUSPECT_DETECTED", "identity": "app.exe|7", "exe": "app.exe",
         "pid": 7, "time": "scan_1.json"},
    ]
    first = tre.update_temporal_risk(events)
    score_after_detect = first["app.exe|7"]["risk_score"]

    # No new events this cycle -- decay should reduce the score.
    second = tre.update_temporal_risk([])
    assert second["app.exe|7"]["risk_score"] < score_after_detect
