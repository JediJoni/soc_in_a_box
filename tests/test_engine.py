import pandas as pd

from socbox.detect.engine import run


def test_engine_handles_empty_df():
    df = pd.DataFrame([])
    cfg = {
        "enabled": ["suspicious_process_access"],
        "parameters": {"suspicious_process_access": {"target_processes": ["\\lsass.exe"], "min_events": 1}},
    }
    alerts = run(df, cfg)
    assert isinstance(alerts, list)
    assert alerts == []