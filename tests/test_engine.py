import pandas as pd

from socbox.detect.engine import run

def test_engine_handles_empty_df():
    df = pd.DataFrame([])
    cfg = {"enabled": ["brute_force_auth"], "parameters": {"brute_force_auth": {"window_minutes": 10, "failures_threshold": 8}}}
    alerts = run(df, cfg)
    assert isinstance(alerts, list)