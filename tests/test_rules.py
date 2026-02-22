import pandas as pd

from socbox.detect.rules import brute_force_auth

def test_bruteforce_rule_returns_list():
    df = pd.DataFrame([])
    alerts = brute_force_auth(df, window_minutes=10, failures_threshold=8)
    assert isinstance(alerts, list)