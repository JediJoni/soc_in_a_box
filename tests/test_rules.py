import pandas as pd
from socbox.detect.rules import suspicious_process_access


def test_suspicious_process_access_finds_target():
    df = pd.DataFrame(
        [
            {
                "@timestamp": "2020-01-01T00:00:00Z",
                "event.action": "10",
                "host.name": "HOST1",
                "user.name": "NT AUTHORITY\\SYSTEM",
                "process.name": "C:\\Windows\\System32\\svchost.exe",
                "process.target": "C:\\Windows\\System32\\lsass.exe",
                "process.granted_access": "0x1000",
            }
        ]
    )
    alerts = suspicious_process_access(df, target_processes=["\\lsass.exe"], min_events=1)
    assert len(alerts) == 1