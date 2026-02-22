from socbox.ingest.normalize import normalize_mordor_event


def test_normalize_minimal_event():
    raw = {
        "@timestamp": "2020-01-01T00:00:00Z",
        "winlog": {
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "event_id": 4625,
            "event_data": {"TargetUserName": "alice", "IpAddress": "1.2.3.4"},
        },
        "Computer": "HOST01",
    }

    ev = normalize_mordor_event(raw, dataset_name="mordor")
    assert ev is not None
    d = ev.to_dict()
    assert d["@timestamp"].startswith("2020-01-01")
    assert d["event.category"] == "auth"
    assert d["host.name"] == "HOST01"
    assert d["user.name"] == "alice"
    assert d["source.ip"] == "1.2.3.4"