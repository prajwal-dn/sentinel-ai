import json
from conftest import attack_log, upload, SRC

WAZUH = json.dumps({"timestamp": "2025-02-18T08:41:02.123+0000", "rule": {"id": "5710", "level": 5, "description": "sshd: attempt to login using a non-existent user", "mitre": {"id": ["T1110.001"]}},
                    "agent": {"id": "001", "name": "web-01"}, "data": {"srcip": SRC}, "full_log": f"Feb 18 08:41:02 web-01 sshd[1]: Failed password for invalid user admin from {SRC} port 4000 ssh2"})
WINXML = """<?xml version="1.0"?><Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4625</EventID><TimeCreated SystemTime="2025-02-18T08:41:02.000000000Z"/><Computer>WS01</Computer></System>
<EventData><Data Name="TargetUserName">bob</Data><Data Name="IpAddress">203.0.113.9</Data><Data Name="IpPort">5555</Data><Data Name="LogonType">3</Data></EventData></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1102</EventID><TimeCreated SystemTime="2025-02-18T08:50:00Z"/><Computer>WS01</Computer></System><EventData><Data Name="SubjectUserName">bob</Data></EventData></Event></Events>"""


def test_syslog_upload_summary_and_no_demo_data(client):
    assert client.get("/api/datasets").json()["datasets"] == []          # nothing preloaded
    r = upload(client, attack_log(), default_year="2025")
    s = r.json()["summary"]
    assert r.status_code == 200 and s["status"] == "SUCCESS" and s["detected_format"] == "syslog"
    assert s["accepted"] == 11 and s["rejected"] == 0 and s["unsupported"] == 0
    assert any("year was assumed" in c for c in s["caveats"])


def test_malformed_lines_are_reported_not_dropped_silently(client):
    r = upload(client, attack_log() + "this is not syslog\n")
    s = r.json()["summary"]
    assert s["status"] == "PARTIAL" and s["rejected"] == 1 and s["rejected_samples"][0]["position"] == 12


def test_unsupported_format_creates_nothing(client):
    r = upload(client, "hello world\nrandom text without structure\n", name="notes.txt")
    assert r.status_code == 422 and r.json()["summary"]["status"] == "FAILED" and r.json()["dataset_id"] is None
    assert client.get("/api/datasets").json()["datasets"] == []


def test_binary_evtx_and_bad_extension_refused(client):
    assert upload(client, b"ElfFile\x00\x00\x00", name="Security.evtx").status_code == 415
    assert upload(client, "x", name="payload.exe").status_code == 415
    assert upload(client, b"\x00\x01\x02binary", name="a.log").status_code == 415


def test_empty_and_oversize(client, settings):
    assert upload(client, b"", name="a.log").status_code == 400
    settings.max_upload_bytes = 100
    assert upload(client, "x" * 500, name="a.log").status_code == 413


def test_jsonl_with_malformed_and_unsupported_records(client):
    body = "\n".join([
        json.dumps({"@timestamp": "2025-02-18T08:41:02Z", "host": {"name": "h1"}, "user": {"name": "u"}, "source": {"ip": SRC}, "event": {"category": ["authentication"], "outcome": "failure"}, "message": "login failed"}),
        "{not json", json.dumps({"foo": 1}), json.dumps([1, 2])])
    s = upload(client, body, name="e.jsonl").json()["summary"]
    assert s["detected_format"] == "jsonl" and s["accepted"] == 1 and s["rejected"] == 2 and s["unsupported"] == 1
    ds = client.get("/api/datasets").json()["datasets"][0]["id"]
    e = client.get(f"/api/datasets/{ds}/events").json()["events"][0]
    assert e["host"] == "h1" and e["username"] == "u" and e["src_ip"] == SRC and e["category"] == "auth" and e["outcome"] == "failure"
    assert e["dst_ip"] is None                                           # missing stays unknown, never invented


def test_json_array_and_epoch_timestamps(client):
    s = upload(client, json.dumps([{"time": 1739868062, "message": "x", "hostname": "h"}]), name="a.json").json()["summary"]
    assert s["detected_format"] == "json" and s["accepted"] == 1


def test_wazuh_alert_parsing_keeps_vendor_metadata(client):
    s = upload(client, WAZUH, name="alerts.json").json()["summary"]
    assert s["accepted"] == 1
    ds = client.get("/api/datasets").json()["datasets"][0]["id"]
    e = client.get(f"/api/datasets/{ds}/events").json()["events"][0]
    assert e["source_type"] == "wazuh_alert" and e["action"] == "ssh_login_failed" and e["host"] == "web-01"
    assert e["extra"]["vendor_mitre_ids"] == ["T1110.001"] and e["timestamp"] == "2025-02-18T08:41:02.123Z"


def test_windows_xml_events(client):
    s = upload(client, WINXML, name="sec.xml").json()["summary"]
    assert s["detected_format"] == "windows_xml" and s["accepted"] == 2
    ds = client.get("/api/datasets").json()["datasets"][0]["id"]
    acts = {e["action"] for e in client.get(f"/api/datasets/{ds}/events").json()["events"]}
    assert acts == {"windows_logon_failed", "audit_log_cleared"}


def test_xml_with_entities_refused(client):
    evil = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "boom">]><Events><Event><System><EventID>4625</EventID></System></Event></Events>'
    r = upload(client, evil, name="x.xml")
    assert r.status_code == 422 and "DOCTYPE" in json.dumps(r.json())


def test_windows_json_export(client):
    rec = {"EventID": 4720, "TimeCreated": "2025-02-18T08:41:02Z", "Computer": "DC1", "EventData": {"SubjectUserName": "adm", "TargetUserName": "newuser"}}
    s = upload(client, json.dumps(rec) + "\n", name="w.jsonl").json()["summary"]
    assert s["accepted"] == 1 and s["action_breakdown"] == {"account_created": 1}


def test_stable_ids_and_duplicate_upload_skipped(client):
    a = upload(client, attack_log(), default_year="2025").json()
    ds = a["dataset_id"]
    b = upload(client, attack_log(), default_year="2025", dataset_id=ds).json()
    assert b["summary"]["new_events_stored"] == 0 and b["summary"]["duplicates_skipped"] == 11
    assert client.get(f"/api/datasets/{ds}").json()["event_count"] == 11


def test_unknown_dataset_target_404(client):
    assert upload(client, attack_log(), dataset_id="ds-nope").status_code == 404


def test_search_is_parameterised(client):
    r = upload(client, attack_log(), default_year="2025").json()
    ds = r["dataset_id"]
    q = client.get(f"/api/datasets/{ds}/events", params={"text": "'; DROP TABLE events;--", "host": "x' OR '1'='1"}).json()
    assert q["total"] == 0
    assert client.get(f"/api/datasets/{ds}").json()["event_count"] == 11
