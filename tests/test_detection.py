from conftest import attack_log, benign_log, ssh_fail, upload, SRC


def inv_of(client, text, year="2025"):
    ds = upload(client, text, default_year=year).json()["dataset_id"]
    r = client.post(f"/api/datasets/{ds}/analyze").json()
    return ds, r["investigations"]


def test_benign_log_produces_no_investigation(client):
    _, invs = inv_of(client, benign_log())
    assert invs == []


def test_below_threshold_not_flagged(client):
    _, invs = inv_of(client, "\n".join(ssh_fail(s, "bob") for s in (1, 2, 3, 4)) + "\n")
    assert invs == []


def test_attack_chain_detected_and_critical(analyzed):
    client, ds, iid = analyzed
    inv = client.get(f"/api/investigations/{iid}").json()
    rules = {f["rule_id"] for f in inv["findings"]}
    assert {"auth.bruteforce", "auth.success_after_failures", "account.created",
            "persistence.ssh_authorized_keys", "network.suspicious_port"} <= rules
    assert inv["severity"] == "critical" and inv["case"]["attack_chain"]
    assert any("Escalated" in b for b in inv["severity_basis"])
    assert inv["case"]["correlation_links"]
    assert inv["analysis_mode"] == "RULE_BASED" and inv["agent"]["status"] == "NOT_RUN"
    assert inv["source"]["live_telemetry"] is False


def test_every_cited_evidence_id_exists_in_dataset(analyzed):
    client, ds, iid = analyzed
    inv = client.get(f"/api/investigations/{iid}").json()
    real = {e["event_id"] for e in client.get(f"/api/datasets/{ds}/events?limit=1000").json()["events"]}
    for f in inv["findings"]:
        assert f["evidence_ids"] and set(f["evidence_ids"]) <= real
    assert {r["event_id"] for r in inv["timeline"]} <= real
    for m in inv["mitre"]:
        assert m["evidence_ids"] and set(m["evidence_ids"]) <= real
    for i in inv["iocs"]:
        assert set(i["evidence_ids"]) <= real


def test_success_after_failures_details(analyzed):
    client, ds, iid = analyzed
    f = next(f for f in client.get(f"/api/investigations/{iid}").json()["findings"] if f["rule_id"] == "auth.success_after_failures")
    assert f["stats"]["success_user"] == "deploy" and f["stats"]["same_account_failed_first"] is True
    assert f["evidence_strength"] == "strong" and f["severity"] == "high"


def test_mitre_status_and_no_overreach(analyzed):
    client, ds, iid = analyzed
    m = {x["technique_id"]: x for x in client.get(f"/api/investigations/{iid}").json()["mitre"]}
    assert m["T1078"]["status"] == "SUSPECTED" and m["T1136.001"]["status"] == "OBSERVED"
    assert m["T1571"]["status"] == "SUSPECTED"
    assert all("basis" in x and x["bases"] for x in m.values())


def test_plain_sudo_gets_no_mitre_mapping(client):
    log = "\n".join(f"Feb 18 08:0{i}:00 h sudo:   bob : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/crontab -l" for i in range(1, 3))
    _, invs = inv_of(client, log)
    inv = client.get(f"/api/investigations/{invs[0]['id']}").json()
    assert inv["mitre"] == [] and inv["severity"] == "low"


def test_spray_pattern_uses_spray_technique(client):
    log = "\n".join(ssh_fail(i, f"user{i}") for i in range(1, 8)) + "\n"
    _, invs = inv_of(client, log)
    inv = client.get(f"/api/investigations/{invs[0]['id']}").json()
    assert inv["findings"][0]["rule_id"] == "auth.spray"
    assert inv["mitre"][0]["technique_id"] == "T1110.003"


def test_windows_log_clear_is_observed(client):
    xml = """<Events><Event><System><EventID>1102</EventID><TimeCreated SystemTime="2025-02-18T08:50:00Z"/><Computer>WS1</Computer></System><EventData><Data Name="SubjectUserName">bob</Data></EventData></Event></Events>"""
    ds = upload(client, xml, name="a.xml").json()["dataset_id"]
    inv = client.get("/api/investigations/" + client.post(f"/api/datasets/{ds}/analyze").json()["investigations"][0]["id"]).json()
    assert inv["mitre"][0]["technique_id"] == "T1070.001" and inv["mitre"][0]["status"] == "OBSERVED"


def test_ioc_local_extraction_and_no_fabricated_enrichment(analyzed):
    client, ds, iid = analyzed
    iocs = client.get(f"/api/investigations/{iid}").json()["iocs"]
    ip = next(i for i in iocs if i["value"] == SRC)
    assert ip["scope"] == "documentation" and ip["source"] == "LOCAL_EXTRACTION"
    assert ip["enrichment"]["status"] == "PROVIDER_NOT_CONFIGURED"
    assert not any("reputation" in i or "geo" in i for i in iocs)


def test_reanalysis_is_idempotent(analyzed):
    client, ds, iid = analyzed
    again = client.post(f"/api/datasets/{ds}/analyze").json()["investigations"]
    assert [i["id"] for i in again] == [iid]
    assert len(client.get("/api/investigations").json()["investigations"]) == 1
