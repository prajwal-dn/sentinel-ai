"""Deterministic Sentinel AI demo correlation. Every finding cites event IDs."""
from collections import Counter
from datetime import datetime, timezone
import hashlib

SRC, HOST = "185.220.101.42", "prod-web-01"

def demo_events():
    raw = [
      ("evt-001","2025-02-18T08:41:02Z","auth","sshd","medium","Failed password for invalid user admin from 185.220.101.42 port 49812 ssh2","admin","failure"),
      ("evt-002","2025-02-18T08:41:14Z","auth","sshd","medium","Failed password for root from 185.220.101.42 port 49830 ssh2","root","failure"),
      ("evt-003","2025-02-18T08:41:26Z","auth","sshd","medium","Failed password for invalid user oracle from 185.220.101.42 port 49844 ssh2","oracle","failure"),
      ("evt-004","2025-02-18T08:41:38Z","auth","sshd","medium","Failed password for deploy from 185.220.101.42 port 49861 ssh2","deploy","failure"),
      ("evt-005","2025-02-18T08:41:50Z","auth","sshd","medium","Failed password for deploy from 185.220.101.42 port 49879 ssh2","deploy","failure"),
      ("evt-006","2025-02-18T08:42:02Z","auth","sshd","medium","Failed password for deploy from 185.220.101.42 port 49898 ssh2","deploy","failure"),
      ("evt-007","2025-02-18T08:42:15Z","auth","sshd","medium","Failed password for deploy from 185.220.101.42 port 49914 ssh2","deploy","failure"),
      ("evt-008","2025-02-18T08:42:31Z","auth","sshd","high","Accepted password for deploy from 185.220.101.42 port 49932 ssh2","deploy","success"),
      ("evt-009","2025-02-18T08:43:07Z","process","sudo","high","deploy executed: sudo -n /usr/sbin/useradd -m svc-backup","deploy","success"),
      ("evt-010","2025-02-18T08:43:19Z","file","auditd","high","Created /home/svc-backup/.ssh/authorized_keys by uid=1002","deploy","success"),
      ("evt-011","2025-02-18T08:44:03Z","network","netflow","high","Outbound TCP connection to 198.51.100.77:4444, 48213 bytes","deploy","success")]
    return [{"id":a,"timestamp":b,"host":HOST,"category":c,"service":d,"event_severity":e,"message":f,"source_ip":SRC if c=="auth" else None,"destination_ip":"198.51.100.77" if c=="network" else None,"destination_port":4444 if c=="network" else (22 if c=="auth" else None),"username":g,"outcome":h,"source_mode":"DEMO","demo_notice":"Simulated event for demonstration; not live telemetry."} for a,b,c,d,e,f,g,h in raw]

def ioc(kind,value,ids,context):
    return {"type":kind,"value":value,"evidence_event_ids":ids,"provenance":"LOCAL_DEMO_EVENT_CORRELATION","context":context,"threat_intelligence":"UNAVAILABLE"}

def analyze(events):
    failures=[e for e in events if e["category"]=="auth" and e["outcome"]=="failure"]
    sources={ip for ip,n in Counter(e["source_ip"] for e in failures).items() if ip and n>=5}
    success=[e for e in events if e["category"]=="auth" and e["outcome"]=="success" and e["source_ip"] in sources]
    bids=[e["id"] for e in failures]; sids=[e["id"] for e in success]
    iid="INC-2025-0218-001"; rid="RPT-"+hashlib.sha256(iid.encode()).hexdigest()[:10].upper()
    tech=[
      {"tactic":"Credential Access","technique":"T1110.001 — Password Guessing","reason/evidence_basis":f"{len(failures)} failed SSH logins from one source in 73 seconds.","confidence":.99,"observed_count":len(failures),"evidence_event_ids":bids},
      {"tactic":"Initial Access","technique":"T1078 — Valid Accounts","reason/evidence_basis":"Successful deploy login from the same source immediately after repeated failures.","confidence":.97,"observed_count":1,"evidence_event_ids":sids},
      {"tactic":"Persistence","technique":"T1136.001 — Local Account","reason/evidence_basis":"A new local svc-backup account was created after the login.","confidence":.96,"observed_count":1,"evidence_event_ids":["evt-009"]},
      {"tactic":"Persistence","technique":"T1098.004 — SSH Authorized Keys","reason/evidence_basis":"An authorized_keys file was created for the new account.","confidence":.96,"observed_count":1,"evidence_event_ids":["evt-010"]},
      {"tactic":"Command and Control","technique":"T1571 — Non-Standard Port","reason/evidence_basis":"Outbound TCP connection used destination port 4444 after account changes.","confidence":.82,"observed_count":1,"evidence_event_ids":["evt-011"]}]
    timeline=[{"timestamp":e["timestamp"],"stage":"Credential attack" if e["id"] in bids else "Initial access" if e["id"] in sids else "Post-compromise activity","event_id":e["id"],"summary":e["message"],"asset":e["host"]} for e in events]
    out={"id":iid,"report_id":rid,"timestamp":success[0]["timestamp"],"first_seen":events[0]["timestamp"],"last_seen":events[-1]["timestamp"],"attack_type":"SSH brute force followed by account compromise and persistence","severity":"CRITICAL","severity_score":96,"severity_reason":"Repeated SSH guessing was followed by a successful login, privileged account creation, SSH key persistence, and an unusual outbound connection on the same asset.","confidence":.98,"confidence_reason":"High-confidence deterministic sequence: 7 failures from one source, same-source success, then three post-authentication indicators within 92 seconds.","source_mode":"DEMO","demo_notice":"This incident is generated from simulated demonstration events, not live telemetry.","status":"AWAITING_HUMAN_DECISION","decision":None,
    "affected_assets":[{"hostname":HOST,"ip":"10.20.4.18","role":"Production web server","evidence_event_ids":[e["id"] for e in events]}],
    "iocs":[ioc("IPv4",SRC,bids+sids,"Source of SSH failures and subsequent successful login"),ioc("IPv4","198.51.100.77",["evt-011"],"Destination of unusual outbound connection"),ioc("Port","4444/tcp",["evt-011"],"Non-standard outbound destination port"),ioc("Username","deploy",[f"evt-{n:03}" for n in range(4,12)],"Compromised account suspected; not independently confirmed"),ioc("Username","svc-backup",["evt-009","evt-010"],"Newly created local account used for persistence")],
    "mitre_techniques":tech,"attack_timeline":timeline,
    "investigation_findings":[{"finding":"Password guessing threshold exceeded","confidence":"HIGH","evidence_event_ids":bids},{"finding":"The same remote source authenticated successfully after the failures","confidence":"HIGH","evidence_event_ids":bids+sids},{"finding":"The deploy account likely performed persistence-related changes","confidence":"HIGH","evidence_event_ids":["evt-009","evt-010"]},{"finding":"The outbound connection may represent command-and-control traffic","confidence":"MEDIUM","evidence_event_ids":["evt-011"],"uncertainty":"No packet content or external reputation lookup is available."}],
    "recommendations":[{"priority":"IMMEDIATE","action":"Isolate prod-web-01 from the network after obtaining human approval; preserve management access for forensics.","destructive":False,"requires_approval":True},{"priority":"IMMEDIATE","action":"Disable or rotate credentials for deploy and investigate all recent sessions.","destructive":False,"requires_approval":True},{"priority":"HIGH","action":"Block 185.220.101.42 and 198.51.100.77 at relevant controls after validating business impact.","destructive":False,"requires_approval":True},{"priority":"HIGH","action":"Preserve auth, audit, process, network, and shell history artifacts before remediation.","destructive":False,"requires_approval":False},{"priority":"HIGH","action":"Review svc-backup and its authorized_keys entry; remove only after evidence capture and approval.","destructive":True,"requires_approval":True},{"priority":"MEDIUM","action":"Enforce SSH keys/MFA, disable password authentication where feasible, and rate-limit login attempts.","destructive":False,"requires_approval":True}],
    "threat_intelligence":{"status":"UNAVAILABLE","mode":"LOCAL","summary":"No external threat-intelligence provider is configured. Indicators are displayed from local deterministic correlation only.","enrichment_performed":False},
    "agent_trace":[{"stage":1,"name":"Ingest","status":"COMPLETED","detail":f"Parsed {len(events)} normalized DEMO events.","input_event_ids":[e["id"] for e in events]},{"stage":2,"name":"Detect","status":"COMPLETED","detail":f"Detected {len(failures)} SSH failures from a single source (threshold: 5).","input_event_ids":bids},{"stage":3,"name":"Correlate","status":"COMPLETED","detail":"Linked same-source success and same-host post-authentication activity.","input_event_ids":sids+["evt-009","evt-010","evt-011"]},{"stage":4,"name":"Classify","status":"COMPLETED","detail":"Applied deterministic attack classification and MITRE mappings from observed evidence.","input_event_ids":[e["id"] for e in events]},{"stage":5,"name":"Score","status":"COMPLETED","detail":"Severity raised to CRITICAL due to access + persistence + potential C2. Confidence 98% based on sequence completeness.","input_event_ids":sids+["evt-009","evt-010","evt-011"]},{"stage":6,"name":"Recommend","status":"COMPLETED","detail":"Prepared non-executing response recommendations; human approval is mandatory.","input_event_ids":[]}]}
    out["generated_markdown_report"]=build_report(out); return out

def build_report(i):
    iocs="\n".join(f"- `{x['value']}` ({x['type']}) — {x['context']} — Evidence: {', '.join(x['evidence_event_ids'])}" for x in i["iocs"])
    timeline="\n".join(f"- **{x['timestamp']}** [{x['event_id']}] {x['summary']}" for x in i["attack_timeline"])
    mitre="\n".join(f"- **{x['technique']}** ({x['tactic']}) — {x['reason/evidence_basis']}" for x in i["mitre_techniques"])
    recs="\n".join(f"- **{x['priority']}** — {x['action']}" for x in i["recommendations"])
    findings="\n".join(f"- {x['finding']} ({x['confidence']}) — Evidence: {', '.join(x['evidence_event_ids'])}" for x in i["investigation_findings"])
    return f"""# Sentinel AI Incident Report

**Report ID:** {i['report_id']}  
**Incident ID:** {i['id']}  
**Source:** DEMO — SIMULATED DATA, NOT LIVE TELEMETRY  
**Generated:** {datetime.now(timezone.utc).isoformat(timespec='seconds')}  

## Incident Summary
Sentinel AI correlated repeated SSH failures with a subsequent successful login and post-authentication persistence activity on `{i['affected_assets'][0]['hostname']}`.

## Attack Type
{i['attack_type']}

## Severity
**{i['severity']} ({i['severity_score']}/100)** — {i['severity_reason']}

## Confidence
**{i['confidence']:.0%}** — {i['confidence_reason']}

## Affected Assets
- `{i['affected_assets'][0]['hostname']}` / `{i['affected_assets'][0]['ip']}` — {i['affected_assets'][0]['role']}

## Indicators of Compromise
{iocs}

## Evidence
{findings}

## Attack Timeline
{timeline}

## MITRE ATT&CK Mapping
{mitre}

## Threat Intelligence Findings
**UNAVAILABLE / LOCAL** — {i['threat_intelligence']['summary']}

## Recommended Actions
{recs}

## Investigation Notes
- Findings were produced by deterministic local rules from the event IDs cited above.
- Potential command-and-control is assessed, not confirmed; packet data and external enrichment are unavailable.
- Sentinel AI has not executed any response action. Human authorization is required.
"""
