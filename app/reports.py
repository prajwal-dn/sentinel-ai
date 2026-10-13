"""Markdown incident report built strictly from the stored investigation record. No hardcoded example content."""
from __future__ import annotations

from .storage import now_iso


def c(v) -> str:
    """Inline-code-safe rendering of untrusted text."""
    s = str(v if v is not None else "unknown").replace("`", "'").replace("<", "‹").replace(">", "›").replace("\n", " ").replace("\r", " ")
    return f"`{s[:300]}`"


def t(v) -> str:
    """Plain-text-safe rendering (neutralises markdown/HTML control characters)."""
    s = str(v if v is not None else "").replace("\n", " ").replace("\r", " ")
    for ch in ("\\", "`", "*", "_", "<", ">", "|", "[", "]"):
        s = s.replace(ch, "\\" + ch)
    return s[:600]


def build_report(inv: dict, decisions: list[dict]) -> str:
    L: list[str] = []
    a = inv.get("agent") or {}
    res = a.get("result")
    src = inv["source"]
    L += [f"# Sentinel AI Investigation Report — {t(inv['id'])}", "",
          f"**Title:** {t(inv['title'])}  ", f"**Generated:** {now_iso()}  ",
          f"**Data source:** {t(src['kind'])} — dataset {c(inv['dataset_id'])} ({t(src['dataset_name'])})  ",
          "**Live telemetry:** " + ("NO — analysis of uploaded file(s), not a live feed" if src["kind"] == "FILE_UPLOAD"
                                    else "see connector status at time of ingestion"),
          f"**Analysis mode:** {t(inv['analysis_mode'])}; AI agent: **{t(a.get('status', 'NOT_RUN'))}**", ""]
    L += ["## 1. Incident summary", ""]
    L += [f"Rule-based severity: **{inv['severity'].upper()}** (detection severity; independent of model confidence).", ""]
    for b in inv["severity_basis"]:
        L.append(f"- {t(b)}")
    L.append("")
    if res:
        L += [f"**AI assessment:** {t(res['assessment'])} — confidence **{t(res['confidence']['level'])}** "
              f"(model-assigned; {t(res['confidence']['rationale'])})", "", t(res["summary"]), ""]
    else:
        L += ["_No AI investigation has been completed for this case; this report contains rule-based findings only._", ""]
    L += ["## 2. Investigation scope", "",
          f"- Events in dataset: {inv['scope']['dataset_events']}; evidence events cited by this case: {inv['scope']['evidence_events']}",
          f"- Time window of case: {t(inv['scope']['window'][0])} → {t(inv['scope']['window'][1])}",
          f"- Hosts: {', '.join(c(h) for h in inv['case']['hosts']) or 'none recorded'}",
          f"- Accounts: {', '.join(c(h) for h in inv['case']['users']) or 'none recorded'}",
          f"- IP addresses: {', '.join(c(h) for h in inv['case']['ips']) or 'none recorded'}", ""]
    L += ["## 3. Source and ingestion", ""]
    for u in src["uploads"]:
        s = u["summary"]
        L.append(f"- {c(u['filename'])} — format **{t(u['detected_format'])}**, sha256 {c(u['sha256'][:16] + '…')}, ingested {t(u['ingested_at'])}: "
                 f"accepted {s['accepted']}, rejected {s['rejected']}, unsupported {s['unsupported']}, "
                 f"unclassified {s['accepted_but_unclassified']}")
        for cv in s.get("caveats", []):
            L.append(f"  - Caveat: {t(cv)}")
    L.append("")
    L += ["## 4. Findings", ""]
    for f in inv["findings"]:
        L += [f"### {t(f['finding_id'])} — {t(f['title'])}", "",
              f"- **Origin / method:** {t(f['origin'])} / {t(f['detection_method'])} (`{f['rule_id']}`)",
              f"- **Severity (detection):** {f['severity']} — {t(f['severity_basis'])}",
              f"- **Evidence strength:** {t(f['evidence_strength'])}", f"- **Description:** {t(f['description'])}",
              f"- **Time range:** {t(f['first_seen'])} → {t(f['last_seen'])}",
              f"- **Evidence IDs ({f['evidence_total']}):** {', '.join(c(i) for i in f['evidence_ids'][:25])}"
              + (" …" if f['evidence_total'] > 25 else ""),
              f"- **Explanation:** {t(f['explanation'])}", f"- **Uncertainty:** {t(f['uncertainty'])}", ""]
    L += ["## 5. Attack timeline", "", "| Time (UTC) | Stage | Event | Summary |", "|---|---|---|---|"]
    for r in inv["timeline"][:150]:
        L.append(f"| {t(r['timestamp'])} | {t(r['stage'])} | {c(r['event_id'])} | {t(r['summary'])} |")
    if inv.get("timeline_truncated") or len(inv["timeline"]) > 150:
        L.append("\n_Timeline truncated; see the application for the full evidence list._")
    L += ["", "## 6. Indicators of compromise", "",
          "_Extracted locally from cited events. Presence here does not mean an indicator is malicious._", ""]
    for i in inv["iocs"][:100]:
        enr = i["enrichment"]
        L.append(f"- {t(i['type'])} {c(i['value'])}" + (f" ({t(i.get('scope'))})" if i.get("scope") else "")
                 + f" — {t('; '.join(i['roles'][:3]))} — evidence {', '.join(c(e) for e in i['evidence_ids'][:5])}"
                 + f" — enrichment: **{t(enr['status'])}**" + (f" ({t(enr.get('detail'))})" if enr.get("detail") else ""))
    L += ["", "## 7. MITRE ATT&CK mapping", "",
          "_OBSERVED = defining behaviour appears in the logs. SUSPECTED = inferred from a pattern. Neither proves malicious intent._", ""]
    for m in inv["mitre"]:
        L.append(f"- **{m['technique_id']} {t(m['name'])}** ({t(m['tactic'])}) — {m['status']} — rule-based — {t(' '.join(m['bases'][:1]))} "
                 f"Evidence: {', '.join(c(e) for e in m['evidence_ids'][:6])}")
    for m in inv.get("mitre_ai", []):
        L.append(f"- **{m['technique_id']} {t(m['name'])}** — {m['status']} — AI hypothesis (validated against dataset) — {t(m['basis'])} "
                 f"Evidence: {', '.join(c(e) for e in m['evidence_ids'][:6])}")
    if not inv["mitre"] and not inv.get("mitre_ai"):
        L.append("- No technique mapping is supported by the evidence.")
    L += ["", "## 8. Investigation steps and tool results", ""]
    if a.get("trace"):
        L.append(f"Provider: {t(a.get('provider'))} / model {t(a.get('model'))}; steps used {a.get('steps_used')} of {a.get('max_steps')}; status **{t(a.get('status'))}**.")
        L.append("")
        for s in a["trace"]:
            L.append(f"{s['step']}. **{t(s['type'])}** {t(s.get('tool', ''))} — {t(s.get('status'))}"
                     + (f" — why: {t(s['rationale'])}" if s.get("rationale") else "")
                     + (f" — result: {t(s['result_summary'])}" if s.get("result_summary") else "")
                     + (f" — {t(s['detail'])}" if s.get("detail") else ""))
        if a.get("error"):
            L.append(f"\n**Agent error:** {t(a['error'])}")
        for w in a.get("validation_warnings", []):
            L.append(f"- Validation: {t(w)}")
    else:
        L.append("No AI agent steps were executed. Rule evaluation is deterministic (see findings).")
    L += ["", "## 9. Alternative explanations, limitations and missing information", ""]
    if res:
        for h in res["hypotheses"]:
            L.append(f"- Hypothesis **{t(h['status'])}** — {t(h['title'])}: {t(h['description'])} "
                     f"Evidence: {', '.join(c(e) for e in h['evidence_ids'][:6]) or 'none'}")
        for x in res["alternative_explanations"]:
            L.append(f"- Alternative: {t(x)}")
        for x in res["missing_information"]:
            L.append(f"- Missing: {t(x)}")
    for f in inv["findings"]:
        L.append(f"- Limitation ({t(f['finding_id'])}): {t(f['uncertainty'])}")
    L += ["", "## 10. Recommended actions and analyst decisions", "",
          "_Sentinel AI executes no response action. A recorded approval is a decision record, not proof of execution._", ""]
    latest = {}
    for d in decisions:
        latest[d["recommendation_id"]] = d
    for r in inv["recommendations"]:
        d = latest.get(r["recommendation_id"])
        L.append(f"- [{t(r.get('origin'))}] {t(r['action'])} — {'DISRUPTIVE, ' if r['disruptive'] else ''}"
                 f"{'approval required' if r['requires_approval'] else 'no approval required'} — "
                 + (f"**{d['decision']}** by {t(d['actor'])} at {t(d['decided_at'])}; execution: **{t(d['execution_status'])}**"
                    if d else "**no decision recorded**"))
    if decisions:
        L += ["", "### Decision history", ""]
        for d in decisions:
            L.append(f"- {t(d['decided_at'])} — {t(d['actor'])} — {d['decision']} — {c(d['recommendation_id'])} — {t(d['note'] or '')}")
    return "\n".join(L) + "\n"
