"""Small, explicit ATT&CK catalogue. A technique is only attached to a finding by a rule that cites why.

Status semantics (neither implies malicious intent was proven):
  OBSERVED  - the technique's defining action appears directly in the log evidence.
  SUSPECTED - the technique is inferred from a pattern; the logs alone cannot confirm it.
"""
TECHNIQUES = {
    "T1110":     ("Brute Force", "Credential Access"),
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1110.003": ("Brute Force: Password Spraying", "Credential Access"),
    "T1078":     ("Valid Accounts", "Initial Access"),
    "T1136.001": ("Create Account: Local Account", "Persistence"),
    "T1098":     ("Account Manipulation", "Persistence"),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", "Persistence"),
    "T1571":     ("Non-Standard Port", "Command and Control"),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", "Defense Evasion"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "Persistence"),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "Persistence"),
}


def technique(tid: str, status: str, basis: str, evidence_ids: list[str]) -> dict:
    name, tactic = TECHNIQUES[tid]
    assert status in ("OBSERVED", "SUSPECTED")
    return {"technique_id": tid, "name": name, "tactic": tactic, "status": status, "basis": basis,
            "evidence_ids": evidence_ids[:200]}
