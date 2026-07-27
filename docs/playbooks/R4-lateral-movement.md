# Playbook - Service Account Network Logon (SMB Lateral Movement)

| | |
|---|---|
| **Detection rule** | 100400 (level 12) |
| **MITRE ATT&CK** | T1021.002 (SMB/Windows Admin Shares), T1078.002 (Valid Accounts: Domain) |
| **Data source** | Windows Security log, Event ID 4624 (Successful Logon) |
| **Severity** | High / Critical (especially following a Kerberoasting alert for the same account) |
| **Trigger** | A network logon (`logonType = 3`) succeeds for a monitored service account |

A service account authenticating over the network is not inherently malicious - context decides. Following a Kerberoasting alert for the same account, it strongly indicates the password was cracked and the valid credential is now being used to reach resources, i.e. lateral movement.

---

## Triage (first 10 minutes)

1. **Confirm the pattern** - `targetUserName` is a service account and `logonType = 3`. Establish whether this account normally performs network logons and to which hosts (its baseline).
2. **The decisive correlation** - did a Kerberoasting alert fire for this same account recently? If yes, treat as confirmed use of a cracked credential - critical, do not downgrade.
3. **Source** - the origin IP/host. Is it the account's expected host, or a workstation/segment it has no reason to authenticate from? Unexpected source is a strong malicious signal.
4. **Auth package** - Kerberos vs NTLM, consistent with a cracked-ticket reuse or a pass-the-hash style reuse respectively.

**Escalate to Tier 2 / IR immediately if:** a Kerberoasting alert preceded this for the same account, or the logon originates from an unexpected host/segment. Roast-then-logon is the smoking gun for a completed credential-theft-to-access chain.

---

## Investigation

- Chain the alerts into a single narrative: initial access -> recon -> Kerberoasting -> this logon. If the earlier stages fired, the intrusion has reached its objective.
- Identify what the logon accessed - correlate with share/file access on the destination. Determine whether sensitive data was read or copied.
- Look for staging and exfiltration: file copy off the target, then transfer off-host. Note that a logon event is only a proxy for file access - direct visibility needs file-access auditing / FIM (a common coverage gap).
- Scope the blast radius: with a valid service credential, enumerate everywhere that account and its groups can authenticate.

**On re-triggering:** this detection fires on new logon-session establishment, not per-file access. Re-using SMB inside an existing session does not generate a new 4624 - a fresh session is required. This is correct behaviour, not a gap: the meaningful moment is the credential being used to establish access.

---

## Containment

1. **Rotate the service account's password immediately** if not already done at the Kerberoasting stage - this kills the attacker's access, since the cracked password stops working.
2. Kill active sessions for the account on the destination host; invalidate tickets (rotate twice for krbtgt-dependent scenarios if escalation to domain-level ticket forging is suspected).
3. Isolate the source host.
4. Lock down the accessed resource - verify only intended principals have access; revoke anything unexpected.

---

## Eradication & recovery

- Complete credential rotation / gMSA migration for the service account.
- Verify the legitimate service still functions under the new secret.
- Restore any affected data from backup if integrity is in question.

**Preventive hardening**

- Migrate the account to gMSA - removes both the roasting and the reusable-password problem.
- Restrict service-account logon rights: `Deny access to this computer from the network` / `Deny interactive logon` scoped so the account can only authenticate where it legitimately needs to.
- Add file-access auditing / FIM on sensitive shares so file-level access is visible, not just the logon.
- Review the group model (AGDLP or equivalent) to confirm least privilege on the accessed resource.

---

## False positives

- The service account performing its legitimate function (a service that genuinely authenticates to other hosts over the network). This is why a per-account baseline is essential.
- Backup, monitoring, or management agents running under the account.
- Scheduled tasks or scripts that map shares under the service identity.

Tuning: baseline each monitored service account's expected source hosts and logon types; alert on deviation (unexpected source, unexpected logon type) rather than on every network logon. The correlation with a preceding Kerberoasting alert is what elevates this from noise to critical.

---

## IOCs to collect (per incident)

- Service account used and its logon type / auth package.
- Source host/IP of the logon.
- Destination host and the specific resource accessed.
- Any file read/copied and its onward transfer destination.

---

## Detection notes

- Detects new logon-session establishment, not per-file access - see the re-triggering note above.
- Highest fidelity when correlated with a preceding Kerberoasting detection for the same account; in isolation a service-account network logon has many benign explanations, so the correlation is what carries the signal.
