# Playbook - PowerView / Active Directory Reconnaissance

| | |
|---|---|
| **Detection rule** | 100200 (level 12) |
| **MITRE ATT&CK** | T1059.001 (PowerShell), T1087.002 (Account Discovery: Domain), T1069.002 (Group Discovery: Domain), T1135 (Network Share Discovery) |
| **Data source** | PowerShell Script Block Logging, Event ID 4104 (`Microsoft-Windows-PowerShell/Operational`) |
| **Severity** | High |
| **Trigger** | A logged script block matches PowerView cmdlets or signatures (matched via PCRE2 on `scriptBlockText`) |

PowerView is a domain-enumeration toolkit. Its execution on a workstation is a strong post-compromise indicator that an actor is mapping the domain for a path to privilege or data.

---

## Triage (first 10 minutes)

1. **Read the script block** - which cmdlets ran? Targeted queries (`Get-NetUser -SPN`, `Get-DomainGroupMember` on privileged groups, ACL enumeration) indicate intent beyond casual discovery and raise priority over a single `Get-Domain`.
2. **User and host legitimacy** - does this identity/host have any business reason to run domain-enumeration tooling? Standard user workstations do not. Admin/pentest hosts may - confirm against change records.
3. **Execution context** - was an execution-policy bypass (`Set-ExecutionPolicy Bypass -Scope Process`) logged immediately before? Common precursor to running downloaded offensive scripts.
4. **Kill-chain position** - did an initial-access detection (Office-spawned interpreter) fire earlier on the same host? Recon following a foothold is a progressing intrusion.

**Escalate to Tier 2 / IR if any of:** SPN enumeration, privileged-group membership queries, ACL/trust enumeration, or a prior initial-access alert on the same host/identity.

---

## Investigation

- Retrieve the full 4104 sequence for the session and reconstruct exactly what was enumerated: users, SPNs, shares, group memberships, ACLs, trusts.
- Determine what the recon exposed - specifically any SPN-bearing (kerberoastable) accounts and any sensitive shares. These become the attacker's next targets; flag them for heightened monitoring.
- Recover the tooling from disk (download folders, `%TEMP%`) and establish how it arrived (agent upload, download cradle, removable media).
- Trace parent-process lineage to tie the PowerShell back to the initial foothold.
- Correlate forward: did a Kerberoasting or lateral-movement detection follow on the enumerated accounts? Recon-to-roast is the expected progression.

---

## Containment

1. Isolate the host if not already contained from a prior stage.
2. Terminate the PowerShell session / offending process tree.
3. Flag every enumerated privileged and service account for heightened monitoring and prioritised credential rotation.
4. Preserve the 4104 logs and any recovered scripts.

---

## Eradication & recovery

- Reimage the host.
- Rotate credentials for accounts that were enumerated, prioritising SPN-bearing service accounts.
- Confirm telemetry resumes post-restore.

**Preventive hardening**

- Keep Script Block Logging enabled on all endpoints - it is what makes offensive PowerShell visible.
- Consider Constrained Language Mode and/or AppLocker/WDAC in high-risk OUs to limit offensive PowerShell.
- Review whether enumerated SPN accounts need SPNs at all, or can move to gMSA to remove Kerberoasting exposure.

---

## False positives

- Administrators using legitimate AD-management scripts or modules (`ActiveDirectory` module cmdlets can superficially resemble recon).
- Security tooling, inventory, or attack-surface-management products enumerating the domain on schedule.
- Authorised red-team / pentest activity - confirm against engagement records before dismissing.

Tuning: scope expected admin/tooling hosts and service accounts; match on PowerView-specific signatures (function names, in-memory module strings) rather than generic verbs that overlap with the native AD module.

---

## IOCs to collect (per incident)

- Hash and path of the recon script.
- The enumerated objects (accounts, SPNs, shares, groups) - defines attacker knowledge and likely next targets.
- Executing identity and host.
- Parent process that launched PowerShell.

---

## Detection notes

- Relies on Script Block Logging (4104), enabled by GPO. Without it the commands are invisible - the process runs but nothing readable reaches the log.
- Matching on cmdlet/signature via PCRE2 is resilient to variable and whitespace obfuscation that a plain string match would miss; heavy obfuscation or renamed functions can still evade and is a known limitation.
