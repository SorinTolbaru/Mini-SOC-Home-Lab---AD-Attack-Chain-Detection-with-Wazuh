# Group Policy Objects

Three custom GPOs drive the lab. Two exist to generate telemetry (audit policy, PowerShell logging); one is baseline hardening (account policy). Without the first two, the detection rules have nothing to fire on — the audit policy is what makes 4769/4624 appear in the Security log, and Script Block Logging is what makes 4104 appear at all.

---

## SOC - Domain Controller Audit Policy

**Linked to:** Domain Controllers OU
**Link order:** 1 — must sit above the Default Domain Controllers Policy, otherwise its settings get overwritten.

**Settings** (Computer Config → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration):

| Category | Subcategory | Setting |
|----------|-------------|---------|
| Account Logon | Audit Kerberos Service Ticket Operations | Success |
| Logon/Logoff | Audit Logon | Success |

This is what turns on the two events the DC-side rules depend on:

- **4769** (Kerberos service ticket requested) — the event R3 keys on for Kerberoasting. Every TGS request lands here, so an RC4 ticket for a service account stands out.
- **4624** (successful logon) — the event R4 keys on for the `svc-payroll` network logon during lateral movement.

> During testing, user-account logons weren't showing up on the DC even with this GPO applied — only machine-account (`$`) events came through. The GPO alone wasn't enough: the `Credential Validation` and `Kerberos Authentication Service` subcategories were still on *No Auditing* at the effective policy level. Fixed by enabling them directly with `auditpol` and restarting the manager. Worth noting because it's a real lesson: the GPO sets intent, but the effective audit policy is what actually decides whether the event gets written.

---

## SOC - PowerShell Logging

**Linked to:** HR OU (the workstation is where the macro runs and recon happens).

**Settings** (Computer Config → Policies → Administrative Templates → Windows Components → Windows PowerShell):

| Policy | Setting |
|--------|---------|
| Turn on PowerShell Script Block Logging | Enabled |
| Turn on Module Logging | Enabled |

Script Block Logging writes **event 4104** to `Microsoft-Windows-PowerShell/Operational` with the actual script text — de-obfuscated where Windows can manage it. That's what R2 matches against to catch PowerView.

The reason this matters: PowerView, Kerberoast tooling, and most post-exploitation recon run as PowerShell. Without 4104 the commands are invisible to the SIEM — the process runs, but nothing readable reaches the log. This GPO is the difference between "PowerShell ran" and "PowerShell ran `Get-DomainUser`."

---

## SOC - Account Policies

**Linked to:** domain root (`aztek.com`)
**Link order:** 1 — above the Default Domain Policy so these values win.

**Password Policy:**

| Setting | Value |
|---------|-------|
| Enforce password history | 24 |
| Maximum password age | 90 days |
| Minimum password age | 1 day |
| Minimum password length | 14 |
| Password must meet complexity requirements | Enabled |
| Store passwords using reversible encryption | Disabled |

**Account Lockout Policy:**

| Setting | Value |
|---------|-------|
| Account lockout threshold | 5 attempts |
| Account lockout duration | 15 minutes |
| Reset lockout counter after | 15 minutes |

This one is prevention, not detection. The 14-character minimum is the direct answer to the Phase 4 gap: offline Kerberoast cracking has no host telemetry, so the defensive control is making the hash expensive to crack in the first place. A short `svc-payroll` password falls to Hashcat in seconds; a 14-char one shifts the economics. Min password age of 1 day stops the trick of cycling through 24 passwords in one sitting to get back to a favourite.