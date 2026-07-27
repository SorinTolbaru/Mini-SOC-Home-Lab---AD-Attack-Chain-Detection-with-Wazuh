# Playbook - Kerberoasting (RC4 Service Ticket)

| | |
|---|---|
| **Detection rule** | 100300 (level 12) |
| **MITRE ATT&CK** | T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting) |
| **Data source** | Windows Security log, Event ID 4769 (Kerberos Service Ticket Requested) |
| **Severity** | High / Critical (depends on privilege of the targeted service account) |
| **Trigger** | A 4769 for a service account with `ticketEncryptionType = 0x17` (RC4) and `status = 0x0` (success) |

A domain controller issued an RC4-encrypted service ticket for an account with an SPN. Because modern clients negotiate AES, an RC4 service-ticket request for a service account is anomalous and is the defining signature of Kerberoasting: the actor collects the ticket and cracks the account's password offline, beyond the reach of any lockout policy.

---

## Triage (first 10 minutes)

1. **Encryption type** - confirm `0x17` (RC4). This is the core signal; a legacy client or app may explain a single RC4 request, but for a service account it warrants investigation.
2. **Requestor** - which source host/IP requested the ticket, and which user account made the request? Map both.
3. **Target service account** - what does it have access to, and how privileged is it? A ticket for a low-value account differs sharply from one for an account with admin rights or access to crown-jewel data. This drives severity.
4. **Volume and spread** - one 4769, or many across multiple SPNs from one source in a short window? Bulk RC4 requests indicate automated roasting of the whole domain - critical.

**Escalate to Tier 2 / IR immediately if:** RC4 request for a privileged/high-value service account, bulk SPN roasting, or the requesting host already triggered an earlier stage (initial access, recon).

---

## Investigation

- Correlate the requestor to earlier kill-chain activity on the same host/identity (initial access, PowerShell recon). A prior recon stage that enumerated SPNs strongly implies deliberate roasting.
- Assess crack feasibility - the pivotal question. Check the service account's password length, age, and complexity. A weak or old password means **assume the crack will succeed**; do not wait for proof.
- Enumerate the full exposure: every SPN-bearing account in the domain is a potential target. Identify all of them and their password posture, not just the one in the alert.
- Watch for the follow-on: a subsequent successful logon as the targeted service account from an unexpected source is credential reuse (lateral movement) and confirms the crack succeeded.

---

## Containment

1. **Treat the targeted service account as compromised.** Assume the offline crack will succeed - this is the safe default for RC4 roasting.
2. **Rotate the account's password now** to a long, random value (25+ characters). This invalidates any ticket the actor cracks.
3. Isolate the requesting host if it maps to a workstation with no legitimate need for service-ticket requests at scale.
4. Heighten monitoring for logons using the targeted account.

---

## Eradication & recovery

- Complete rotation and confirm the service still functions under the new secret.
- If lateral movement already occurred, pivot to the lateral-movement / incident process.

**Preventive hardening**

- Migrate service accounts to **Group Managed Service Accounts (gMSA)** - automatic 120-character rotation removes the Kerberoasting value entirely.
- Where gMSA is not possible: enforce 25+ character random passwords and set the account to AES-only (`msDS-SupportedEncryptionTypes`), disabling RC4.
- Audit every SPN-bearing account across the domain for password strength and encryption support.
- Deploy a honeytoken SPN account - any 4769 for it is a near-zero-false-positive roasting alert.

---

## False positives

- Legacy applications or appliances that genuinely negotiate RC4 (older Java stacks, some third-party services). Establish a documented baseline of expected RC4 for known accounts.
- Vulnerability scanners or authorised red-team tooling requesting tickets.
- A one-off RC4 request from a single legacy client differs from bulk requests or requests tied to a compromised host - context decides.

Tuning: baseline expected RC4-using service accounts and exclude them explicitly; keep the detection tight on unexpected accounts. Never blanket-suppress RC4 4769 events.

---

## IOCs to collect (per incident)

- Targeted service account and its SPN.
- Requesting host/IP and requesting user.
- Ticket encryption type and options from the 4769.
- Any cracked credential (record its existence for rotation tracking; never store the plaintext in shared artifacts).

---

## Detection notes

- This is typically the highest-value detection in an AD intrusion chain and a good candidate for real-time alerting/escalation (e.g. to a chat channel), because the RC4-for-service-account signature is high-fidelity.
- Detects the roasting request, not the offline crack (which produces no telemetry). The value is the window it creates: rotating the account on this alert defeats the attack before the cracked credential can be used.
