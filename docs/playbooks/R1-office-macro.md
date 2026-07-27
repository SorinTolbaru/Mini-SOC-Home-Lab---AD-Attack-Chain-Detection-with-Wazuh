# Playbook - Office Application Spawning a Command Interpreter

| | |
|---|---|
| **Detection rule** | 100100 (level 12) |
| **MITRE ATT&CK** | T1566.001 (Spearphishing Attachment), T1204.002 (Malicious File), T1059.001 (PowerShell) |
| **Data source** | Sysmon Event ID 1 (Process Creation) |
| **Severity** | High |
| **Trigger** | An Office binary (`WINWORD.EXE`, `EXCEL.EXE`, `POWERPNT.EXE`) spawns a command interpreter (`cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`) |

Office applications do not normally launch script interpreters. This parent-child relationship is a high-confidence indicator of macro-borne code execution and is a common initial-access vector.

---

## Triage (first 10 minutes)

Answer these in order; the goal is a benign / malicious / escalate decision, not full attribution.

1. **Parent legitimacy** - is `parentImage` a genuine Office install path, or a renamed/relocated binary (e.g. under `%TEMP%`, `%APPDATA%`)? A lookalike path is malicious on its own.
2. **Child command line** - the strongest single signal. Encoded (`-enc`, `-e`), hidden (`-w hidden`), download cradles (`IEX`, `Invoke-WebRequest`, `DownloadString`), or a bare `cmd.exe` with no arguments (typical process-migration host) all raise confidence. A recognised add-in or updater lowers it.
3. **User and asset context** - which user/role, and does that role routinely open external documents (HR, finance, reception, recruiting)? Higher-exposure roles raise priority.
4. **Immediate follow-on** - did the child spawn further children, open a network connection (EID 3), or write files (EID 11) within seconds? Progression means active execution, not a one-off.

**Escalate to Tier 2 / IR if any of:** encoded or hidden interpreter, download cradle, lookalike parent path, an outbound connection immediately after spawn, or a related detection already firing on the same host.

---

## Investigation

- Reconstruct the process tree around the child PID: EID 1 (creation), EID 3 (network), EID 11 (file writes), EID 22 (DNS). Establish parent, siblings, and children.
- Check for an outbound connection shortly after the spawn - a C2 callback is the confirming artifact. Note destination and port (attackers commonly use 443 to blend with HTTPS).
- Locate the source document via the Office MRU and the user's download/mail directories; identify file type (`.docm`, `.xlsm`, `.pptm`) and origin.
- Pull mail and web-proxy logs to establish delivery - attachment, link, or removable media.
- Correlate across the kill chain: is there subsequent PowerShell recon, credential access, or lateral movement on this host or identity? If so, treat as an active intrusion and open an incident.

---

## Containment

1. Network-isolate the host to sever C2 while preserving it for forensics (isolate, do not power off - powering off loses volatile memory).
2. Capture volatile data (memory, active connections, process list) if IR policy requires, then terminate the malicious process tree.
3. Disable or force-reset the affected user account if credential theft is plausible.
4. Preserve the source document and relevant Sysmon logs before any reimage.

---

## Eradication & recovery

- Reimage the host - macro loaders frequently install persistence (Run keys, scheduled tasks, WMI subscriptions) beyond the initial process.
- Reset the user's credentials and clear cached domain secrets.
- Restore from a known-good image and confirm agent telemetry resumes before returning to service.

**Preventive hardening**

- Block macros in files from the internet via GPO (Mark-of-the-Web); allow signed macros only.
- Consider Attack Surface Reduction rules that block Office from creating child processes.
- Reinforce user-awareness for the phishing vector if that was the delivery method.

---

## False positives

Legitimate causes exist and must be ruled out, not assumed:

- Enterprise add-ins, document-automation, or reporting tools that legitimately shell out.
- Software-deployment or management agents invoking Office in automation.
- Developer or admin macros in controlled environments.

Tuning: allow-list by full signed binary path **and** expected command-line pattern, never by process name alone. A bare interpreter spawn with a suspicious command line is never a candidate for allow-listing.

---

## IOCs to collect (per incident)

Recorded during response and fed to the incident report / threat-intel - not hard-coded here:

- Full path and hash of the source document and any dropped payload.
- Child process command line and any decoded/base64 content.
- C2 destination (IP / domain / port) and DNS lookups from the process.
- Compromised user and host identifiers.

---

## Detection notes

- The rule keys on the parent-child relationship, not a payload signature - it catches any Office-spawned interpreter regardless of the specific macro.
- With in-memory payloads, enabling the macro alone may produce no EID 1; the process-creation event often appears only when the payload migrates to a host process. Detection therefore depends on that migration or any child-process spawn.
