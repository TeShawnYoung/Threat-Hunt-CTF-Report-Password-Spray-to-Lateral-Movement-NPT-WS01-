# Threat Hunt CTF Report: Password Spray to Lateral Movement (NPT-WS01)

## Platforms and Languages Leveraged
- Windows Server 2022 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Attacker tooling observed: NetExec (`nxc`) and WMI remote execution (wmiexec)

## Scenario

This was a capture-the-flag threat hunt (Module 1: Core Investigation Skills) run in a lab environment. The incident below is simulated.

Help Desk Ticket #4451 was received on 22 April 2026 at 09:14 UTC from Mark Smith in Finance, reporting on the machine `NPT-WS01`:

> "My machine was throwing login prompts at me through the night. I ignored it and went back to sleep. Seems fine this morning. Can someone take a look?"

The goal was to decide whether this was nothing or a real intrusion and, if real, to reconstruct what happened, what was touched and where the attacker ended up. The hunt was run in Microsoft Defender Advanced Hunting against `npt-ws01`, with a focus window of 22 April 2026, 04:30 to 06:00 UTC, and captured 11 flags along the way.

Per the NIST 800-61 Incident Response framework, this hunt and its findings are organized below across Preparation, Detection & Analysis, Containment, Eradication, Recovery, and Lessons Learned.

---

## Steps Taken

### 1. Preparation

Before hunting, a high-level plan was built to follow the attack from first logon to final foothold across the available EDR telemetry:

- **Check `DeviceLogonEvents`** for successful logons from accounts or addresses that do not belong on the host.
- **Check `DeviceProcessEvents`** for what the suspicious account ran, including persistence and account-creation commands.
- **Check `DeviceNetworkEvents`** for outbound command-and-control traffic.
- **Check `DeviceFileEvents`** for executables dropped in staging folders.
- **Check `DeviceRegistryEvents`** for Run-key persistence.
- **Check `AlertEvidence` and `DeviceInfo`** to scope the incident across the rest of the `npt-` fleet.

Every query was scoped with the same three variables:

```kql
let start_time = datetime(2026-04-21T00:00:00.00Z);
let end_time = datetime(2026-04-23T00:00:00.00Z);
let HostInQuestion = "npt-ws01";
```

---

### 2. Detection & Analysis

**Flags 1 & 2: Logon Events — Suspicious Network Logon**

> [!IMPORTANT]
> **Flag 1 objective:** Find the account the attacker succeeded with and then operated under.
>
> **Flag 2 objective:** Find the external IP address the attacker authenticated from.

**Flag 1 captured:** `helpdesk` (`DeviceLogonEvents` → `AccountName`)

**Flag 2 captured:** `20.110.92.50` (`DeviceLogonEvents` → `RemoteIP`)

Searched `DeviceLogonEvents` for every successful logon on `npt-ws01`. Among the accounts returned, `helpdesk` stood out: it was not Mark's own account and had no business logging on to his workstation.

```kql
let start_time = datetime(2026-04-21T00:00:00.00Z);
let end_time = datetime(2026-04-23T00:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceLogonEvents
| where TimeGenerated between (start_time .. end_time) 
| where DeviceName  == HostInQuestion
| where ActionType == "LogonSuccess"
```

<img width="1363" height="192" alt="image" src="https://github.com/user-attachments/assets/466d8487-b1fa-4131-9d1c-1f44bcd1bcd7" />

A second query narrowed the results to `helpdesk` and brought in the `RemoteIP` column. The logons came from the external IP address `20.110.92.50`. A local administrator account authenticating from a public address has no legitimate reason to occur on a Finance workstation.

```kql
let start_time = datetime(2026-04-21T00:00:00.00Z);
let end_time = datetime(2026-04-23T00:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceLogonEvents
| where TimeGenerated between (start_time .. end_time) 
| where DeviceName  == HostInQuestion
| where AccountName =="helpdesk"
| where ActionType == "LogonSuccess"
| project TimeGenerated, DeviceName, ActionType, AccountName, RemoteIP
```

<img width="873" height="157" alt="image" src="https://github.com/user-attachments/assets/bf38022d-5138-46e4-ae10-f5903a735744" />

**Flag 3: Process Events — Implant Execution**

> [!IMPORTANT]
> **Objective:** Find the command line that launched the implant.

**Flag captured:** `cmd.exe /Q /c start "" "C:\Windows\Temp\WindowsUpdate.exe"` (`DeviceProcessEvents` → `ProcessCommandLine`)

Searched `DeviceProcessEvents` for everything that ran under the `helpdesk` account. One command line silently launched a binary out of a Temp folder: `cmd.exe /Q /c start "" "C:\Windows\Temp\WindowsUpdate.exe"`. The quiet `/Q /c` pattern is the fingerprint of wmiexec-style remote execution.

```kql
let start_time = datetime(2026-04-21T00:00:00.00Z);
let end_time = datetime(2026-04-23T00:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time) 
| where DeviceName  == HostInQuestion
| where AccountName == "helpdesk"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

<img width="1530" height="105" alt="image" src="https://github.com/user-attachments/assets/120a0609-36dc-4a3a-acdc-2260457c0017" />

**Flag 4: Process Events — Parent Process**

> [!IMPORTANT]
> **Objective:** Identify the parent process that spawned that `cmd.exe`.

**Flag captured:** `wmiprvse.exe` (`DeviceProcessEvents` → `InitiatingProcessFileName`)

Re-ran the same query with the `InitiatingProcessFileName` column added to see what spawned that `cmd.exe`. The initiating process was `wmiprvse.exe`, the WMI provider host. This confirms the implant was started through remote WMI execution and not by a user sitting at the machine.

```kql
let start_time = datetime(2026-04-21T00:00:00.00Z);
let end_time = datetime(2026-04-23T00:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time) 
| where DeviceName  == HostInQuestion
| where AccountName == "helpdesk"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine,InitiatingProcessFileName
```

<img width="1386" height="123" alt="image" src="https://github.com/user-attachments/assets/1437f886-6547-458d-9497-217b517f517d" />

**Flag 5: Network Events — Command and Control**

> [!IMPORTANT]
> **Objective:** Find the command-and-control domain the host beaconed to.

**Flag captured:** `updates.abordasync.website` (`DeviceNetworkEvents` → `RemoteUrl`)

Searched `DeviceNetworkEvents` for connections made by processes running under the `helpdesk` account. Filtering on the compromised account cut out the normal system traffic, and the `RemoteUrl` column showed the command-and-control domain: `updates.abordasync.website`.

```kql
let start_time = datetime(2026-04-21T00:00:00.00Z);
let end_time = datetime(2026-04-23T00:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceNetworkEvents
| where TimeGenerated between (start_time .. end_time) 
| where DeviceName  == HostInQuestion
| where InitiatingProcessAccountName == "helpdesk"
| project TimeGenerated, DeviceName, ActionType, RemoteUrl, InitiatingProcessCommandLine, InitiatingProcessFileName
```

<img width="1423" height="94" alt="image" src="https://github.com/user-attachments/assets/9791d252-b3a5-458b-bd2b-10f89a60e928" />

**Flag 6: File Events — Dropped Implant**

> [!IMPORTANT]
> **Objective:** Find the SHA256 hash of the dropped implant.

**Flag captured:** `20cef6a013953890f9d38605d25d60dd63b42b09946bbb18ddb4a456da306e77` (`DeviceFileEvents` → `SHA256`)

Searched `DeviceFileEvents` on `npt-ws01` for any file event with `.exe` in its path. The query returned only a small number of results, so they could be reviewed by eye without any further filtering. One entry stood out: `WindowsUpdate.exe` sitting in `C:\Windows\Temp\`. A genuine Windows Update component has no reason to be in a Temp folder, so the file was out of place and was identified as the implant. Its SHA256 hash is `20cef6a013953890f9d38605d25d60dd63b42b09946bbb18ddb4a456da306e77`.

```kql
let start_time = datetime(2026-04-21T00:00:00.00Z);
let end_time = datetime(2026-04-23T00:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceFileEvents
| where TimeGenerated between (start_time .. end_time) 
| where DeviceName  == HostInQuestion
| where FolderPath contains ".exe"
| project Timestamp, DeviceName, ActionType, FolderPath, SHA256
```

<img width="1207" height="213" alt="image" src="https://github.com/user-attachments/assets/84c929a3-0412-4d63-963f-de0944b46e35" />

**Flag 7: Registry Events — Run-Key Persistence**

> [!IMPORTANT]
> **Objective:** Find the name of the Run-key value created for autostart persistence.

**Flag captured:** `WindowsHealthCheck` (`DeviceRegistryEvents` → `RegistryValueName`)

Searched `DeviceRegistryEvents` for events whose initiating command line contained `run`, which catches commands that write to the Run keys. The `RegistryValueName` column showed a value named `WindowsHealthCheck`, disguised as a legitimate health task.

```kql
let start_time = datetime(2026-04-21T00:00:00.00Z);
let end_time = datetime(2026-04-23T00:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceRegistryEvents 
| where TimeGenerated between (start_time .. end_time) 
| where DeviceName  == HostInQuestion
| where InitiatingProcessCommandLine contains "run"
| project TimeGenerated, DeviceName, ActionType, RegistryValueName, InitiatingProcessCommandLine
```

<img width="1463" height="170" alt="image" src="https://github.com/user-attachments/assets/56810ac8-7e47-4961-9a53-886ab914e5f7" />

**Flag 8: Process Events — Scheduled-Task Persistence**

> [!IMPORTANT]
> **Objective:** Find the name of the scheduled task created for persistence.

**Flag captured:** `GoogleUpdaterTask` (`DeviceProcessEvents` → `ProcessCommandLine` (the `/tn` value))

Searched `DeviceProcessEvents` for command lines containing `tn`, the task-name switch used by `schtasks.exe`. The `/tn` argument shows a task named `GoogleUpdaterTask`, impersonating a well-known software updater.

```kql
let start_time = datetime(2026-04-21T00:00:00.00Z);
let end_time = datetime(2026-04-23T00:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time) 
| where DeviceName  == HostInQuestion
| where ProcessCommandLine contains "tn"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

<img width="1445" height="188" alt="image" src="https://github.com/user-attachments/assets/9df660d8-09f4-4001-a97a-0a814b74dfd7" />

**Flag 9: Process Events — Service Persistence**

> [!IMPORTANT]
> **Objective:** Find the name of the Windows service installed to run the implant.

**Flag captured:** `WindowsHealthSvc` (`DeviceProcessEvents` → `ProcessCommandLine` (`sc.exe create`))

Searched `DeviceProcessEvents` for command lines containing `sc.exe create`. The attacker installed a service named `WindowsHealthSvc`, masquerading as a Windows health service, with its `binPath` pointing at the implant.

```kql
let start_time = datetime(2026-04-21T00:00:00.00Z);
let end_time = datetime(2026-04-23T00:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time) 
| where DeviceName  == HostInQuestion
| where ProcessCommandLine contains "sc.exe create"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
```

<img width="1445" height="113" alt="image" src="https://github.com/user-attachments/assets/64f3b38e-4b0e-4ad1-919d-645f48b0aede" />

**Flag 10: Process Events — Backdoor Account**

> [!IMPORTANT]
> **Objective:** Find the backdoor local account the attacker created and promoted to Administrators.

**Flag captured:** `nexus_admin` (`DeviceProcessEvents` → `ProcessCommandLine` (`net user ... /add`))

Searched `DeviceProcessEvents` for command lines containing `user`. The results showed the `net user ... /add` command that created the local account `nexus_admin`, the attacker's backdoor into the machine.

```kql
let start_time = datetime(2026-04-21T00:00:00.00Z);
let end_time = datetime(2026-04-23T00:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time) 
| where DeviceName  == HostInQuestion
| where ProcessCommandLine contains "user"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
```

<img width="1357" height="221" alt="image" src="https://github.com/user-attachments/assets/99065a04-b415-4ebb-8f82-358ed187cb1b" />

**Flag 11: Alert Evidence — Second Host**

> [!IMPORTANT]
> **Objective:** Find the second host the attacker moved toward.

**Flag captured:** `npt-srv01` (`AlertEvidence` → `DeviceName`)

Searched `AlertEvidence` for other `npt-` devices carrying a lateral-movement alert. One other host, `npt-srv01`, appeared with the alert "Azure RunScript used to deploy malicious code", so containment was extended to it.

```kql
let start_time = datetime(2026-04-21T00:00:00.00Z);
let end_time = datetime(2026-04-23T00:00:00.00Z);
let HostInQuestion = "npt-ws01";
AlertEvidence
| where Timestamp between (start_time .. end_time)
| where DeviceName startswith "npt-" and DeviceName != HostInQuestion
| where Categories has "LateralMovement"
| project Timestamp, DeviceName, Title, Categories, AttackTechniques
```

<img width="1176" height="342" alt="image" src="https://github.com/user-attachments/assets/b28c7b7f-fd81-422a-863a-7d80a880a3c7" />

**Alert Evidence — Attacker Tooling**

A second alert in `AlertEvidence`, "Network service exploitation tool activity", recorded the attacker's own tooling. It ran on the host `npt-c2-01`, whose public IP address in `DeviceInfo` is `20.110.92.50`. The commands show a Remote Desktop password spray against `npt-ws01`, followed seven seconds later by an SMB upload of the implant using the `helpdesk` credentials. The same table shows `helpdesk` being created through Azure Run Command and added to Administrators and Remote Desktop Users a few hours earlier.

```
nxc rdp 172.200.177.145 -u /tmp/gf-users.txt -p **********
nxc smb 172.200.177.145 -u helpdesk -p ********** --put-file /tmp/WindowsUpdate.exe \Windows\Temp\WindowsUpdate.exe --share C$
```

```kql
let start_time = datetime(2026-04-21T00:00:00.00Z);
let end_time = datetime(2026-04-23T00:00:00.00Z);
let HostInQuestion = "npt-ws01";
AlertEvidence
| where Timestamp between (start_time .. end_time)
| where EntityType == "Process"
| where ProcessCommandLine has_any ("nxc", "helpdesk")
| summarize FirstSeen = min(Timestamp) by ProcessCommandLine
| order by FirstSeen asc
```

<!-- SCREENSHOT: paste query results image here -->

**Indicators Observed**

- Attacker IP address: `20.110.92.50`
- C2 domain: `updates.abordasync.website`
- Implant: `C:\Windows\Temp\WindowsUpdate.exe`
- Implant SHA256: `20cef6a013953890f9d38605d25d60dd63b42b09946bbb18ddb4a456da306e77`
- Execution: `cmd.exe /Q /c start "" "C:\Windows\Temp\WindowsUpdate.exe"` spawned by `wmiprvse.exe`
- Run-key value: `WindowsHealthCheck`
- Scheduled task: `GoogleUpdaterTask`
- Service: `WindowsHealthSvc`
- Compromised account: `helpdesk`
- Attacker-created account: `nexus_admin` (member of Administrators)
- Second host in scope: `npt-srv01`

**Event Timeline**

| Time (UTC) | Event |
|---|---|
| 21 Apr 23:38 | Defender raises a lateral-movement alert on `npt-srv01` |
| 22 Apr 01:03 | `helpdesk` is created on `npt-ws01` through Azure Run Command and added to Administrators and Remote Desktop Users |
| 22 Apr 03:47 | NetExec on `npt-c2-01` sprays Remote Desktop on `npt-ws01`, then uploads `WindowsUpdate.exe` over SMB as `helpdesk` |
| 22 Apr 04:30 to 06:00 | `helpdesk` logs on from `20.110.92.50`. The implant is launched through WMI and beacons to `updates.abordasync.website` |
| 22 Apr 04:30 to 06:00 | Persistence is set with `WindowsHealthCheck`, `GoogleUpdaterTask` and `WindowsHealthSvc`. `nexus_admin` is created and added to Administrators |
| 22 Apr 09:14 | Mark Smith reports overnight login prompts (Ticket #4451) |

---

### 3. Containment

Short-Term Containment:

- Isolate `npt-ws01` and `npt-srv01` in Microsoft Defender for Endpoint. Leave both powered on so memory and logs are preserved.
- Collect a Defender investigation package and a copy of the implant from each host before any clean-up.
- Disable the accounts `helpdesk` and `nexus_admin`, and reset the password for `m.smith`.
- Block the IP address `20.110.92.50` and the domain `updates.abordasync.website`, and add the implant SHA256 as a Defender file indicator set to Block and Remediate.

Long-Term Containment:

- Remove inbound Remote Desktop (3389) and SMB (445) from the internet on both hosts.
- Establish who owns `npt-c2-01` and the account that ran the attack tooling on it, and deallocate the VM if it sits in the organization's own subscription.
- Hunt for the file hash, domain, IP address and artifact names across every `npt-` host.

---

### 4. Eradication

Remove Artifacts:

- Stop and delete the implant `C:\Windows\Temp\WindowsUpdate.exe`.
- Delete the Run-key value `WindowsHealthCheck`.
- Delete the scheduled task `GoogleUpdaterTask` (`schtasks /delete /tn GoogleUpdaterTask /f`).
- Stop and delete the service `WindowsHealthSvc` (`sc.exe delete WindowsHealthSvc`).
- Delete the backdoor account `nexus_admin` and its profile.
- Repeat the same checks on `npt-srv01`.

Patch/Remediate Gaps:

- Keep `helpdesk` disabled. If the account is needed, recreate it with a unique password and without Remote Desktop rights.
- Use Windows LAPS for unique local administrator passwords and enforce an account lockout policy.
- Restrict Azure Run Command through role-based access control.

---

### 5. Recovery

System Validation:

- Rebuild `npt-ws01` from a known-good image. The attacker held administrator rights and planted several footholds, so removing the artifacts is not enough to trust the machine again.
- Confirm that none of the artifacts are present and that there are no connections to `20.110.92.50` or `updates.abordasync.website` before either host returns to service.
- Reset all local account passwords on both hosts and any credentials Mark Smith used on the workstation.

Reintegration:

- Release `npt-srv01` from isolation only once the hunts are clean and its logons have been reviewed. Otherwise rebuild it as well.
- Monitor both hosts for 30 days for the indicators above and for new local accounts, services and scheduled tasks.

---

### 6. Lessons Learned

Root Cause: Remote Desktop and SMB on `npt-ws01` were reachable from the internet, and a local administrator account with a guessable password was a member of Remote Desktop Users. A password spray succeeded and nothing stopped it before the attacker was in.

Detection Improvements:

- Alert on a successful network logon from a public IP address that follows a run of failures.
- Alert on `wmiprvse.exe` spawning `cmd.exe /Q /c`.
- Alert on executables written to `C:\Windows\Temp` that are then registered as a service, scheduled task or Run key.
- Alert on `net user /add` followed by an addition to the Administrators group.

Response Enhancements:

- Defender recorded attacker activity at 03:47 UTC, yet the incident was opened by a user at 09:14 UTC. Set response targets for medium and high alerts so triage does not wait for a ticket.
- Put Remote Desktop behind Azure Bastion, a VPN or just-in-time access.
- Ask staff to report unexpected login prompts straight away.

---

## Summary

The investigation confirmed that this was a real intrusion and not a false alarm. An attacker operating from `20.110.92.50` password-sprayed Remote Desktop on `npt-ws01`, logged on as the local administrator account `helpdesk`, uploaded the implant `WindowsUpdate.exe` over SMB and ran it through WMI. The implant beaconed to `updates.abordasync.website`. The attacker then established persistence three ways (a Run key, a scheduled task and a service), created the backdoor administrator account `nexus_admin` and moved toward a second host, `npt-srv01`.

## Response Taken

The intrusion on `npt-ws01` was confirmed and scoped to a second host, `npt-srv01`. A containment and remediation plan covering both hosts was produced and is set out above.
