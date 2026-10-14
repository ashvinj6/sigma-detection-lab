# Lab setup

This guide walks through building the Windows lab, running Atomic Red Team
tests, and turning the resulting logs into fixtures for this repo. It
assumes you have never done this before. Follow the steps in order.

What you end up with:

- a Windows 11 VM with Sysmon and extra audit logging turned on
- Atomic Red Team installed and ready to run the tests listed below
- `.evtx` log exports from each test, plus a benign baseline
- JSON fixtures in `fixtures/`, made with `tools/evtx_to_fixture.py`

Budget a weekend for the first setup. After that, each technique takes
about an hour.

## Safety first

Atomic Red Team runs real attacker techniques. Some tests dump credentials
or change how Windows starts up. Treat the VM as disposable and dirty.

- **Never run any of this on your real computer**, a school machine, or a
  work machine. Only inside the lab VM.
- **Isolate the VM.** Use NAT networking while installing tools. Before
  running any test, switch the VM's network adapter to **host-only**, or
  disconnect it. There is one exception, noted under T1547.001.
- **Turn off shared folders, shared clipboard, and drag and drop** in the VM
  settings. The only time a shared folder is on is the export step, after
  cleanup, with the VM about to be reverted. See [Step 9](#step-9-export-the-logs).
- **Take a snapshot before every test session** and revert to it when you
  finish. Snapshots are cheap. A half-cleaned VM gives you confusing data.
- **Use throwaway names.** Use a local account (not your Microsoft
  account), the user name `labadmin`, and the computer name `LAB-WIN11`.
  Everything in the logs ends up in a public repo, so nothing in the VM
  should identify you, your school, or any employer.
- **Do not commit `.evtx` files or tools.** `.gitignore` already blocks
  `*.evtx`. Only the JSON fixtures go in the repo, and never copy ProcDump,
  Mimikatz, or other tool binaries out of the VM.
- **Defender gets disabled inside the VM** (Step 3), because it blocks most
  of these tests. That is one more reason the VM must stay isolated.

## Step 1: Pick a hypervisor

A hypervisor is the program that runs the virtual machine.

Your Mac has Apple Silicon, so it can only run the ARM64 build of Windows.
That works, and Windows 11 on ARM runs x64 programs through built-in
emulation, so the Atomic tools work too. Free options:

- **VMware Fusion Pro**, free for personal use. Snapshots are easy.
- **UTM**, free and open source. Also fine.

Give the VM at least 4 CPU cores, 8 GB of RAM, and 80 GB of disk.

If a test fails because of ARM (a tool refuses to run under emulation),
write down which one. That is useful information for the write-up, not a
reason to give up on the technique.

## Step 2: Install Windows 11

1. Download the **Windows 11 ARM64 ISO** from Microsoft's official download
   page. You can skip activation for a lab.
2. Create the VM from the ISO and install. When setup asks for a Microsoft
   account, choose the offline or "domain join instead" option and create a
   local account named `labadmin`.
3. Rename the computer to `LAB-WIN11`: Settings > System > About > Rename
   this PC. Reboot.
4. Run Windows Update until there is nothing left, then **pause updates**
   so the OS version stays the same through the project.
5. Write down the Windows version. Run `winver` and note something like
   "Windows 11 24H2, build 26100.xxxx". It goes in every fixture's `source`.

## Step 3: Turn off Defender (inside the VM only)

Open Windows Security > Virus & threat protection > Manage settings, and
turn off **Tamper Protection** first, then **Real-time protection**, **Cloud
protection**, and **Automatic sample submission**. Real-time protection
turns itself back on after a reboot, so check it before every session.

Then, in an admin PowerShell window:

```powershell
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
```

## Step 4: Install Sysmon

Sysmon (System Monitor) is a free Microsoft Sysinternals tool. It logs
process starts, registry changes, process access, and more, in far more
detail than Windows does by default. Most rules in this repo read Sysmon
events. A **config file** tells Sysmon what to log and what to skip. We use
the widely used SwiftOnSecurity config, plus one change.

1. Download Sysmon from the Sysinternals site and unzip it to `C:\Tools\Sysmon`.
2. Download `sysmonconfig-export.xml` from
   <https://github.com/SwiftOnSecurity/sysmon-config> into the same folder
   and save a copy as `sysmonconfig-lab.xml`.
3. **The one change.** The SwiftOnSecurity config logs no Event ID 10
   (ProcessAccess), so the LSASS rule would never see anything. Open
   `sysmonconfig-lab.xml`, search for `<ProcessAccess onmatch="include">`,
   and change that block to:

   ```xml
   <ProcessAccess onmatch="include">
       <TargetImage condition="end with">lsass.exe</TargetImage>
   </ProcessAccess>
   ```

   This logs only handles opened to LSASS, which keeps the volume low.
4. Install it from an admin prompt in `C:\Tools\Sysmon`. On ARM use
   `Sysmon64a.exe`; on an Intel PC use `Sysmon64.exe`:

   ```
   Sysmon64a.exe -accepteula -i sysmonconfig-lab.xml
   ```

5. Make the log big enough that events are not overwritten during a session:

   ```
   wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:1073741824
   ```

6. Check that it works:

   ```powershell
   Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5
   ```

7. Write down the Sysmon version (right-click the exe > Properties >
   Details) and the date of the SwiftOnSecurity config. Both go in `source`.

## Step 5: Turn on extra Windows logging

Some techniques show up better, or only, in the Security or PowerShell logs.
From an admin prompt:

```
:: Scheduled task created/changed/deleted (4698, 4699, 4702)
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable

:: Process creation with command line in the Security log (4688)
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

:: Network share access (5140, 5145), for T1021.002
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable

:: Service installs (4697), for PsExec
auditpol /set /subcategory:"Security System Extension" /success:enable

:: PowerShell script block logging (PowerShell Operational 4104), for T1059.001
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

:: Bigger Security log
wevtutil sl Security /ms:1073741824
```

Log clearing (1102 in Security, 104 in System) and service installs (7045
in System) are logged by default.

## Step 6: Install Atomic Red Team

Atomic Red Team is a library of small, documented tests, one or more per
ATT&CK technique, maintained by Red Canary. Each test has a number and a
GUID. Fixtures reference the GUID so anyone can look up exactly what ran.
The repo never contains the test code itself.

With the VM still on NAT, in an admin PowerShell window:

```powershell
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

Now download the prerequisites for every test in the table below while you
still have internet access, for example:

```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 1,2,13 -GetPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 15,17 -GetPrereqs
Invoke-AtomicTest T1021.002 -TestNumbers 3 -GetPrereqs
```

Then check with `-CheckPrereqs` in place of `-GetPrereqs`.

To see exactly what a test will do before you run it:

```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 1 -ShowDetails
```

Read this every time. Knowing what ran is half of writing a good rule.

## Step 7: Take the base snapshot

Shut down the VM, switch the network adapter to host-only (or disconnect
it), turn off shared folders and clipboard sharing, and take a snapshot
named `base-tooled`. Every test session starts from this snapshot.

## Step 8: Collect benign data first

Benign data is what keeps the false positive numbers honest. Collect it
from `base-tooled` before running any attacks, so it is clean.

**Common baseline** (replayed against every rule, goes in
`fixtures/benign/common/`). Note the UTC start time, then spend about 30
minutes using the VM normally: open Edge, open and save files in Notepad
and Paint, open Task Manager, Event Viewer, and Services, run a Defender
quick scan if you can turn it on briefly, install and uninstall a small app
from an installer you copied in before the snapshot, and reboot once. Then
note the end time and export (Step 9).

**Per-technique benign** (goes in `fixtures/benign/<technique>/`). Things
that look a little like the attack but are not:

| Technique | Benign activity to capture |
|---|---|
| T1003.001 | Defender scan, Task Manager open on the Details tab, `tasklist /v` |
| T1059.001 | Normal admin PowerShell: `Get-Process`, `Get-Service`, a script run with `-ExecutionPolicy Bypass -File` |
| T1053.005 | A task made in the Task Scheduler GUI, `schtasks /query` |
| T1547.001 | Installing an app that adds itself to startup, `reg query` on a Run key |
| T1021.002 | Opening a normal (non-admin) share, `net use` with no arguments |
| T1685.005 | `wevtutil el`, `wevtutil gl System`, opening Event Viewer |

## Step 9: Run one attack session

For each technique:

1. Revert to `base-tooled`, start the VM, and confirm Defender real-time
   protection is still off.
2. Open an admin PowerShell window and import the module (Step 6).
3. Get the UTC time and write it down:

   ```powershell
   (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
   ```

4. Run **one** test, wait about 30 seconds, write down the UTC time again,
   then run its cleanup:

   ```powershell
   Invoke-AtomicTest T1003.001 -TestNumbers 1
   Invoke-AtomicTest T1003.001 -TestNumbers 1 -Cleanup
   ```

5. Repeat steps 3 and 4 for each test in the session, writing down a start
   and end time for each one. Leave a minute between tests so the windows
   don't overlap.
6. Export the logs into a folder per session:

   ```
   mkdir C:\exports\t1003.001
   wevtutil epl Microsoft-Windows-Sysmon/Operational C:\exports\t1003.001\sysmon.evtx
   wevtutil epl Security C:\exports\t1003.001\security.evtx
   wevtutil epl System C:\exports\t1003.001\system.evtx
   wevtutil epl Microsoft-Windows-PowerShell/Operational C:\exports\t1003.001\powershell.evtx
   ```

   Save your notes with the times as `C:\exports\t1003.001\times.txt`.
7. **Getting files out.** Shut down the VM. Turn on a shared folder pointing
   at an empty folder on your Mac, such as `~/lab-exports`. Boot, copy only
   `C:\exports\<technique>` into the share, shut down, turn the shared
   folder off, and revert to `base-tooled`. Copy logs only, never tools or
   dump files (`*.dmp`).

### Evasion runs

Phase 3 also tests one simple evasion per technique. The idea is to change
something an attacker could easily change and see if the rule still fires.
Run it the same way, but mark it with `--variant evasion` when converting.
Suggestions are in the table below.

## Step 10: Convert to fixtures

On your Mac, inside the repo:

```
source .venv/bin/activate
python tools/evtx_to_fixture.py ~/lab-exports/t1003.001/*.evtx --summary \
    --start "2026-10-20 14:02:00" --end "2026-10-20 14:03:30"
```

`--summary` writes nothing. It shows which event types fall inside the
window, so you can check that the window is right. Then write the fixture:

```
python tools/evtx_to_fixture.py ~/lab-exports/t1003.001/*.evtx \
    --start "2026-10-20 14:02:00" --end "2026-10-20 14:03:30" \
    --kind attack --technique T1003.001 \
    --atomic-number 1 --atomic-guid 0be2230c-9ab3-4ac2-8826-3199b9a0ebf8 \
    --source "LAB-WIN11, Windows 11 24H2 ARM64 build 26100.xxxx, Sysmon 15.xx, SwiftOnSecurity config 2026-xx-xx plus lsass include" \
    --description "Atomic T1003.001 #1, ProcDump -ma against lsass.exe" \
    --out fixtures/attack/t1003.001/atomic_01_procdump.json
```

One attack run per file. For benign data, use `--kind benign` and either
`--technique common` with `--out fixtures/benign/common/...` or the
technique ID with `--out fixtures/benign/<technique>/...`.

Before committing, open each fixture and skim it. Look for anything that
identifies you (a real name, your Mac's host name, an email address). If
you find something, fix the VM and re-run rather than editing the JSON.

Then run `pytest`. A missed attack or a flagged benign event shows up as a
failure, which is exactly what Phase 3 is for. Don't change the rule yet.
Bring the results back first.

## Atomic tests per technique

GUIDs come from the Atomic Red Team repo as of October 2026. Check them with
`-ShowDetailsBrief` in case numbering has changed.

### 1. T1003.001 LSASS Memory

Telemetry: Sysmon 10 (needs the lsass include from Step 4), Sysmon 1.

| # | GUID | Test | Use |
|---|---|---|---|
| 1 | `0be2230c-9ab3-4ac2-8826-3199b9a0ebf8` | Dump LSASS with ProcDump | baseline |
| 2 | `2536dee2-12fb-459a-8c37-971844fa73be` | Dump LSASS with comsvcs.dll | baseline |
| 13 | `47a539d1-61b9-4364-bf49-a68bc2a95ef0` | Dump LSASS with rdrleakdiag.exe | baseline |
| 5 | `dea6c349-f1c6-44f3-87a1-1ed33a59a607` | Task Manager "Create dump file" (manual) | baseline |

Evasion idea: copy ProcDump to `C:\Users\Public\svchost.exe` and run test 1
with `-InputArgs @{procdump_exe="C:\Users\Public\svchost.exe"}`. The rule's
filters only check the file name, so this is expected to slip through. That
is a good thing to prove.

### 2. T1059.001 Encoded or obfuscated PowerShell

Telemetry: Sysmon 1 command lines, PowerShell 4104.

| # | GUID | Test | Use |
|---|---|---|---|
| 17 | `a538de64-1c74-46ed-aa60-b995ed302598` | PowerShell Command Execution (`powershell.exe -e <base64>`) | baseline |
| 15 | `86a43bad-12e3-4e85-b97c-4d5cf25b95c3` | -EncodedCommand parameter variations | baseline |
| 16 | `0d181431-ddf3-4826-8055-2dbf63ae848b` | -EncodedCommand variations with encoded arguments | baseline |
| 14 | `1c0a870f-dc74-49cf-9afc-eccc45e58790` | -Command variations with encoded arguments | baseline |

Tests 14 to 16 need the AtomicTestHarnesses module, which `-GetPrereqs`
installs from the PowerShell Gallery while you are online. Evasion ideas:
run test 15 with a different switch style or parameter spelling through
`-InputArgs` (`-ShowDetails` lists the allowed values for
`command_line_switch_type` and `encoded_command_param_variation`), or copy
`powershell.exe` to another name and run an encoded command with it.

### 3. T1053.005 Scheduled Task

Telemetry: Sysmon 1 (`schtasks.exe`), Security 4698 (needs Step 5).

| # | GUID | Test | Use |
|---|---|---|---|
| 2 | `42f53695-ad4a-4546-abb6-7d837f644a71` | Scheduled task Local (`schtasks /create`) | baseline |
| 1 | `fec27f65-db86-4c2d-b66c-61945aee87c2` | Scheduled Task Startup Script | baseline |
| 4 | `af9fd58f-c4ac-4bf2-a9ba-224b71ff25fd` | PowerShell cmdlet (no schtasks.exe) | evasion |
| 6 | `e16b3b75-dc9e-4cde-a23d-dfa2d0507b3b` | WMI Invoke-CimMethod | evasion |

Tests 4 and 6 never start `schtasks.exe`, so a rule built only on Sysmon 1
will miss them. Security 4698 should still catch them. That comparison is
the most interesting part of this technique.

### 4. T1547.001 Registry Run Keys

Telemetry: Sysmon 13 (registry value set). SwiftOnSecurity already logs
writes under `CurrentVersion\Run`.

| # | GUID | Test | Use |
|---|---|---|---|
| 1 | `e55be3fd-3521-4610-9d1a-e210e42dcf05` | Reg Key Run (`reg add`, HKCU) | baseline |
| 2 | `554cbd88-cde1-4b56-8168-0be552eed9eb` | Reg Key RunOnce | baseline |
| 3 | `eb44f842-0457-4ddc-9b92-c4caa144ac42` | PowerShell Registry RunOnce | baseline |
| 12 | `a70faea1-e206-4f6f-8d9a-67379be8f6f1` | HKCU Policies\Explorer\Run key | evasion |

Test 3 writes a value that downloads a script the next time someone logs
in. The registry write (what we detect) happens offline. Don't log off or
reboot before reverting, or the VM will try to reach the internet.

### 5. T1021.002 SMB/Windows Admin Shares

Telemetry: Security 5140 and 5145 (needs Step 5), 4624 logon type 3,
System 7045 and Security 4697 for PsExec's service, Sysmon 1.

| # | GUID | Test | Use |
|---|---|---|---|
| 1 | `3386975b-367a-4fbb-9d77-4dcf3639ffd3` | Map admin share (`net use \\host\C$`) | baseline |
| 3 | `0eb03d41-79e4-4393-8e57-6344856be1cf` | Copy and Execute File with PsExec | baseline |
| 4 | `d41aaab5-bdfe-431d-a3d5-c29e9136ff46` | Write command output to `\\127.0.0.1\ADMIN$` | baseline |
| 2 | `514e9cd7-9207-4882-98b1-c8f791bae3c5` | Map admin share with PowerShell `New-PSDrive` | evasion |

**Caveat: this technique really needs two machines.** With one VM, these
tests connect to `localhost`. That produces share-access events, but the
logon looks local, the source IP is `127.0.0.1` or `::1`, and nothing
crosses the network. A rule tuned on that would not be convincing. Options:

- **Two VMs** (better). Clone the VM into `LAB-WIN11-B`, put both on the
  same host-only network, set the same `labadmin` password on both, and run
  the tests from A against B with
  `-InputArgs @{computer_name="LAB-WIN11-B"; user_name="LAB-WIN11-B\labadmin"; password="<lab password>"}`.
  Export logs from **B**, the target. This needs about 16 GB of RAM free.
- **Swap the technique** if two VMs won't fit. T1543.003 (Create or Modify
  System Process: Windows Service) covers the service-install half of
  PsExec, is fully visible on one host (System 7045, Security 4697), and has
  its own Atomic tests.

Tell me which way you want to go before collecting data for this one.

### 6. T1685.005 Clear Windows Event Logs (formerly T1070.001)

**ATT&CK changed this ID.** In the 2026 ATT&CK release, MITRE moved "Clear
Windows Event Logs" out of Indicator Removal (T1070.001) into the new
Defense Impairment tactic as **T1685.005**. `attack.t1070.001` now fails
pySigma's ATT&CK tag check, and Atomic Red Team moved its tests to
`atomics/T1685.005`. The rule and fixtures will use T1685.005.

Telemetry: Security 1102 (log cleared), System 104, Sysmon 1 (`wevtutil`).

| # | GUID | Test | Use |
|---|---|---|---|
| 1 | `e6abb60e-26b8-41da-8aae-0c35174b0967` | Clear Logs (`wevtutil cl System`) | baseline, run again with `-InputArgs @{log_name="Security"}` |
| 2 | `b13e9306-3351-4b4b-a6e8-477358b0b498` | Clear-EventLog on every classic log | evasion (no wevtutil.exe) |

Export logs right after each test, since the next clear wipes the evidence
from the previous one. Skip test 4 (BlackCat full clear). It also wipes
the Sysmon log, which leaves nothing to export but the clear events
themselves. That is worth one sentence in the blind spots section, not a
fixture.

## What to send back

For each technique, drop files here and tell me:

```
fixtures/attack/<technique>/atomic_<NN>_<short-name>.json     one per run
fixtures/attack/<technique>/evasion_<short-name>.json         marked --variant evasion
fixtures/benign/<technique>/<short-name>.json                 per-technique benign
fixtures/benign/common/<short-name>.json                      once, shared by all rules
```

Also send anything odd: a test that errored, a tool that would not run on
ARM, a window you were unsure about. Odd things usually end up in the
blind spots section.
