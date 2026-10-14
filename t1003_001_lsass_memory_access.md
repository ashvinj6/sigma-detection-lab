# T1003.001 OS Credential Dumping: LSASS Memory

Rule: [`rules/t1003_001_lsass_memory_access.yml`](../rules/t1003_001_lsass_memory_access.yml)

> **Status: draft.** So far this rule has only been run against synthetic
> placeholder events. It gets rewritten with real hit/miss results once lab
> exports exist (Phase 3).

## Technique

LSASS (`lsass.exe`, the Local Security Authority Subsystem Service) is the
Windows process that handles logons. It keeps credential material in memory:
NTLM hashes, Kerberos tickets, and sometimes cleartext passwords. An attacker
with admin rights can open a handle to LSASS that lets them read its memory,
and then either parse it on the spot (Mimikatz `sekurlsa::logonpasswords`) or
write a dump file to parse somewhere else (ProcDump, the `comsvcs.dll`
MiniDump export, Task Manager's "Create dump file").

ATT&CK: <https://attack.mitre.org/techniques/T1003/001/>

## Telemetry used

Sysmon **Event ID 10, ProcessAccess**. It is logged when one process opens a
handle to another. Fields the rule reads:

| Field | Why |
|---|---|
| `TargetImage` | is the handle for `lsass.exe`? |
| `GrantedAccess` | which rights were granted. This is the main signal. |
| `SourceImage` | who asked. Used only to filter out known OS and Defender processes. |
| `CallTrace` | not matched on, but listed in `fields:` because it helps triage |

Important: the SwiftOnSecurity Sysmon config used in the lab logs **no**
ProcessAccess events by default, because logging every handle open would
flood the log. [LAB_SETUP.md](LAB_SETUP.md#step-4-install-sysmon) adds a
single include rule for `TargetImage` ending in `lsass.exe`. Without that
change this rule never fires, no matter what the attacker does.

## Detection logic

```
selection_target and selection_access and not 1 of filter_main_*
```

- `selection_target`: `TargetImage` ends with `\lsass.exe`.
- `selection_access`: `GrantedAccess` is one of eleven masks that include
  `PROCESS_VM_READ` (0x0010) or full access. These are values publicly
  documented for Mimikatz, ProcDump, and similar tools. A mask like `0x1000`
  (`PROCESS_QUERY_LIMITED_INFORMATION`) is left out on purpose: lots of normal
  software asks for it, and it cannot read memory.
- `filter_main_system`, `filter_main_defender`: drop events where the
  requesting process is an OS component (`services.exe`, `svchost.exe`,
  `wininit.exe`, `lsass.exe`) or Defender (`MsMpEng.exe`, `SenseIR.exe`).

## Tuning notes

- The access mask list is the main lever, and it comes from public writeups,
  not from this lab's own baseline. Phase 3 checks it against what the lab's
  Sysmon actually records.
- The Defender filter is deliberately short. Any other security agent that
  inspects LSASS will fire this rule until it is added, and agent names vary
  by vendor.
- ProcDump and Task Manager are not filtered even though they are legitimate
  admin tools, because they are also the most common way this technique is
  done. If an environment really does dump LSASS on purpose, scope the
  exception to a specific user and host, not to the binary name.

## Known blind spots

- **Access mask formatting depends on the Sysmon version.** While testing
  the fixture converter against a public 2019 Sysmon sample
  ([EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES),
  `CA_sysmon_hashdump_cmd_meterpreter.evtx`, used for testing only and not
  committed here), the mask was written zero-padded as `0x001f1fff`. The rule
  lists `0x1f1fff`, so it missed that event. It matched once the padding was
  removed. Whether the lab's Sysmon pads or not gets checked in Phase 3.
- **Masks outside the list.** Exact-match lists are brittle. A tool that asks
  for an unusual combination of rights that still includes `PROCESS_VM_READ`
  gets past it. Matching on the bit itself would be stronger, but Sigma has
  no bitwise operator, so that needs a different query language.
- **Renaming or impersonating a filtered binary.** The filters only check
  that `SourceImage` ends with a name like `\svchost.exe`. A dumper copied to
  `C:\Users\Public\svchost.exe` is filtered out. Pinning the filters to full
  `C:\Windows\System32\` paths would close the easiest version of this.
- **No handle, no event.** Techniques that never call `OpenProcess` on LSASS
  are invisible to Event ID 10. Examples are a vulnerable signed driver
  reading kernel memory, duplicating a handle that some other process already
  has open, or Silent Process Exit dumping (Atomic T1003.001 #14), where
  `WerFault.exe` does the dump on the attacker's behalf.
- **Direct syscalls.** Tools that make the system call themselves (Atomic
  T1003.001 #3) can still be seen by Sysmon's kernel callback, but the
  `CallTrace` looks different. The rule does not rely on `CallTrace`, so this
  should not cause a miss. That is still unconfirmed until it is tested in the
  lab.
- **Offline dumps.** Reading credentials from a dump file copied off the host
  (Atomic T1003.001 #6) creates no ProcessAccess event on the victim at all.

## Fixtures

| Kind | Real | Synthetic |
|---|---|---|
| Attack | none yet | `mimikatz_sekurlsa_logonpasswords`, `procdump_lsass_dump` |
| Benign | none yet | `defender_lsass_scan`, `low_rights_handle_unknown_process`, `svchost_lsass_handle`, `unrelated_process_access` |

The README coverage table shows real results only.
