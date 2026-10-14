"""Checks the evtx-to-fixture flattening on hand-written event XML.

The XML here mirrors the shape of real Sysmon and Security records. It is
test input for the converter, not telemetry, and never becomes a fixture.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from evtx_to_fixture import flatten, parse_time  # noqa: E402

SYSMON_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>
    <EventID>10</EventID><Level>4</Level><Task>10</Task><Opcode>0</Opcode>
    <TimeCreated SystemTime="2026-10-20 14:02:11.104123"/>
    <EventRecordID>4242</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>LAB-WIN11</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="SourceImage">C:\\Tools\\procdump64.exe</Data>
    <Data Name="TargetImage">C:\\Windows\\system32\\lsass.exe</Data>
    <Data Name="GrantedAccess">0x1FFFFF</Data>
    <Data Name="SourceProcessId">8820</Data>
    <Data Name="RuleName">-</Data>
  </EventData>
</Event>"""

CLEARED_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Eventlog"/>
    <EventID>1102</EventID>
    <TimeCreated SystemTime="2026-10-20T15:00:00.000000Z"/>
    <Channel>Security</Channel><Computer>LAB-WIN11</Computer>
  </System>
  <UserData>
    <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
      <SubjectUserName>labadmin</SubjectUserName>
      <SubjectLogonId>0x3e7</SubjectLogonId>
    </LogFileCleared>
  </UserData>
</Event>"""


def test_flatten_sysmon_event():
    ev = flatten(SYSMON_XML)
    assert ev["EventID"] == 10
    assert ev["Channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert ev["Provider_Name"] == "Microsoft-Windows-Sysmon"
    assert ev["TargetImage"] == r"C:\Windows\system32\lsass.exe"
    assert ev["GrantedAccess"] == "0x1FFFFF"  # hex stays a string
    assert ev["SourceProcessId"] == 8820
    assert ev["TimeCreated"] == "2026-10-20T14:02:11.104123+00:00"


def test_flatten_userdata_event():
    ev = flatten(CLEARED_XML)
    assert ev["EventID"] == 1102
    assert ev["SubjectUserName"] == "labadmin"
    assert ev["SubjectLogonId"] == "0x3e7"


def test_parse_time_formats_agree():
    a = parse_time("2026-10-20 14:02:11")
    b = parse_time("2026-10-20T14:02:11.0000000Z")
    assert a == b and a.tzinfo is not None
