# Case 0001: Suspicious ProcessAccess to sensitive target process

## Alert summary
- **Rule:** `suspicious_process_access`
- **Severity:** `high`
- **First seen:** `2020-09-20T16:17:03.996000+00:00`

## Entities
- **host**: `WORKSTATION6.theshire.local`
- **user**: `NT AUTHORITY\SYSTEM`
- **source_process**: `C:\windows\system32\svchost.exe`
- **target_process**: `C:\windows\system32\lsass.exe`

## Evidence (samples)

```json
{"@timestamp": "2020-09-20T16:17:03.996000+00:00", "process.name": "C:\\windows\\system32\\svchost.exe", "process.target": "C:\\windows\\system32\\lsass.exe", "process.granted_access": "0x1000"}
{"@timestamp": "2020-09-20T16:17:03.996000+00:00", "process.name": "C:\\windows\\system32\\svchost.exe", "process.target": "C:\\windows\\system32\\lsass.exe", "process.granted_access": "0x1000"}
{"@timestamp": "2020-09-20T16:17:25.432000+00:00", "process.name": "C:\\windows\\system32\\svchost.exe", "process.target": "C:\\windows\\system32\\lsass.exe", "process.granted_access": "0x3000"}
{"@timestamp": "2020-09-20T16:18:21.454000+00:00", "process.name": "C:\\windows\\system32\\svchost.exe", "process.target": "C:\\windows\\system32\\lsass.exe", "process.granted_access": "0x1000"}
{"@timestamp": "2020-09-20T16:18:21.456000+00:00", "process.name": "C:\\windows\\system32\\svchost.exe", "process.target": "C:\\windows\\system32\\lsass.exe", "process.granted_access": "0x1000"}
{"@timestamp": "2020-09-20T16:18:21.483000+00:00", "process.name": "C:\\windows\\system32\\svchost.exe", "process.target": "C:\\windows\\system32\\lsass.exe", "process.granted_access": "0x1000"}
{"@timestamp": "2020-09-20T16:18:21.483000+00:00", "process.name": "C:\\windows\\system32\\svchost.exe", "process.target": "C:\\windows\\system32\\lsass.exe", "process.granted_access": "0x1000"}
```

## Triage notes (starter)
- Does the source process normally access this target on this host?
- Is the user context expected (SYSTEM/NT AUTHORITY) for this activity?
- Correlate with adjacent events: process creation (Sysmon 1), registry writes (Sysmon 13), network (5156).
