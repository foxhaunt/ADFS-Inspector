# ADFS-Inspector

**Professional AD FS log analysis tool for Windows Server 2019 / PowerShell 5.1**

ADFS-Inspector transforms raw Windows Event Log entries from AD FS into actionable intelligence: correlated authentication flows, statistical summaries, advanced filtering, and exportable dashboards — without any external dependencies.

---

## Features

- **Full event parsing** — extracts User, UPN, Client IP, Activity ID, Correlation ID, Endpoint, Protocol, Relying Party, Claims Provider, Error Detail from raw `Message` fields using precompiled regex
- **Event dictionary** — 60+ known AD FS Event IDs with human-readable names, severity, and protocol labels (WS-Trust, SAML, OAuth, OIDC, MFA, Device Registration, PRT)
- **Authentication flow correlation** — groups events by Activity ID to show the complete lifecycle of a single authentication attempt
- **Multiple views** — detailed per-event blocks or compact one-line timeline
- **Real-time follow mode** — like `tail -f`, prints new events without refreshing the screen
- **Statistical summary** — totals by severity, top failing users, top source IPs, protocol distribution
- **Exports** — CSV, JSON, and a self-contained HTML dashboard (no CDN dependencies, IE11 compatible)
- **Efficient querying** — uses `Get-WinEvent -FilterHashtable` for ETW-level pre-filtering; post-filtering only where unavoidable
- **Modular architecture** — 6 independent modules, extensible without touching the core

---

## Requirements

| Requirement | Value |
|---|---|
| PowerShell | 5.1 (Windows PowerShell) |
| OS | Windows Server 2019 / 2016 |
| Permissions | Local Administrator (to read `AD FS/Admin` log) |
| External modules | None |

---

## Installation

```powershell
# 1. Download or clone the repository
git clone https://github.com/tu-org/ADFS-Inspector.git

# 2. Copy to your preferred location on the AD FS server
#    (or run directly from the download path)
Copy-Item -Recurse .\ADFS-Inspector\ C:\Tools\ADFS-Inspector\

# 3. Unblock files if downloaded from internet
Get-ChildItem C:\Tools\ADFS-Inspector -Recurse | Unblock-File

# 4. Allow script execution (if not already set)
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

No module installation or `Import-Module` needed — the script loads its own modules automatically.

---

## Quick Start

```powershell
cd C:\Tools\ADFS-Inspector

# Summary of today's authentication activity
.\ADFS-Inspector.ps1 -Today -Summary

# All errors in the last hour, timeline view
.\ADFS-Inspector.ps1 -LastMinutes 60 -ErrorsOnly -View Timeline

# Real-time monitoring
.\ADFS-Inspector.ps1 -Follow -View Timeline
```

---

## Parameters

### Time Range

| Parameter | Type | Description |
|---|---|---|
| `-Today` | Switch | Events since 00:00 today |
| `-LastMinutes <int>` | Int | Events from the last N minutes (1–525600) |

If neither is specified, the tool reads up to `-MaxEvents` most recent events.

### Content Filters

| Parameter | Type | Description |
|---|---|---|
| `-User <string>` | String | Filter by username/UPN. Wildcards supported: `*eva*` |
| `-IP <string>` | String | Filter by client IP. Wildcards: `192.168.*` |
| `-ActivityId <string>` | String | Show full authentication flow for a specific Activity ID |
| `-EventId <int>` | Int | Filter by a specific Event ID |
| `-Protocol <string>` | String | Filter by protocol: `WS-Trust`, `OAuth`, `SAML`, `MFA`, etc. |
| `-RelyingParty <string>` | String | Filter by Relying Party name. Wildcards: `*Office 365*` |

### Severity Filters

| Parameter | Type | Description |
|---|---|---|
| `-ErrorsOnly` | Switch | Show only error events |
| `-WarningsOnly` | Switch | Show only warning events |

### Output Modes

| Parameter | Type | Description |
|---|---|---|
| `-View <string>` | String | `Detailed` (default) or `Timeline` |
| `-Summary` | Switch | Show statistical summary instead of individual events |
| `-Follow` | Switch | Real-time monitoring mode (Ctrl+C to stop) |
| `-FollowInterval <int>` | Int | Polling interval in seconds for `-Follow` (default: 5) |
| `-ListEvents` | Switch | Print the full Event ID catalog and exit |

### Export

| Parameter | Type | Description |
|---|---|---|
| `-ExportCsv <path>` | String | Export results to CSV |
| `-ExportJson <path>` | String | Export results to JSON |
| `-ExportHtml <path>` | String | Export results as HTML dashboard |

### Advanced

| Parameter | Type | Description |
|---|---|---|
| `-LogName <string>` | String | Event log to read (default: `AD FS/Admin`) |
| `-MaxEvents <int>` | Int | Maximum events to read (default: 500, max: 100000) |

---

## Usage Examples

### Daily Operations

```powershell
# Summary of today's authentications
.\ADFS-Inspector.ps1 -Today -Summary

# Last hour, all events, detailed view
.\ADFS-Inspector.ps1 -LastMinutes 60

# Last hour, timeline view
.\ADFS-Inspector.ps1 -LastMinutes 60 -View Timeline
```

### User Troubleshooting

```powershell
# All events for a specific user today
.\ADFS-Inspector.ps1 -Today -User "eva@foxhaunt.es"

# Only errors for that user
.\ADFS-Inspector.ps1 -Today -User "eva@foxhaunt.es" -ErrorsOnly

# User's activity with wildcard (partial UPN)
.\ADFS-Inspector.ps1 -Today -User "*foxhaunt.es" -View Timeline
```

### Authentication Flow Investigation

```powershell
# Show the complete authentication flow for a specific Activity ID
.\ADFS-Inspector.ps1 -ActivityId "3f2c1a4b-88d0-4e3a-b1c2-000000000001"

# First find the Activity ID from a failure
.\ADFS-Inspector.ps1 -LastMinutes 30 -ErrorsOnly -View Timeline
# Then drill into the flow:
.\ADFS-Inspector.ps1 -ActivityId "<guid-from-above>"
```

### IP-Based Investigation

```powershell
# All events from a suspicious IP
.\ADFS-Inspector.ps1 -IP "10.0.0.50" -LastMinutes 60

# Errors from an IP range
.\ADFS-Inspector.ps1 -IP "192.168.1.*" -ErrorsOnly -Today

# Top IPs by activity
.\ADFS-Inspector.ps1 -Today -Summary
```

### Protocol Analysis

```powershell
# OAuth authentications today
.\ADFS-Inspector.ps1 -Today -Protocol "OAuth" -Summary

# SAML failures
.\ADFS-Inspector.ps1 -LastMinutes 120 -Protocol "SAML" -ErrorsOnly

# MFA events
.\ADFS-Inspector.ps1 -Today -Protocol "MFA" -View Timeline
```

### Real-Time Monitoring

```powershell
# Monitor all events as they happen
.\ADFS-Inspector.ps1 -Follow

# Monitor only errors, check every 10 seconds
.\ADFS-Inspector.ps1 -Follow -ErrorsOnly -FollowInterval 10

# Monitor a specific user's authentication attempts
.\ADFS-Inspector.ps1 -Follow -User "admin@foxhaunt.es" -View Timeline
```

### Exports & Reporting

```powershell
# Daily HTML report
.\ADFS-Inspector.ps1 -Today -ExportHtml "C:\Reports\adfs-$(Get-Date -f yyyyMMdd).html"

# Export all failures to CSV for Excel analysis
.\ADFS-Inspector.ps1 -Today -ErrorsOnly -ExportCsv "C:\Reports\failures.csv"

# JSON export for SIEM ingestion
.\ADFS-Inspector.ps1 -LastMinutes 60 -ExportJson "C:\Reports\adfs-events.json"

# Export and display at the same time
.\ADFS-Inspector.ps1 -Today -Summary -ExportHtml "C:\Reports\today.html"
```

### Specific Event Investigation

```powershell
# All AUTH_FAILURE events (EventId 364)
.\ADFS-Inspector.ps1 -Today -EventId 364

# TOKEN_ISSUED events for a specific Relying Party
.\ADFS-Inspector.ps1 -Today -EventId 307 -RelyingParty "*Office 365*"

# List all known Event IDs
.\ADFS-Inspector.ps1 -ListEvents
```

---

## Real Troubleshooting Scenarios

### Scenario 1: User reports "can't log in to Office 365"

```powershell
# Step 1: Check recent errors for the user
.\ADFS-Inspector.ps1 -LastMinutes 30 -User "user@domain.com" -ErrorsOnly

# Step 2: If you find a failure, get the Activity ID from the output
# Step 3: See the full authentication flow
.\ADFS-Inspector.ps1 -ActivityId "GUID-FROM-STEP-2"

# Look for: AUTH_FAILURE, ACCOUNT_LOCKED, MFA_FAILURE, EXTRANET_LOCKOUT
```

### Scenario 2: Spike in authentication failures — possible brute force

```powershell
# Step 1: Get summary to see the magnitude
.\ADFS-Inspector.ps1 -LastMinutes 60 -Summary

# Step 2: See top failing IPs from the summary output
# Step 3: Investigate the specific attacking IP
.\ADFS-Inspector.ps1 -LastMinutes 60 -IP "suspicious.ip.here" -View Timeline

# Look for: EXTRANET_LOCKOUT (516), repeated AUTH_FAILURE (364)
```

### Scenario 3: MFA failures — is the MFA provider down?

```powershell
# Check MFA events across the last hour
.\ADFS-Inspector.ps1 -LastMinutes 60 -Protocol "MFA" -View Timeline

# If you see MFA_PROVIDER_UNAVAILABLE (408), the adapter is unreachable
# Check the flow of a specific MFA failure
.\ADFS-Inspector.ps1 -ActivityId "GUID-OF-MFA-FAILURE"
```

### Scenario 4: Office 365 hybrid auth broken after certificate renewal

```powershell
# Look for token signing / encryption errors
.\ADFS-Inspector.ps1 -Today -EventId 308  # TOKEN_SIGN_ERROR
.\ADFS-Inspector.ps1 -Today -EventId 309  # TOKEN_ENCRYPT_ERROR

# Check certificate-related system events
.\ADFS-Inspector.ps1 -Today -EventId 106  # CERTIFICATE_EXPIRED
.\ADFS-Inspector.ps1 -Today -EventId 105  # CERTIFICATE_EXPIRING
```

### Scenario 5: Generate daily security report

```powershell
# Full HTML dashboard for today
.\ADFS-Inspector.ps1 -Today `
    -ExportHtml "C:\Reports\adfs-$(Get-Date -f yyyy-MM-dd).html" `
    -Summary
```

---

## Testing Without an AD FS Server

Use the included test script to verify the parser, renderer, and all modules work correctly on any Windows machine with PowerShell 5.1:

```powershell
.\examples\test-parser.ps1
```

This runs 9 tests covering: EventDictionary, severity helpers, filter logic, timeline grouping, detailed view, timeline view, summary, authentication flow view, and HTML export.

---

## Architecture

```
ADFS-Inspector/
│
├── ADFS-Inspector.ps1          # Entry point — orchestration only
│
├── Modules/
│   ├── EventDictionary.psm1   # Event ID catalog with name/severity/protocol
│   ├── Parser.psm1            # Raw EventLogRecord → normalized PSCustomObject
│   ├── Filters.psm1           # Predicate filtering + ETW FilterHashtable builder
│   ├── Timeline.psm1          # Group by ActivityId, flow summaries
│   ├── Renderer.psm1          # Write-Host output: detailed, timeline, flow, summary
│   └── Utils.psm1             # CSV/JSON/HTML export + Follow mode
│
├── examples/
│   ├── event-307-token-issued.txt  # Sample event messages for testing
│   ├── event-364-auth-failure.txt
│   ├── event-mfa-flow.txt
│   └── test-parser.ps1             # Automated test suite (no AD FS needed)
│
└── README.md
```

### Module dependencies

```
EventDictionary  ← (no deps)
Parser           ← EventDictionary
Filters          ← (no deps on domain modules)
Timeline         ← (no deps on domain modules)
Renderer         ← EventDictionary
Utils            ← Parser, Filters, Renderer (via caller)
```

No circular dependencies. Each module can be imported and tested in isolation.

---

## Extending for New Protocols

To add support for a new protocol (e.g., Azure AD seamless SSO, WS-Federation B2B):

1. **Add Event IDs** in `Modules/EventDictionary.psm1` under `$script:EventCatalog`
2. **Add regex patterns** in `Modules/Parser.psm1` under `$script:Patterns` if the new events have unique field formats
3. **Add FlowStepOrder entries** in `Modules/Timeline.psm1` if the new events participate in authentication flows
4. No changes needed in Filters, Renderer, Utils, or the main script

---

## Known AD FS Event IDs Reference

| Range | Area |
|---|---|
| 100–108 | Service lifecycle, certificates, database |
| 200–209 | Primary authentication (WS-Trust) |
| 299–310 | Token issuance, claims pipeline |
| 364, 403, 411–413 | Authentication and token errors |
| 400–408 | MFA / additional authentication |
| 510, 516–517 | WAP / Extranet lockout |
| 600–606 | Device registration |
| 700–704 | PRT / Seamless SSO |
| 1000–1008 | Audit events |
| 1100–1105 | SAML |
| 1200–1208 | OAuth 2.0 / OpenID Connect |

Run `.\ADFS-Inspector.ps1 -ListEvents` for the full catalog.

---

## Changelog

### v1.0.0 (2026-07-23)
- Initial release
- Protocols: WS-Trust, WS-Federation, SAML, OAuth 2.0, OIDC, MFA, Device Registration, PRT
- Views: Detailed, Timeline, Authentication Flow, Summary
- Exports: CSV, JSON, HTML dashboard
- Follow mode (real-time)
- 60+ known Event IDs
- Full test suite (no AD FS server needed)

---

## License

MIT License. See LICENSE file.
