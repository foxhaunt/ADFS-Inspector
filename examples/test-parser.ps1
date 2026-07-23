#Requires -Version 5.1
<#
.SYNOPSIS
    Script de prueba para verificar el Parser sin necesitar un servidor AD FS real.
    Simula objetos EventLogRecord con mensajes de ejemplo para validar la extracción
    de campos en Parser.psm1.

    Ejecutar desde la raíz del proyecto:
        .\examples\test-parser.ps1
#>

$RootPath = Split-Path $PSScriptRoot -Parent
$ModulesPath = Join-Path $RootPath 'Modules'

Import-Module (Join-Path $ModulesPath 'EventDictionary.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $ModulesPath 'Parser.psm1')          -Force -DisableNameChecking
Import-Module (Join-Path $ModulesPath 'Filters.psm1')         -Force -DisableNameChecking
Import-Module (Join-Path $ModulesPath 'Timeline.psm1')        -Force -DisableNameChecking
Import-Module (Join-Path $ModulesPath 'Renderer.psm1')        -Force -DisableNameChecking
Import-Module (Join-Path $ModulesPath 'Utils.psm1')           -Force -DisableNameChecking

Write-Host ''
Write-Host '══════════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host '  ADFS-Inspector — Parser & Renderer Test                ' -ForegroundColor Cyan
Write-Host '══════════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ''

# ---------------------------------------------------------------------------
# Test 1: EventDictionary
# ---------------------------------------------------------------------------
Write-Host '[ TEST 1 ] EventDictionary' -ForegroundColor Yellow
$meta = Get-EventMeta -EventId 307
if ($meta -and $meta.Name -eq 'TOKEN_ISSUED') {
    Write-Host '  [+] Get-EventMeta(307) → TOKEN_ISSUED (Success)' -ForegroundColor Green
} else {
    Write-Host '  [!] FAILED: Get-EventMeta(307) returned unexpected result' -ForegroundColor Red
}

$meta364 = Get-EventMeta -EventId 364
if ($meta364 -and $meta364.Severity -eq 'Error') {
    Write-Host '  [+] Get-EventMeta(364) → AUTH_FAILURE / Error (Success)' -ForegroundColor Green
} else {
    Write-Host '  [!] FAILED: Get-EventMeta(364) severity mismatch' -ForegroundColor Red
}

$metaUnknown = Get-EventMeta -EventId 99999
if ($null -eq $metaUnknown) {
    Write-Host '  [+] Get-EventMeta(99999) → null for unknown ID (Success)' -ForegroundColor Green
} else {
    Write-Host '  [!] FAILED: Unknown EventId should return null' -ForegroundColor Red
}

Write-Host ''

# ---------------------------------------------------------------------------
# Test 2: SeverityColor / Icon
# ---------------------------------------------------------------------------
Write-Host '[ TEST 2 ] Severity Helpers' -ForegroundColor Yellow
$colors = @('Success','Error','Warning','Info','System')
foreach ($sev in $colors) {
    $color = Get-SeverityColor -Severity $sev
    $icon  = Get-SeverityIcon  -Severity $sev
    Write-Host "  $icon $($sev.PadRight(10)) → " -NoNewline
    Write-Host $color -ForegroundColor $color
}
Write-Host ''

# ---------------------------------------------------------------------------
# Test 3: Regex extraction (simulated messages)
# ---------------------------------------------------------------------------
Write-Host '[ TEST 3 ] Filter Logic' -ForegroundColor Yellow

# Simular objetos parseados (normalmente vendrían de ConvertTo-AdfsEvent)
$mockEvents = @(
    [PSCustomObject]@{ EventId=307; EventName='TOKEN_ISSUED'; Severity='Success'; User='eva@foxhaunt.es'; ClientIp='192.168.1.15'; Protocol='WS-Trust'; ActivityId='aaa'; CorrelationId=$null; Endpoint='/adfs/services/trust/13/usernamemixed'; RequestUri=$null; RelyingParty='Office 365'; ClaimsProvider='AD'; ErrorDetail=$null; MachineName='ADFS01'; LogName='AD FS/Admin'; TimeCreated=(Get-Date).AddMinutes(-5); Description='Token issued'; RawMessage='' },
    [PSCustomObject]@{ EventId=364; EventName='AUTH_FAILURE'; Severity='Error';   User='admin@foxhaunt.es'; ClientIp='10.0.0.50'; Protocol='WS-Trust'; ActivityId='bbb'; CorrelationId=$null; Endpoint='/adfs/services/trust/13/usernamemixed'; RequestUri=$null; RelyingParty='Office 365'; ClaimsProvider='AD'; ErrorDetail='Invalid credentials'; MachineName='ADFS01'; LogName='AD FS/Admin'; TimeCreated=(Get-Date).AddMinutes(-3); Description='Auth failed'; RawMessage='' },
    [PSCustomObject]@{ EventId=400; EventName='MFA_REQUIRED'; Severity='Warning'; User='svc@foxhaunt.es'; ClientIp='10.0.0.5'; Protocol='WS-Fed'; ActivityId='ccc'; CorrelationId=$null; Endpoint='/adfs/ls/'; RequestUri=$null; RelyingParty='Office 365'; ClaimsProvider='AD'; ErrorDetail=$null; MachineName='ADFS01'; LogName='AD FS/Admin'; TimeCreated=(Get-Date).AddMinutes(-1); Description='MFA required'; RawMessage='' }
)

# Filtrar por usuario
$filtered = Invoke-AdfsFilter -Events $mockEvents -FilterParams @{ User = 'eva' }
if ($filtered.Count -eq 1 -and $filtered[0].User -eq 'eva@foxhaunt.es') {
    Write-Host '  [+] User filter "eva" → 1 result (Success)' -ForegroundColor Green
} else {
    Write-Host "  [!] FAILED: User filter returned $($filtered.Count) results" -ForegroundColor Red
}

# Filtrar ErrorsOnly
$errOnly = Invoke-AdfsFilter -Events $mockEvents -FilterParams @{ ErrorsOnly = $true }
if ($errOnly.Count -eq 1 -and $errOnly[0].Severity -eq 'Error') {
    Write-Host '  [+] ErrorsOnly filter → 1 error event (Success)' -ForegroundColor Green
} else {
    Write-Host "  [!] FAILED: ErrorsOnly returned $($errOnly.Count) results" -ForegroundColor Red
}

# Sin filtros → todos
$all = Invoke-AdfsFilter -Events $mockEvents -FilterParams @{}
if ($all.Count -eq 3) {
    Write-Host '  [+] Empty filter → 3 events (Success)' -ForegroundColor Green
} else {
    Write-Host "  [!] FAILED: Empty filter returned $($all.Count) results" -ForegroundColor Red
}

Write-Host ''

# ---------------------------------------------------------------------------
# Test 4: Timeline grouping
# ---------------------------------------------------------------------------
Write-Host '[ TEST 4 ] Timeline / Flow Grouping' -ForegroundColor Yellow

$flows = Get-AuthenticationFlow -Events $mockEvents
$uniqueFlowCount = ($flows.Keys | Where-Object { $_ -ne '_UNGROUPED' }).Count
if ($uniqueFlowCount -eq 3) {
    Write-Host "  [+] Got $uniqueFlowCount unique Activity IDs (Success)" -ForegroundColor Green
} else {
    Write-Host "  [!] FAILED: Expected 3 flows, got $uniqueFlowCount" -ForegroundColor Red
}

Write-Host ''

# ---------------------------------------------------------------------------
# Test 5: Renderer — vista detallada con evento mock
# ---------------------------------------------------------------------------
Write-Host '[ TEST 5 ] Renderer — Detailed View' -ForegroundColor Yellow
Write-Host ''
Show-DetailedEvent -Event $mockEvents[0]
Show-DetailedEvent -Event $mockEvents[1]

# ---------------------------------------------------------------------------
# Test 6: Renderer — vista timeline
# ---------------------------------------------------------------------------
Write-Host '[ TEST 6 ] Renderer — Timeline View' -ForegroundColor Yellow
Write-Host ''
Write-Host "  $('TIME'.PadRight(10))  $('EVENT'.PadRight(30))$('USER'.PadRight(35))CLIENT IP" -ForegroundColor DarkCyan
Write-Host "  $('─'*8)  $('─'*28)$('─'*33)$('─'*15)" -ForegroundColor DarkGray
foreach ($ev in $mockEvents) { Show-TimelineEvent -Event $ev }

Write-Host ''

# ---------------------------------------------------------------------------
# Test 7: Summary
# ---------------------------------------------------------------------------
Write-Host '[ TEST 7 ] Renderer — Summary' -ForegroundColor Yellow
Show-Summary -Events $mockEvents

# ---------------------------------------------------------------------------
# Test 8: AuthFlow view
# ---------------------------------------------------------------------------
Write-Host '[ TEST 8 ] Renderer — Auth Flow' -ForegroundColor Yellow
$flowEvents = @(
    [PSCustomObject]@{ EventId=200; EventName='AUTH_REQUEST'; Severity='Info'; User='svc@foxhaunt.es'; ClientIp='10.0.0.5'; Protocol='WS-Fed'; ActivityId='test-flow-001'; CorrelationId=$null; Endpoint='/adfs/ls/'; RequestUri=$null; RelyingParty='Office 365'; ClaimsProvider='AD'; ErrorDetail=$null; MachineName='ADFS01'; LogName='AD FS/Admin'; TimeCreated=(Get-Date).AddSeconds(-8); Description='Auth request'; RawMessage='' },
    [PSCustomObject]@{ EventId=400; EventName='MFA_REQUIRED'; Severity='Warning'; User='svc@foxhaunt.es'; ClientIp='10.0.0.5'; Protocol='WS-Fed'; ActivityId='test-flow-001'; CorrelationId=$null; Endpoint='/adfs/ls/'; RequestUri=$null; RelyingParty='Office 365'; ClaimsProvider='AD'; ErrorDetail=$null; MachineName='ADFS01'; LogName='AD FS/Admin'; TimeCreated=(Get-Date).AddSeconds(-6); Description='MFA required'; RawMessage='' },
    [PSCustomObject]@{ EventId=402; EventName='MFA_SUCCESS'; Severity='Success'; User='svc@foxhaunt.es'; ClientIp='10.0.0.5'; Protocol='MFA'; ActivityId='test-flow-001'; CorrelationId=$null; Endpoint=$null; RequestUri=$null; RelyingParty=$null; ClaimsProvider=$null; ErrorDetail=$null; MachineName='ADFS01'; LogName='AD FS/Admin'; TimeCreated=(Get-Date).AddSeconds(-1); Description='MFA succeeded'; RawMessage='' },
    [PSCustomObject]@{ EventId=307; EventName='TOKEN_ISSUED'; Severity='Success'; User='svc@foxhaunt.es'; ClientIp='10.0.0.5'; Protocol='WS-Fed'; ActivityId='test-flow-001'; CorrelationId=$null; Endpoint='/adfs/ls/'; RequestUri=$null; RelyingParty='Office 365'; ClaimsProvider='AD'; ErrorDetail=$null; MachineName='ADFS01'; LogName='AD FS/Admin'; TimeCreated=(Get-Date); Description='Token issued'; RawMessage='' }
)
Show-AuthFlow -ActivityId 'test-flow-001' -Flow $flowEvents

# ---------------------------------------------------------------------------
# Test 9: Exportación HTML
# ---------------------------------------------------------------------------
Write-Host '[ TEST 9 ] HTML Export' -ForegroundColor Yellow
$htmlPath = Join-Path $PSScriptRoot 'test-output.html'
try {
    Export-ToHtml -Events $mockEvents -Path $htmlPath
    if (Test-Path $htmlPath) {
        Write-Host "  [+] HTML exported to: $htmlPath (Success)" -ForegroundColor Green
    }
} catch {
    Write-Host "  [!] FAILED: $_" -ForegroundColor Red
}

Write-Host ''
Write-Host '══════════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host '  All tests completed.' -ForegroundColor Cyan
Write-Host '══════════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ''
