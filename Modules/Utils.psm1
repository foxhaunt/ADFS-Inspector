#Requires -Version 5.1
<#
.SYNOPSIS
    Utilidades de soporte: exportación (CSV, JSON, HTML) y Follow mode.
.DESCRIPTION
    Funciones auxiliares sin dependencias de dominio AD FS.
    La exportación HTML genera un dashboard autocontenido compatible con IE11.
#>

Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------------
# CSS base para el dashboard HTML (inline, sin dependencias externas)
# ---------------------------------------------------------------------------
$script:HtmlCss = @'
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', Consolas, monospace; background: #0d1117; color: #c9d1d9; font-size: 13px; }
h1 { color: #58a6ff; padding: 16px 24px 0; font-size: 18px; }
.meta { color: #8b949e; padding: 4px 24px 16px; font-size: 12px; }
.stats { display: flex; gap: 12px; padding: 0 24px 16px; flex-wrap: wrap; }
.stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px 18px; min-width: 120px; }
.stat-card .label { font-size: 11px; color: #8b949e; text-transform: uppercase; letter-spacing: .5px; }
.stat-card .value { font-size: 24px; font-weight: 700; margin-top: 4px; }
.v-success { color: #3fb950; } .v-error { color: #f85149; } .v-warning { color: #d29922; } .v-info { color: #58a6ff; }
.container { padding: 0 24px 32px; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th { background: #161b22; color: #8b949e; text-align: left; padding: 8px 10px; border-bottom: 2px solid #30363d; position: sticky; top: 0; }
td { padding: 6px 10px; border-bottom: 1px solid #21262d; vertical-align: top; word-break: break-word; }
tr:hover td { background: #161b22; }
.badge { display: inline-block; padding: 1px 7px; border-radius: 9px; font-size: 11px; font-weight: 600; }
.b-success { background: #1a3a23; color: #3fb950; }
.b-error   { background: #3a1a1a; color: #f85149; }
.b-warning { background: #3a2a10; color: #d29922; }
.b-info    { background: #1a2a3a; color: #58a6ff; }
.b-system  { background: #2a2a2a; color: #8b949e; }
.mono { font-family: Consolas, monospace; font-size: 11px; color: #8b949e; }
.user-cell { color: #79c0ff; }
.ip-cell   { color: #a5d6ff; }
.rp-cell   { color: #ffa657; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
'@

# ---------------------------------------------------------------------------
# Función pública: exportar a CSV
# ---------------------------------------------------------------------------
function Export-ToCsv {
    <#
    .SYNOPSIS
        Exporta eventos AD FS parseados a un archivo CSV.
    .PARAMETER Events
        Array de PSCustomObject producido por ConvertTo-AdfsEvent.
    .PARAMETER Path
        Ruta del archivo de destino.
    .EXAMPLE
        Export-ToCsv -Events $events -Path 'C:\logs\adfs-export.csv'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Events,

        [Parameter(Mandatory)]
        [string]$Path
    )

    # Excluir RawMessage del CSV para mantenerlo legible
    $Events | Select-Object -ExcludeProperty RawMessage |
        Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -Force

    Write-Verbose "CSV exportado: $Path ($($Events.Count) eventos)"
}

# ---------------------------------------------------------------------------
# Función pública: exportar a JSON
# ---------------------------------------------------------------------------
function Export-ToJson {
    <#
    .SYNOPSIS
        Exporta eventos AD FS parseados a un archivo JSON.
    .PARAMETER Events
        Array de PSCustomObject producido por ConvertTo-AdfsEvent.
    .PARAMETER Path
        Ruta del archivo de destino.
    .EXAMPLE
        Export-ToJson -Events $events -Path 'C:\logs\adfs-export.json'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Events,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $Events | ConvertTo-Json -Depth 5 |
        Set-Content -Path $Path -Encoding UTF8 -Force

    Write-Verbose "JSON exportado: $Path ($($Events.Count) eventos)"
}

# ---------------------------------------------------------------------------
# Función pública: exportar a HTML (dashboard)
# ---------------------------------------------------------------------------
function Export-ToHtml {
    <#
    .SYNOPSIS
        Exporta eventos AD FS como un dashboard HTML autocontenido.
    .PARAMETER Events
        Array de PSCustomObject producido por ConvertTo-AdfsEvent.
    .PARAMETER Path
        Ruta del archivo HTML de destino.
    .EXAMPLE
        Export-ToHtml -Events $events -Path 'C:\logs\adfs-report.html'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Events,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $total    = $Events.Count
    $success  = @($Events | Where-Object { $_.Severity -eq 'Success'  }).Count
    $errors   = @($Events | Where-Object { $_.Severity -eq 'Error'    }).Count
    $warnings = @($Events | Where-Object { $_.Severity -eq 'Warning'  }).Count
    $info     = @($Events | Where-Object { $_.Severity -eq 'Info'     }).Count

    $firstTime = if ($total -gt 0) { ($Events | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }
    $lastTime  = if ($total -gt 0) { ($Events | Sort-Object TimeCreated | Select-Object -Last  1).TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }

    # Construir filas de tabla
    $rows = [System.Text.StringBuilder]::new()
    foreach ($ev in $Events) {
        $badgeClass = "b-$($ev.Severity.ToLower())"
        $time       = $ev.TimeCreated.ToString('HH:mm:ss.fff')
        $user       = [System.Web.HttpUtility]::HtmlEncode($ev.User)
        $ip         = [System.Web.HttpUtility]::HtmlEncode($ev.ClientIp)
        $ep         = [System.Web.HttpUtility]::HtmlEncode($ev.Endpoint)
        $rp         = [System.Web.HttpUtility]::HtmlEncode($ev.RelyingParty)
        $actId      = [System.Web.HttpUtility]::HtmlEncode($ev.ActivityId)
        $errD       = [System.Web.HttpUtility]::HtmlEncode($ev.ErrorDetail)

        [void]$rows.AppendLine("<tr>
          <td class='mono'>$time</td>
          <td>$($ev.EventId)</td>
          <td><span class='badge $badgeClass'>$($ev.EventName)</span></td>
          <td><span class='badge $badgeClass'>$($ev.Severity)</span></td>
          <td class='user-cell'>$user</td>
          <td class='ip-cell'>$ip</td>
          <td class='mono'>$($ev.Protocol)</td>
          <td class='mono' title='$ep'>$(if($ep.Length -gt 40){ $ep.Substring(0,40)+'...' } else { $ep })</td>
          <td class='rp-cell' title='$rp'>$rp</td>
          <td class='mono' style='font-size:10px;color:#6e7681;'>$(if($actId){ $actId.Substring(0,[Math]::Min(8,$actId.Length))+'...' } else { '' })</td>
          <td style='color:#f85149;font-size:11px;'>$errD</td>
        </tr>")
    }

    $html = @"
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ADFS-Inspector Report -- $(Get-Date -Format 'yyyy-MM-dd HH:mm')</title>
<style>$($script:HtmlCss)</style>
</head>
<body>
<h1>ADFS-Inspector -- Authentication Log Report</h1>
<p class="meta">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  |  Window: $firstTime -&gt; $lastTime</p>

<div class="stats">
  <div class="stat-card"><div class="label">Total Events</div><div class="value" style="color:#c9d1d9;">$total</div></div>
  <div class="stat-card"><div class="label">Success</div><div class="value v-success">$success</div></div>
  <div class="stat-card"><div class="label">Errors</div><div class="value v-error">$errors</div></div>
  <div class="stat-card"><div class="label">Warnings</div><div class="value v-warning">$warnings</div></div>
  <div class="stat-card"><div class="label">Info</div><div class="value v-info">$info</div></div>
</div>

<div class="container">
<table>
<thead>
  <tr>
    <th>Time</th><th>ID</th><th>Event</th><th>Severity</th>
    <th>User</th><th>Client IP</th><th>Protocol</th>
    <th>Endpoint</th><th>Relying Party</th><th>Activity ID</th><th>Error</th>
  </tr>
</thead>
<tbody>
$($rows.ToString())
</tbody>
</table>
</div>
</body>
</html>
"@

    Set-Content -Path $Path -Value $html -Encoding UTF8 -Force
    Write-Verbose "HTML exportado: $Path ($total eventos)"
}

# ---------------------------------------------------------------------------
# Función pública: modo Follow (tail -f sobre el Event Log)
# ---------------------------------------------------------------------------
function Invoke-FollowMode {
    <#
    .SYNOPSIS
        Monitorea el log de AD FS en tiempo real, imprimiendo solo nuevos eventos.
    .DESCRIPTION
        Implementa tail -f sobre el Event Log usando Get-WinEvent con un
        timestamp creciente. No recarga la pantalla completa: solo append.
        Interrumpir con Ctrl+C.
    .PARAMETER LogName
        Nombre del log a monitorear.
    .PARAMETER IntervalSeconds
        Segundos entre cada sondeo. Default: 5.
    .PARAMETER View
        Modo de vista: Detailed | Timeline.
    .PARAMETER FilterParams
        Hashtable de filtros adicionales a aplicar a los nuevos eventos.
    .EXAMPLE
        Invoke-FollowMode -LogName 'AD FS/Admin' -IntervalSeconds 5 -View Timeline
    #>
    [CmdletBinding()]
    param(
        [string]$LogName = 'AD FS/Admin',
        [int]$IntervalSeconds = 5,
        [ValidateSet('Detailed','Timeline')]
        [string]$View = 'Timeline',
        [hashtable]$FilterParams = @{}
    )

    Write-Host ''
    Write-Host "  [*] FOLLOW MODE -- $LogName" -ForegroundColor Cyan
    Write-Host "  Interval: ${IntervalSeconds}s  |  View: $View  |  Press Ctrl+C to stop" -ForegroundColor DarkGray
    Write-Host ''

    $lastCheck = (Get-Date).AddSeconds(-$IntervalSeconds)

    while ($true) {
        $now = Get-Date
        try {
            $filter = @{
                LogName   = $LogName
                StartTime = $lastCheck
                EndTime   = $now
            }
            $rawEvents = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue

            if ($rawEvents) {
                $parsed = $rawEvents | ConvertTo-AdfsEvent
                $filtered = Invoke-AdfsFilter -Events @($parsed) -FilterParams $FilterParams

                foreach ($ev in ($filtered | Sort-Object TimeCreated)) {
                    if ($View -eq 'Timeline') {
                        Show-TimelineEvent -Event $ev
                    } else {
                        Show-DetailedEvent -Event $ev
                    }
                }
            }
        }
        catch {
            Write-Host "  [!] Error reading log: $_" -ForegroundColor Red
        }

        $lastCheck = $now
        Start-Sleep -Seconds $IntervalSeconds
    }
}

# ---------------------------------------------------------------------------
# Función pública: verificar que el log de AD FS existe y hay permisos
# ---------------------------------------------------------------------------
function Test-AdfsLogAccess {
    <#
    .SYNOPSIS
        Verifica que el log especificado existe y es accesible.
    .PARAMETER LogName
        Nombre del log a verificar.
    .OUTPUTS
        Boolean: $true si accesible, $false si no.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$LogName
    )

    try {
        $null = Get-WinEvent -ListLog $LogName -ErrorAction Stop
        return $true
    }
    catch [System.UnauthorizedAccessException] {
        Write-Host "  [!] Access denied to '$LogName'. Run as Administrator." -ForegroundColor Red
        return $false
    }
    catch {
        Write-Host "  [!] Log '$LogName' not found or not accessible." -ForegroundColor Red
        Write-Host "      Available AD FS logs:" -ForegroundColor DarkGray
        Get-WinEvent -ListLog 'AD FS*' -ErrorAction SilentlyContinue |
            ForEach-Object { Write-Host "      -- $($_.LogName)" -ForegroundColor DarkGray }
        return $false
    }
}

# ---------------------------------------------------------------------------
# Función pública: construir descripción de filtros activos para display
# ---------------------------------------------------------------------------
function Get-FilterDescription {
    <#
    .SYNOPSIS
        Construye una cadena legible con los filtros activos.
    .PARAMETER Params
        Hashtable de parámetros de filtrado.
    .OUTPUTS
        String descriptivo.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [hashtable]$Params
    )

    $parts = [System.Collections.Generic.List[string]]::new()

    if ($Params['User'])         { $parts.Add("User='$($Params['User'])'") }
    if ($Params['IP'])           { $parts.Add("IP='$($Params['IP'])'") }
    if ($Params['ActivityId'])   { $parts.Add("ActivityId='$($Params['ActivityId'])'") }
    if ($Params['EventId'] -gt 0){ $parts.Add("EventId=$($Params['EventId'])") }
    if ($Params['ErrorsOnly'])   { $parts.Add('ErrorsOnly') }
    if ($Params['WarningsOnly']) { $parts.Add('WarningsOnly') }
    if ($Params['Protocol'])     { $parts.Add("Protocol='$($Params['Protocol'])'") }
    if ($Params['RelyingParty']) { $parts.Add("RP='$($Params['RelyingParty'])'") }

    if ($parts.Count -eq 0) { return 'none' }
    return $parts -join '  |  '
}

Export-ModuleMember -Function Export-ToCsv, Export-ToJson, Export-ToHtml,
                               Invoke-FollowMode, Test-AdfsLogAccess, Get-FilterDescription
