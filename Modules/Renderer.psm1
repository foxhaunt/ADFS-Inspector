#Requires -Version 5.1
<#
.SYNOPSIS
    Renderizado de eventos AD FS en consola con colores y vistas múltiples.
.DESCRIPTION
    Contiene toda la lógica de presentación visual. No lee logs ni filtra.
    Recibe objetos PSCustomObject del Parser y los muestra con Write-Host.
    Compatible con PowerShell 5.1 (no usa Write-Information coloreado).
#>

Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------------
# Constantes de presentación
# ---------------------------------------------------------------------------
$script:Separator  = '─' * 70
$script:ThinSep    = '·' * 70
$script:ColLabel   = 'DarkCyan'
$script:ColValue   = 'White'
$script:ColMuted   = 'DarkGray'
$script:ColBorder  = 'DarkGray'

# ---------------------------------------------------------------------------
# Función interna: Write-Host con color de severidad
# ---------------------------------------------------------------------------
function script:Write-Severity {
    param(
        [string]$Text,
        [string]$Severity,
        [switch]$NoNewLine
    )
    $color = Get-SeverityColor -Severity $Severity
    if ($NoNewLine) {
        Write-Host $Text -ForegroundColor $color -NoNewline
    } else {
        Write-Host $Text -ForegroundColor $color
    }
}

# ---------------------------------------------------------------------------
# Función interna: imprimir línea de campo/valor
# ---------------------------------------------------------------------------
function script:Write-Field {
    param(
        [string]$Label,
        [string]$Value,
        [int]$Indent = 2
    )
    if ([string]::IsNullOrEmpty($Value)) { return }
    $pad = ' ' * $Indent
    Write-Host "${pad}$($Label.PadRight(15))" -ForegroundColor $script:ColLabel -NoNewline
    Write-Host ": $Value" -ForegroundColor $script:ColValue
}

# ---------------------------------------------------------------------------
# Función pública: vista detallada de un evento
# ---------------------------------------------------------------------------
function Show-DetailedEvent {
    <#
    .SYNOPSIS
        Muestra un evento AD FS en formato detallado con todos los campos.
    .PARAMETER Event
        PSCustomObject producido por ConvertTo-AdfsEvent.
    .EXAMPLE
        $events | Show-DetailedEvent
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject]$Event
    )

    process {
        $icon     = Get-SeverityIcon -Severity $Event.Severity
        $timeStr  = $Event.TimeCreated.ToString('HH:mm:ss.fff')
        $color    = Get-SeverityColor -Severity $Event.Severity

        Write-Host $script:Separator -ForegroundColor $script:ColBorder
        # Cabecera: timestamp + icono + nombre del evento + EventId
        Write-Host "[$timeStr]  " -ForegroundColor $script:ColMuted -NoNewline
        Write-Host "$icon $($Event.EventName)" -ForegroundColor $color -NoNewline
        Write-Host "  (ID: $($Event.EventId))" -ForegroundColor $script:ColMuted

        if ($Event.Description) {
            Write-Host "  $($Event.Description)" -ForegroundColor $script:ColMuted
        }

        Write-Host ''

        # Campos de identidad
        script:Write-Field 'User'          $Event.User
        script:Write-Field 'Client IP'     $Event.ClientIp
        script:Write-Field 'Protocol'      $Event.Protocol
        script:Write-Field 'Endpoint'      $Event.Endpoint
        script:Write-Field 'Request URI'   $Event.RequestUri
        script:Write-Field 'Relying Party' $Event.RelyingParty
        script:Write-Field 'Claims Prov.'  $Event.ClaimsProvider
        script:Write-Field 'Activity ID'   $Event.ActivityId
        script:Write-Field 'Correlation'   $Event.CorrelationId
        script:Write-Field 'Server'        $Event.MachineName

        # Error detail si existe
        if ($Event.ErrorDetail -and $Event.Severity -in @('Error','Warning')) {
            Write-Host ''
            Write-Host '  ERROR DETAIL' -ForegroundColor $script:ColLabel
            Write-Host "  $($Event.ErrorDetail)" -ForegroundColor ([System.ConsoleColor]::Red)
        }

        Write-Host ''
    }
}

# ---------------------------------------------------------------------------
# Función pública: vista timeline (una línea por evento)
# ---------------------------------------------------------------------------
function Show-TimelineEvent {
    <#
    .SYNOPSIS
        Muestra un evento en formato de línea de timeline compacta.
    .PARAMETER Event
        PSCustomObject producido por ConvertTo-AdfsEvent.
    .EXAMPLE
        $events | Show-TimelineEvent
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject]$Event
    )

    process {
        $icon    = Get-SeverityIcon -Severity $Event.Severity
        $color   = Get-SeverityColor -Severity $Event.Severity
        $timeStr = $Event.TimeCreated.ToString('HH:mm:ss')

        Write-Host $timeStr -ForegroundColor $script:ColMuted -NoNewline
        Write-Host '  ' -NoNewline
        Write-Host "$icon $($Event.EventName.PadRight(28))" -ForegroundColor $color -NoNewline

        $user = if ($Event.User) { $Event.User.PadRight(35) } else { ''.PadRight(35) }
        Write-Host $user -ForegroundColor $script:ColValue -NoNewline

        if ($Event.ClientIp) {
            Write-Host $Event.ClientIp -ForegroundColor $script:ColMuted
        } else {
            Write-Host ''
        }
    }
}

# ---------------------------------------------------------------------------
# Función pública: mostrar el flujo de autenticación de un ActivityId
# ---------------------------------------------------------------------------
function Show-AuthFlow {
    <#
    .SYNOPSIS
        Muestra el flujo completo de una autenticación agrupada por ActivityId.
    .PARAMETER ActivityId
        El GUID del Activity ID.
    .PARAMETER Flow
        Array de PSCustomObject del flujo (mismo ActivityId), ordenados.
    .EXAMPLE
        Show-AuthFlow -ActivityId $id -Flow $flows[$id]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ActivityId,

        [Parameter(Mandatory)]
        [PSCustomObject[]]$Flow
    )

    # Resumen del flujo
    $summary = Get-FlowSummary -Flow $Flow
    $outColor = switch ($summary.Outcome) {
        'Success'    { 'Green'  }
        'Failure'    { 'Red'    }
        'Incomplete' { 'Yellow' }
        default      { 'White'  }
    }

    Write-Host ''
    Write-Host ('═' * 70) -ForegroundColor $script:ColBorder
    Write-Host "  AUTHENTICATION FLOW" -ForegroundColor Cyan
    Write-Host ('═' * 70) -ForegroundColor $script:ColBorder

    Write-Host "  Activity ID : " -ForegroundColor $script:ColLabel -NoNewline
    Write-Host $ActivityId -ForegroundColor White
    Write-Host "  Outcome     : " -ForegroundColor $script:ColLabel -NoNewline
    Write-Host $summary.Outcome -ForegroundColor $outColor
    Write-Host "  Duration    : " -ForegroundColor $script:ColLabel -NoNewline
    Write-Host "$($summary.DurationMs) ms" -ForegroundColor White
    if ($summary.User)        { Write-Host "  User        : " -ForegroundColor $script:ColLabel -NoNewline; Write-Host $summary.User        -ForegroundColor White }
    if ($summary.ClientIp)    { Write-Host "  Client IP   : " -ForegroundColor $script:ColLabel -NoNewline; Write-Host $summary.ClientIp    -ForegroundColor White }
    if ($summary.Protocol)    { Write-Host "  Protocol    : " -ForegroundColor $script:ColLabel -NoNewline; Write-Host $summary.Protocol    -ForegroundColor White }
    if ($summary.RelyingParty){ Write-Host "  Relying Party:" -ForegroundColor $script:ColLabel -NoNewline; Write-Host " $($summary.RelyingParty)" -ForegroundColor White }

    Write-Host ''
    Write-Host '  TIMELINE' -ForegroundColor $script:ColLabel
    Write-Host ('  ' + $script:ThinSep) -ForegroundColor $script:ColBorder

    $baseTime = $Flow[0].TimeCreated
    foreach ($ev in $Flow) {
        $offsetMs = [int](($ev.TimeCreated - $baseTime).TotalMilliseconds)
        $step     = Get-FlowStepLabel -Event $ev
        $icon     = Get-SeverityIcon -Severity $ev.Severity
        $color    = Get-SeverityColor -Severity $ev.Severity

        Write-Host "  +$($offsetMs.ToString().PadLeft(6)) ms  " -ForegroundColor $script:ColMuted -NoNewline
        Write-Host "$step " -ForegroundColor $script:ColMuted -NoNewline
        Write-Host "$icon $($ev.EventName)" -ForegroundColor $color -NoNewline

        if ($ev.ErrorDetail -and $ev.Severity -in @('Error','Warning')) {
            Write-Host "  → $($ev.ErrorDetail.Substring(0, [Math]::Min(60, $ev.ErrorDetail.Length)))" -ForegroundColor DarkRed
        } else {
            Write-Host ''
        }
    }

    Write-Host ('═' * 70) -ForegroundColor $script:ColBorder
    Write-Host ''
}

# ---------------------------------------------------------------------------
# Función pública: mostrar resumen estadístico
# ---------------------------------------------------------------------------
function Show-Summary {
    <#
    .SYNOPSIS
        Muestra un resumen estadístico de la colección de eventos analizada.
    .PARAMETER Events
        Array de PSCustomObject producido por ConvertTo-AdfsEvent.
    .EXAMPLE
        Show-Summary -Events $events
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Events
    )

    $total    = $Events.Count
    $success  = ($Events | Where-Object { $_.Severity -eq 'Success'  }).Count
    $errors   = ($Events | Where-Object { $_.Severity -eq 'Error'    }).Count
    $warnings = ($Events | Where-Object { $_.Severity -eq 'Warning'  }).Count
    $info     = ($Events | Where-Object { $_.Severity -eq 'Info'     }).Count

    # Top usuarios con más errores
    $topUsers = $Events | Where-Object { $_.Severity -eq 'Error' -and $_.User } |
                Group-Object User | Sort-Object Count -Descending | Select-Object -First 5

    # Top IPs con más actividad
    $topIps = $Events | Where-Object { $_.ClientIp } |
              Group-Object ClientIp | Sort-Object Count -Descending | Select-Object -First 5

    # Distribución por protocolo
    $byProtocol = $Events | Where-Object { $_.Protocol } |
                  Group-Object Protocol | Sort-Object Count -Descending

    # Actividad IDs únicos
    $uniqueFlows = ($Events | Where-Object { $_.ActivityId } | Select-Object -ExpandProperty ActivityId -Unique).Count

    $firstTime = if ($total -gt 0) { ($Events | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated } else { $null }
    $lastTime  = if ($total -gt 0) { ($Events | Sort-Object TimeCreated | Select-Object -Last  1).TimeCreated } else { $null }

    Write-Host ''
    Write-Host ('═' * 70) -ForegroundColor $script:ColBorder
    Write-Host '  ADFS-INSPECTOR  —  SUMMARY' -ForegroundColor Cyan
    Write-Host ('═' * 70) -ForegroundColor $script:ColBorder

    if ($firstTime) {
        Write-Host "  Window   : $($firstTime.ToString('yyyy-MM-dd HH:mm:ss'))  →  $($lastTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor $script:ColMuted
    }
    Write-Host "  Total    : $total events  |  $uniqueFlows unique flows" -ForegroundColor White
    Write-Host ''

    # Barra de severidades
    Write-Host '  SEVERITY BREAKDOWN' -ForegroundColor $script:ColLabel
    Write-Host "  [+] Success  : " -ForegroundColor Green  -NoNewline; Write-Host $success  -ForegroundColor White
    Write-Host "  [!] Errors   : " -ForegroundColor Red    -NoNewline; Write-Host $errors   -ForegroundColor White
    Write-Host "  [~] Warnings : " -ForegroundColor Yellow -NoNewline; Write-Host $warnings -ForegroundColor White
    Write-Host "  [i] Info     : " -ForegroundColor Cyan   -NoNewline; Write-Host $info     -ForegroundColor White

    if ($byProtocol.Count -gt 0) {
        Write-Host ''
        Write-Host '  BY PROTOCOL' -ForegroundColor $script:ColLabel
        foreach ($g in $byProtocol) {
            Write-Host "  $($g.Name.PadRight(20))" -ForegroundColor White -NoNewline
            Write-Host " $($g.Count)" -ForegroundColor $script:ColMuted
        }
    }

    if ($topUsers.Count -gt 0) {
        Write-Host ''
        Write-Host '  TOP FAILING USERS' -ForegroundColor $script:ColLabel
        foreach ($u in $topUsers) {
            Write-Host "  $($u.Name.PadRight(40))" -ForegroundColor White -NoNewline
            Write-Host " $($u.Count) errors" -ForegroundColor Red
        }
    }

    if ($topIps.Count -gt 0) {
        Write-Host ''
        Write-Host '  TOP SOURCE IPs' -ForegroundColor $script:ColLabel
        foreach ($ip in $topIps) {
            Write-Host "  $($ip.Name.PadRight(20))" -ForegroundColor White -NoNewline
            Write-Host " $($ip.Count) events" -ForegroundColor $script:ColMuted
        }
    }

    Write-Host ('═' * 70) -ForegroundColor $script:ColBorder
    Write-Host ''
}

# ---------------------------------------------------------------------------
# Función pública: imprimir cabecera de sesión
# ---------------------------------------------------------------------------
function Show-Header {
    <#
    .SYNOPSIS
        Muestra la cabecera de inicio de ADFS-Inspector.
    .PARAMETER LogName
        Nombre del log que se está analizando.
    .PARAMETER FilterDesc
        Descripción textual de los filtros activos.
    #>
    [CmdletBinding()]
    param(
        [string]$LogName    = 'AD FS/Admin',
        [string]$FilterDesc = ''
    )

    Write-Host ''
    Write-Host ('╔' + ('═' * 68) + '╗') -ForegroundColor Cyan
    Write-Host '║           ADFS-INSPECTOR  v1.0  —  AD FS Log Analyzer           ║' -ForegroundColor Cyan
    Write-Host ('╚' + ('═' * 68) + '╝') -ForegroundColor Cyan
    Write-Host "  Log    : $LogName" -ForegroundColor $script:ColMuted
    Write-Host "  Time   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor $script:ColMuted
    if ($FilterDesc) {
        Write-Host "  Filter : $FilterDesc" -ForegroundColor $script:ColMuted
    }
    Write-Host ''
}

# ---------------------------------------------------------------------------
# Función pública: imprimir mensaje de estado (no event)
# ---------------------------------------------------------------------------
function Show-StatusMessage {
    <#
    .SYNOPSIS
        Muestra un mensaje de estado/informativo al usuario.
    .PARAMETER Message
        El texto a mostrar.
    .PARAMETER Type
        Info | Warning | Error | Success
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success')]
        [string]$Type = 'Info'
    )

    $icon  = Get-SeverityIcon  -Severity $Type
    $color = Get-SeverityColor -Severity $Type
    Write-Host "  $icon $Message" -ForegroundColor $color
}

Export-ModuleMember -Function Show-DetailedEvent, Show-TimelineEvent, Show-AuthFlow,
                               Show-Summary, Show-Header, Show-StatusMessage
