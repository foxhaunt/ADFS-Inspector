#Requires -Version 5.1
<#
.SYNOPSIS
    ADFS-Inspector — Herramienta profesional de análisis de logs de AD FS.

.DESCRIPTION
    Analiza los eventos del Event Log de AD FS transformándolos en información
    accionable: flujos de autenticación correlacionados, resúmenes estadísticos,
    filtrado avanzado y exportación en múltiples formatos.

    Soporta los protocolos: WS-Trust, WS-Federation, SAML, OAuth 2.0,
    OpenID Connect, MFA, Device Registration y PRT.

    Requiere ejecutarse como Administrador para acceder al log 'AD FS/Admin'.

.PARAMETER Today
    Analizar únicamente los eventos del día de hoy (desde las 00:00).

.PARAMETER LastMinutes
    Analizar los últimos N minutos. Incompatible con -Today.

.PARAMETER User
    Filtrar por usuario o UPN. Admite wildcards: -User "*eva*"

.PARAMETER IP
    Filtrar por dirección IP de cliente. Admite wildcards: -IP "192.168.*"

.PARAMETER ActivityId
    Mostrar el flujo completo de una autenticación específica por su Activity ID (GUID).

.PARAMETER EventId
    Filtrar por un Event ID concreto. Ej: -EventId 364

.PARAMETER Protocol
    Filtrar por protocolo: WS-Trust, OAuth, SAML, OIDC, MFA, etc.

.PARAMETER RelyingParty
    Filtrar por Relying Party. Admite wildcards: -RelyingParty "*Office 365*"

.PARAMETER Follow
    Modo tail -f: monitorear el log en tiempo real imprimiendo solo nuevos eventos.
    Interrumpir con Ctrl+C.

.PARAMETER FollowInterval
    Segundos entre cada sondeo en modo -Follow. Default: 5.

.PARAMETER ErrorsOnly
    Mostrar únicamente eventos de error.

.PARAMETER WarningsOnly
    Mostrar únicamente eventos de advertencia.

.PARAMETER Summary
    Mostrar resumen estadístico en lugar de los eventos individuales.

.PARAMETER View
    Modo de presentación: Detailed (por defecto) o Timeline.
    - Detailed: un bloque por evento con todos los campos.
    - Timeline: una línea por evento.

.PARAMETER ExportCsv
    Exportar resultados a un archivo CSV en la ruta indicada.

.PARAMETER ExportJson
    Exportar resultados a un archivo JSON en la ruta indicada.

.PARAMETER ExportHtml
    Exportar resultados como dashboard HTML en la ruta indicada.

.PARAMETER LogName
    Nombre del Event Log a leer. Default: 'AD FS/Admin'.
    Ampliar a otros logs: 'AD FS Tracing/Debug', 'Security', etc.

.PARAMETER MaxEvents
    Número máximo de eventos a leer del log. Default: 500.
    Aumentar para análisis históricos extensos.

.PARAMETER ListEvents
    Mostrar el catálogo completo de Event IDs conocidos y salir.

.EXAMPLE
    .\ADFS-Inspector.ps1 -Today -Summary
    Resumen estadístico de la autenticación de hoy.

.EXAMPLE
    .\ADFS-Inspector.ps1 -LastMinutes 60 -ErrorsOnly -View Timeline
    Todos los errores de la última hora en vista compacta.

.EXAMPLE
    .\ADFS-Inspector.ps1 -User "eva@foxhaunt.es" -Today
    Todos los eventos del usuario eva hoy.

.EXAMPLE
    .\ADFS-Inspector.ps1 -ActivityId "3f2c1a4b-0000-0000-0000-000000000001"
    Flujo completo de una autenticación específica.

.EXAMPLE
    .\ADFS-Inspector.ps1 -IP "192.168.1.15" -LastMinutes 30 -ErrorsOnly
    Errores de una IP específica en los últimos 30 minutos.

.EXAMPLE
    .\ADFS-Inspector.ps1 -Follow -View Timeline -ErrorsOnly
    Monitor en tiempo real mostrando solo errores.

.EXAMPLE
    .\ADFS-Inspector.ps1 -Today -ExportHtml "C:\Reports\adfs-$(Get-Date -f yyyyMMdd).html"
    Exportar el día de hoy como dashboard HTML.

.EXAMPLE
    .\ADFS-Inspector.ps1 -EventId 364 -LastMinutes 120 -ExportCsv "C:\Reports\failures.csv"
    Exportar todos los AUTH_FAILURE de las últimas 2 horas.

.EXAMPLE
    .\ADFS-Inspector.ps1 -Protocol OAuth -Today -Summary
    Resumen de autenticaciones OAuth del día.

.NOTES
    Autor:       ADFS-Inspector Project
    Versión:     1.0.0
    Compatibilidad: PowerShell 5.1, Windows Server 2019/2016
    Repositorio: https://github.com/tu-org/ADFS-Inspector
#>

[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
    # ── Rango de tiempo ─────────────────────────────────────────────────────
    [Parameter(ParameterSetName = 'Today')]
    [switch]$Today,

    [Parameter(ParameterSetName = 'LastMinutes')]
    [ValidateRange(1, 525600)]  # max 1 año en minutos
    [int]$LastMinutes,

    # ── Filtros de contenido ─────────────────────────────────────────────────
    [string]$User,
    [string]$IP,
    [string]$ActivityId,
    [int]$EventId,
    [string]$Protocol,
    [string]$RelyingParty,

    # ── Filtros de severidad ─────────────────────────────────────────────────
    [switch]$ErrorsOnly,
    [switch]$WarningsOnly,

    # ── Modos de operación ───────────────────────────────────────────────────
    [switch]$Follow,
    [ValidateRange(1, 300)]
    [int]$FollowInterval = 5,
    [switch]$Summary,
    [ValidateSet('Detailed', 'Timeline')]
    [string]$View = 'Detailed',
    [switch]$ListEvents,

    # ── Exportación ──────────────────────────────────────────────────────────
    [string]$ExportCsv,
    [string]$ExportJson,
    [string]$ExportHtml,

    # ── Configuración avanzada ───────────────────────────────────────────────
    [string]$LogName = 'AD FS/Admin',
    [ValidateRange(1, 100000)]
    [int]$MaxEvents = 500
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Cargar módulos (ruta relativa al script)
# ---------------------------------------------------------------------------
$ModulesPath = Join-Path $PSScriptRoot 'Modules'

$moduleFiles = @(
    'EventDictionary.psm1',
    'Parser.psm1',
    'Filters.psm1',
    'Timeline.psm1',
    'Renderer.psm1',
    'Utils.psm1'
)

foreach ($mod in $moduleFiles) {
    $modPath = Join-Path $ModulesPath $mod
    if (-not (Test-Path $modPath)) {
        Write-Error "Module not found: $modPath`nEnsure ADFS-Inspector is installed correctly."
        exit 1
    }
    Import-Module $modPath -Force -DisableNameChecking
}

# ---------------------------------------------------------------------------
# Modo ListEvents: mostrar catálogo y salir
# ---------------------------------------------------------------------------
if ($ListEvents) {
    Show-Header -LogName $LogName
    Write-Host '  KNOWN EVENT IDs' -ForegroundColor Cyan
    Write-Host ''
    Get-AllKnownEventIds | Format-Table -AutoSize | Out-String | Write-Host
    exit 0
}

# ---------------------------------------------------------------------------
# Construir descripción de filtros para la cabecera
# ---------------------------------------------------------------------------
$filterParams = @{
    User         = $User
    IP           = $IP
    ActivityId   = $ActivityId
    EventId      = $EventId
    ErrorsOnly   = $ErrorsOnly.IsPresent
    WarningsOnly = $WarningsOnly.IsPresent
    Protocol     = $Protocol
    RelyingParty = $RelyingParty
}

$filterDesc = Get-FilterDescription -Params $filterParams

# ---------------------------------------------------------------------------
# Mostrar cabecera
# ---------------------------------------------------------------------------
Show-Header -LogName $LogName -FilterDesc $filterDesc

# ---------------------------------------------------------------------------
# Modo Follow: delegar y salir
# ---------------------------------------------------------------------------
if ($Follow) {
    if (-not (Test-AdfsLogAccess -LogName $LogName)) { exit 1 }
    Invoke-FollowMode -LogName $LogName -IntervalSeconds $FollowInterval `
                      -View $View -FilterParams $filterParams
    exit 0
}

# ---------------------------------------------------------------------------
# Calcular rango de tiempo
# ---------------------------------------------------------------------------
$timeRange = Resolve-TimeRange -Today:$Today -LastMinutes $LastMinutes

# ---------------------------------------------------------------------------
# Verificar acceso al log
# ---------------------------------------------------------------------------
if (-not (Test-AdfsLogAccess -LogName $LogName)) { exit 1 }

# ---------------------------------------------------------------------------
# Leer eventos con FilterHashtable (pre-filtrado eficiente en ETW)
# ---------------------------------------------------------------------------
$winEventParams = @{
    FilterHashtable = Build-WinEventFilter -LogName $LogName `
                          -EventId $EventId
    MaxEvents       = $MaxEvents
    ErrorAction     = 'SilentlyContinue'
}

# Añadir rango de tiempo al FilterHashtable si aplica
if ($timeRange.StartTime) {
    $winEventParams.FilterHashtable['StartTime'] = $timeRange.StartTime
    $winEventParams.FilterHashtable['EndTime']   = $timeRange.EndTime
}

Write-Verbose "Querying: $LogName  |  StartTime: $($timeRange.StartTime)  |  MaxEvents: $MaxEvents"

$rawEvents = $null
try {
    $rawEvents = @(Get-WinEvent @winEventParams)
}
catch [System.Exception] {
    if ($_.Exception.Message -like '*No events*' -or $_.Exception.HResult -eq -2147024809) {
        Show-StatusMessage -Message 'No events found in the specified time range.' -Type 'Warning'
        exit 0
    }
    Write-Error "Failed to read event log: $_"
    exit 1
}

if (-not $rawEvents -or $rawEvents.Count -eq 0) {
    Show-StatusMessage -Message 'No events found matching the specified criteria.' -Type 'Warning'
    exit 0
}

Show-StatusMessage -Message "Read $($rawEvents.Count) raw events from '$LogName'." -Type 'Info'

# ---------------------------------------------------------------------------
# Parsear eventos
# ---------------------------------------------------------------------------
$parsedList = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($raw in $rawEvents) {
    try {
        $parsed = ConvertTo-AdfsEvent -RawEvent $raw
        $parsedList.Add($parsed)
    }
    catch {
        Write-Verbose "Failed to parse event $($raw.Id): $_"
    }
}
$parsed = $parsedList.ToArray()

Write-Verbose "Parsed: $($parsed.Count) events"

# ---------------------------------------------------------------------------
# Aplicar filtros de post-lectura
# ---------------------------------------------------------------------------
$filtered = @(Invoke-AdfsFilter -Events $parsed -FilterParams $filterParams)

if ($filtered.Count -eq 0) {
    Show-StatusMessage -Message 'No events matched the active filters.' -Type 'Warning'
    exit 0
}

Show-StatusMessage -Message "Filtered: $($filtered.Count) events match your criteria." -Type 'Success'
Write-Host ''

# ---------------------------------------------------------------------------
# Modo ActivityId: mostrar flujo completo de autenticación
# ---------------------------------------------------------------------------
if ($ActivityId) {
    $flow = @(Get-SingleFlow -Events $filtered -ActivityId $ActivityId)
    if (-not $flow -or $flow.Count -eq 0) {
        Show-StatusMessage -Message "No events found for ActivityId: $ActivityId" -Type 'Warning'
        exit 0
    }
    Show-AuthFlow -ActivityId $ActivityId -Flow $flow
}
# ---------------------------------------------------------------------------
# Modo Summary
# ---------------------------------------------------------------------------
elseif ($Summary) {
    Show-Summary -Events $filtered
}
# ---------------------------------------------------------------------------
# Modo normal: mostrar eventos individuales
# ---------------------------------------------------------------------------
else {
    if ($View -eq 'Timeline') {
        # Cabecera de columnas para la vista timeline
        Write-Host "  $('TIME'.PadRight(10))  $('EVENT'.PadRight(30))$('USER'.PadRight(35))CLIENT IP" -ForegroundColor DarkCyan
        Write-Host "  $('─' * 8)  $('─' * 28)$('─' * 33)$('─' * 15)" -ForegroundColor DarkGray
        foreach ($ev in ($filtered | Sort-Object TimeCreated)) {
            Show-TimelineEvent -Event $ev
        }
    }
    else {
        foreach ($ev in ($filtered | Sort-Object TimeCreated)) {
            Show-DetailedEvent -Event $ev
        }
    }
}

# ---------------------------------------------------------------------------
# Exportaciones
# ---------------------------------------------------------------------------
if ($ExportCsv) {
    try {
        Export-ToCsv -Events $filtered -Path $ExportCsv
        Show-StatusMessage -Message "CSV exported: $ExportCsv" -Type 'Success'
    }
    catch {
        Show-StatusMessage -Message "CSV export failed: $_" -Type 'Error'
    }
}

if ($ExportJson) {
    try {
        Export-ToJson -Events $filtered -Path $ExportJson
        Show-StatusMessage -Message "JSON exported: $ExportJson" -Type 'Success'
    }
    catch {
        Show-StatusMessage -Message "JSON export failed: $_" -Type 'Error'
    }
}

if ($ExportHtml) {
    try {
        Export-ToHtml -Events $filtered -Path $ExportHtml
        Show-StatusMessage -Message "HTML dashboard exported: $ExportHtml" -Type 'Success'
    }
    catch {
        Show-StatusMessage -Message "HTML export failed: $_" -Type 'Error'
    }
}

Write-Host ''
