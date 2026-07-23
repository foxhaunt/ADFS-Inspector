#Requires -Version 5.1
<#
.SYNOPSIS
    ADFS-Inspector — Herramienta profesional de analisis de logs de AD FS.

.DESCRIPTION
    Analiza los eventos del Event Log de AD FS transformandolos en informacion
    accionable: flujos de autenticacion correlacionados, resumenes estadisticos,
    filtrado avanzado y exportacion en multiples formatos.

    Soporta los protocolos: WS-Trust, WS-Federation, SAML, OAuth 2.0,
    OpenID Connect, MFA, Device Registration y PRT.

    Requiere ejecutarse como Administrador para acceder a los logs de AD FS.

.PARAMETER Today
    Analizar unicamente los eventos del dia de hoy (desde las 00:00).

.PARAMETER LastMinutes
    Analizar los ultimos N minutos. Incompatible con -Today.

.PARAMETER User
    Filtrar por usuario o UPN. Admite wildcards: -User "*eva*"

.PARAMETER IP
    Filtrar por direccion IP de cliente. Admite wildcards: -IP "192.168.*"

.PARAMETER ActivityId
    Mostrar el flujo completo de una autenticacion especifica por su Activity ID (GUID).

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
    Mostrar unicamente eventos de error.

.PARAMETER WarningsOnly
    Mostrar unicamente eventos de advertencia.

.PARAMETER Summary
    Mostrar resumen estadistico en lugar de los eventos individuales.

.PARAMETER View
    Modo de presentacion: Detailed (por defecto) o Timeline.
    - Detailed: un bloque por evento con todos los campos.
    - Timeline: una linea por evento.

.PARAMETER ExportCsv
    Exportar resultados a un archivo CSV en la ruta indicada.

.PARAMETER ExportJson
    Exportar resultados a un archivo JSON en la ruta indicada.

.PARAMETER ExportHtml
    Exportar resultados como dashboard HTML en la ruta indicada.

.PARAMETER LogName
    Nombre del Event Log a leer. Default: 'AD FS/Admin'.
    Ignorado si se usa -AllLogs.

.PARAMETER AllLogs
    Leer TODOS los logs de AD FS simultaneamente:
      - AD FS/Admin        (WS-Trust, WS-Fed, claims)
      - AD FS/Operational  (Forms, OAuth/OIDC, dispositivos)
      - Security           (auditoria AD FS, filtrado por proveedor)
      - AD FS Tracing/Debug (traza detallada, si esta habilitado)
    Los eventos de todos los logs se fusionan y ordenan por hora.

.PARAMETER MaxEvents
    Numero maximo de eventos a leer POR LOG. Default: 500.
    Con -AllLogs el total puede ser hasta 4x este valor.

.PARAMETER ListEvents
    Mostrar el catalogo completo de Event IDs conocidos y salir.

.EXAMPLE
    .\ADFS-Inspector.ps1 -AllLogs -Today -Summary
    Resumen estadistico de TODOS los logs de AD FS del dia de hoy.

.EXAMPLE
    .\ADFS-Inspector.ps1 -AllLogs -LastMinutes 30 -View Timeline
    Timeline con TODOS los eventos de AD FS de los ultimos 30 minutos.

.EXAMPLE
    .\ADFS-Inspector.ps1 -AllLogs -User "bob@contoso.com" -Today
    Todos los eventos del usuario bob en todos los logs de hoy.

.EXAMPLE
    .\ADFS-Inspector.ps1 -Today -Summary
    Resumen estadistico del log Admin de hoy.

.EXAMPLE
    .\ADFS-Inspector.ps1 -LastMinutes 60 -ErrorsOnly -View Timeline
    Todos los errores de la ultima hora en vista compacta.

.EXAMPLE
    .\ADFS-Inspector.ps1 -User "eva@foxhaunt.es" -Today
    Todos los eventos del usuario eva hoy.

.EXAMPLE
    .\ADFS-Inspector.ps1 -ActivityId "3f2c1a4b-0000-0000-0000-000000000001"
    Flujo completo de una autenticacion especifica.

.EXAMPLE
    .\ADFS-Inspector.ps1 -Follow -AllLogs -View Timeline -ErrorsOnly
    Monitor en tiempo real mostrando solo errores de todos los logs.

.EXAMPLE
    .\ADFS-Inspector.ps1 -AllLogs -Today -ExportHtml "C:\Reports\adfs-$(Get-Date -f yyyyMMdd).html"
    Exportar el dia de hoy (todos los logs) como dashboard HTML.

.NOTES
    Autor:       ADFS-Inspector Project
    Version:     1.1.0
    Compatibilidad: PowerShell 5.1, Windows Server 2019/2016
    Repositorio: https://github.com/foxhaunt/ADFS-Inspector
#>

[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
    # -- Rango de tiempo --
    [Parameter(ParameterSetName = 'Today')]
    [switch]$Today,

    [Parameter(ParameterSetName = 'LastMinutes')]
    [ValidateRange(1, 525600)]
    [int]$LastMinutes,

    # -- Filtros de contenido --
    [string]$User,
    [string]$IP,
    [string]$ActivityId,
    [int]$EventId,
    [string]$Protocol,
    [string]$RelyingParty,

    # -- Filtros de severidad --
    [switch]$ErrorsOnly,
    [switch]$WarningsOnly,

    # -- Modos de operacion --
    [switch]$Follow,
    [ValidateRange(1, 300)]
    [int]$FollowInterval = 5,
    [switch]$Summary,
    [ValidateSet('Detailed', 'Timeline')]
    [string]$View = 'Detailed',
    [switch]$ListEvents,

    # -- Exportacion --
    [string]$ExportCsv,
    [string]$ExportJson,
    [string]$ExportHtml,

    # -- Configuracion avanzada --
    [string]$LogName = 'AD FS/Admin',
    [switch]$AllLogs,
    [ValidateRange(1, 100000)]
    [int]$MaxEvents = 500
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Cargar modulos (ruta relativa al script)
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
# Definir los logs a consultar
# ---------------------------------------------------------------------------
# Cada entrada: Name = nombre del log, Provider = filtro opcional de proveedor
if ($AllLogs) {
    $logDefinitions = @(
        @{ Name = 'AD FS/Admin';          Provider = '' },
        @{ Name = 'AD FS/Operational';    Provider = '' },
        @{ Name = 'AD FS Tracing/Debug';  Provider = '' },
        @{ Name = 'Security';             Provider = 'AD FS Auditing' }
    )
    $headerLogName = 'ALL AD FS LOGS'
} else {
    $logDefinitions = @(
        @{ Name = $LogName; Provider = '' }
    )
    $headerLogName = $LogName
}

# ---------------------------------------------------------------------------
# Modo ListEvents: mostrar catalogo y salir
# ---------------------------------------------------------------------------
if ($ListEvents) {
    Show-Header -LogName $headerLogName
    Write-Host '  KNOWN EVENT IDs' -ForegroundColor Cyan
    Write-Host ''
    Get-AllKnownEventIds | Format-Table -AutoSize | Out-String | Write-Host
    exit 0
}

# ---------------------------------------------------------------------------
# Construir descripcion de filtros para la cabecera
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
Show-Header -LogName $headerLogName -FilterDesc $filterDesc

# ---------------------------------------------------------------------------
# Modo Follow: delegar y salir
# ---------------------------------------------------------------------------
if ($Follow) {
    if ($AllLogs) {
        Invoke-FollowModeMulti -LogDefinitions $logDefinitions `
                               -IntervalSeconds $FollowInterval `
                               -View $View -FilterParams $filterParams
    } else {
        if (-not (Test-AdfsLogAccess -LogName $LogName)) { exit 1 }
        Invoke-FollowMode -LogName $LogName -IntervalSeconds $FollowInterval `
                          -View $View -FilterParams $filterParams
    }
    exit 0
}

# ---------------------------------------------------------------------------
# Calcular rango de tiempo
# ---------------------------------------------------------------------------
$timeRange = Resolve-TimeRange -Today:$Today -LastMinutes $LastMinutes

# ---------------------------------------------------------------------------
# Leer eventos de todos los logs configurados
# ---------------------------------------------------------------------------
$allRawEvents = [System.Collections.Generic.List[object]]::new()
$accessibleLogs = [System.Collections.Generic.List[string]]::new()
$seenRecordIds  = [System.Collections.Generic.HashSet[long]]::new()

foreach ($logDef in $logDefinitions) {
    $logN = $logDef.Name
    $prov = $logDef.Provider

    # Verificar acceso al log (silencioso si no existe, solo warn)
    if (-not (Test-AdfsLogAccess -LogName $logN -Silent)) {
        continue
    }

    $filterHt = Build-WinEventFilter -LogName $logN -EventId $EventId -ProviderName $prov
    if ($timeRange.StartTime) {
        $filterHt['StartTime'] = $timeRange.StartTime
        $filterHt['EndTime']   = $timeRange.EndTime
    }

    $winEventParams = @{
        FilterHashtable = $filterHt
        MaxEvents       = $MaxEvents
        ErrorAction     = 'SilentlyContinue'
    }

    Write-Verbose "Querying log: $logN  |  Provider: '$prov'  |  StartTime: $($timeRange.StartTime)"

    try {
        $rawBatch = @(Get-WinEvent @winEventParams 2>$null)
        if ($rawBatch.Count -gt 0) {
            $accessibleLogs.Add($logN)
            foreach ($ev in $rawBatch) {
                # Deduplicar por EventRecordId (puede ser null en Security, usar Id+TimeCreated)
                $dedupKey = if ($ev.RecordId) { [long]$ev.RecordId } else { [long]0 }
                $isNew = if ($dedupKey -ne 0) { $seenRecordIds.Add($dedupKey) } else { $true }
                if ($isNew) { $allRawEvents.Add($ev) }
            }
            Show-StatusMessage -Message "Read $($rawBatch.Count) events from '$logN'." -Type 'Info'
        } else {
            Show-StatusMessage -Message "No events in '$logN' for the specified range." -Type 'Info'
        }
    }
    catch {
        Write-Verbose "Error reading $logN : $_"
    }
}

if ($allRawEvents.Count -eq 0) {
    Show-StatusMessage -Message 'No events found in any AD FS log for the specified criteria.' -Type 'Warning'
    exit 0
}

$rawEvents = $allRawEvents.ToArray()

Show-StatusMessage -Message "Total: $($rawEvents.Count) raw events from $($accessibleLogs.Count) log(s)." -Type 'Info'

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
# Modo ActivityId: mostrar flujo completo de autenticacion
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
        Write-Host "  $('TIME'.PadRight(10))  $('  ID'.PadRight(6))  $('EVENT'.PadRight(28))$('USER'.PadRight(35))CLIENT IP" -ForegroundColor DarkCyan
        Write-Host "  $('-' * 8)  $('-' * 4)  $('-' * 26)$('-' * 33)$('-' * 15)" -ForegroundColor DarkGray
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
