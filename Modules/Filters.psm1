#Requires -Version 5.1
<#
.SYNOPSIS
    Lógica de filtrado sobre colecciones de eventos AD FS parseados.
.DESCRIPTION
    Aplica predicados combinados (AND lógico) sobre arrays de PSCustomObject
    producidos por Parser.psm1. También construye el FilterHashtable para
    Get-WinEvent para pre-filtrar eficientemente a nivel de ETW.
#>

Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------------
# Función pública: construir FilterHashtable para Get-WinEvent
# ---------------------------------------------------------------------------
function Build-WinEventFilter {
    <#
    .SYNOPSIS
        Construye un FilterHashtable para Get-WinEvent basado en los parámetros CLI.
    .DESCRIPTION
        Solo incluye filtros que el Event Log puede resolver eficientemente:
        LogName, StartTime, EndTime, y opcionalmente Id.
        Los filtros por User/IP/RP se aplican después con Invoke-AdfsFilter.
    .PARAMETER LogName
        Nombre del log de Windows (ej: 'AD FS/Admin').
    .PARAMETER StartTime
        Límite de tiempo inferior.
    .PARAMETER EndTime
        Límite de tiempo superior.
    .PARAMETER EventId
        ID de evento específico (opcional).
    .OUTPUTS
        Hashtable para FilterHashtable de Get-WinEvent.
    .EXAMPLE
        Build-WinEventFilter -LogName 'AD FS/Admin' -StartTime (Get-Date).AddHours(-1)
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$LogName,

        [datetime]$StartTime,
        [datetime]$EndTime,
        [int]$EventId = 0
    )

    $filter = @{ LogName = $LogName }

    if ($PSBoundParameters.ContainsKey('StartTime')) {
        $filter['StartTime'] = $StartTime
    }
    if ($PSBoundParameters.ContainsKey('EndTime')) {
        $filter['EndTime'] = $EndTime
    }
    # Solo añadir Id si se solicitó uno concreto; filtrar por múltiples IDs
    # es menos eficiente que post-filtrar, así que solo para el caso singular
    if ($EventId -gt 0) {
        $filter['Id'] = $EventId
    }

    return $filter
}

# ---------------------------------------------------------------------------
# Función pública: aplicar todos los filtros de post-lectura
# ---------------------------------------------------------------------------
function Invoke-AdfsFilter {
    <#
    .SYNOPSIS
        Aplica filtros sobre eventos AD FS parseados.
    .DESCRIPTION
        Recibe la colección de PSCustomObject del Parser y aplica los predicados
        activos en $FilterParams. Todos los predicados se combinan con AND lógico.
        Los valores string se comparan con -like para soportar wildcards.
    .PARAMETER Events
        Array de objetos producidos por ConvertTo-AdfsEvent.
    .PARAMETER FilterParams
        Hashtable con los parámetros de filtrado activos. Claves reconocidas:
          User       - string, comparación -like sobre campo User
          IP         - string, comparación -like sobre campo ClientIp
          ActivityId - string/guid, comparación -eq sobre campo ActivityId
          EventId    - int, comparación -eq sobre campo EventId
          ErrorsOnly   - bool
          WarningsOnly - bool
          Protocol   - string, comparación -like sobre campo Protocol
          RelyingParty - string, comparación -like sobre campo RelyingParty
    .OUTPUTS
        Array filtrado de PSCustomObject.
    .EXAMPLE
        Invoke-AdfsFilter -Events $events -FilterParams @{ User = '*eva*'; ErrorsOnly = $true }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Events,

        [Parameter(Mandatory)]
        [hashtable]$FilterParams
    )

    # Si no hay eventos, devolver vacío inmediatamente
    if ($Events.Count -eq 0) { return @() }

    # Construir lista de scriptblocks de predicado
    $predicates = [System.Collections.Generic.List[scriptblock]]::new()

    if (-not [string]::IsNullOrEmpty($FilterParams['User'])) {
        $val = $FilterParams['User']
        $predicates.Add({ param($e) $e.User -like "*$val*" }.GetNewClosure())
    }

    if (-not [string]::IsNullOrEmpty($FilterParams['IP'])) {
        $val = $FilterParams['IP']
        $predicates.Add({ param($e) $e.ClientIp -like "*$val*" }.GetNewClosure())
    }

    if (-not [string]::IsNullOrEmpty($FilterParams['ActivityId'])) {
        $val = $FilterParams['ActivityId'].ToString().Trim('{}')
        $predicates.Add({ param($e) $e.ActivityId -eq $val }.GetNewClosure())
    }

    if ($FilterParams['EventId'] -gt 0) {
        $val = $FilterParams['EventId']
        $predicates.Add({ param($e) $e.EventId -eq $val }.GetNewClosure())
    }

    if ($FilterParams['ErrorsOnly'] -eq $true) {
        $predicates.Add({ param($e) $e.Severity -eq 'Error' })
    }

    if ($FilterParams['WarningsOnly'] -eq $true) {
        $predicates.Add({ param($e) $e.Severity -eq 'Warning' })
    }

    if (-not [string]::IsNullOrEmpty($FilterParams['Protocol'])) {
        $val = $FilterParams['Protocol']
        $predicates.Add({ param($e) $e.Protocol -like "*$val*" }.GetNewClosure())
    }

    if (-not [string]::IsNullOrEmpty($FilterParams['RelyingParty'])) {
        $val = $FilterParams['RelyingParty']
        $predicates.Add({ param($e) $e.RelyingParty -like "*$val*" }.GetNewClosure())
    }

    # Sin predicados activos → devolver todo
    if ($predicates.Count -eq 0) { return $Events }

    # Aplicar predicados (AND lógico)
    $result = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($ev in $Events) {
        $pass = $true
        foreach ($pred in $predicates) {
            if (-not (& $pred $ev)) {
                $pass = $false
                break
            }
        }
        if ($pass) { $result.Add($ev) }
    }

    return $result.ToArray()
}

# ---------------------------------------------------------------------------
# Función pública: calcular ventana de tiempo desde parámetros CLI
# ---------------------------------------------------------------------------
function Resolve-TimeRange {
    <#
    .SYNOPSIS
        Calcula StartTime y EndTime a partir de los parámetros -Today y -LastMinutes.
    .PARAMETER Today
        Si se activa, la ventana empieza a las 00:00 del día actual.
    .PARAMETER LastMinutes
        Número de minutos hacia atrás desde ahora.
    .OUTPUTS
        Hashtable con claves StartTime (datetime) y EndTime (datetime).
        StartTime puede ser $null si no se especificó ningún filtro de tiempo.
    .EXAMPLE
        Resolve-TimeRange -LastMinutes 60
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [switch]$Today,
        [int]$LastMinutes = 0
    )

    $now = Get-Date
    $result = @{ StartTime = $null; EndTime = $now }

    if ($Today) {
        $result['StartTime'] = $now.Date  # 00:00:00 del día actual
    }
    elseif ($LastMinutes -gt 0) {
        $result['StartTime'] = $now.AddMinutes(-$LastMinutes)
    }

    return $result
}

Export-ModuleMember -Function Build-WinEventFilter, Invoke-AdfsFilter, Resolve-TimeRange
