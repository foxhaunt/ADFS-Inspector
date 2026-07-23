#Requires -Version 5.1
<#
.SYNOPSIS
    Agrupación y correlación de eventos AD FS por Activity ID.
.DESCRIPTION
    Agrupa eventos parseados en flujos de autenticación completos, ordenados
    cronológicamente. No contiene lógica de renderizado — ese rol es de Renderer.psm1.
#>

Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------------
# Etiquetas de paso en el flujo de autenticación, inferidas del EventName
# ---------------------------------------------------------------------------
$script:FlowStepOrder = @{
    # Inicio de autenticación
    'AUTH_REQUEST'            = 1
    'TOKEN_REQUEST'           = 1
    'SAML_REQUEST_RECEIVED'   = 1
    'OAUTH_AUTH_CODE_ISSUED'  = 1
    # Autenticación primaria
    'FORMS_AUTH_START'        = 2
    'WINDOWS_AUTH_START'      = 2
    'CERT_AUTH_START'         = 2
    'AUTH_SUCCESS'            = 3
    'AUTH_FAILURE'            = 3
    'ACCOUNT_LOCKED'          = 3
    'ACCOUNT_DISABLED'        = 3
    'INVALID_CREDENTIAL'      = 3
    # MFA
    'MFA_REQUIRED'            = 4
    'MFA_CHALLENGE_SENT'      = 4
    'MFA_SUCCESS'             = 5
    'MFA_FAILURE'             = 5
    'MFA_TIMEOUT'             = 5
    # Claims pipeline
    'CLAIMS_PIPELINE_START'   = 6
    'CLAIMS_LOOKUP'           = 6
    'CLAIMS_TRANSFORM'        = 6
    'CLAIMS_ISSUANCE_POLICY'  = 6
    'CLAIMS_FILTER_APPLIED'   = 6
    # Emisión de token
    'TOKEN_ISSUED'            = 7
    'TOKEN_ISSUED_AUDIT'      = 7
    'DELEGATION_TOKEN_ISSUED' = 7
    'SAML_ASSERTION_ISSUED'   = 7
    'OAUTH_TOKEN_ISSUED'      = 7
    'OIDC_ID_TOKEN_ISSUED'    = 7
    # Errores de token
    'TOKEN_SIGN_ERROR'        = 7
    'TOKEN_ENCRYPT_ERROR'     = 7
    'TOKEN_VALIDATION_ERROR'  = 7
}

# ---------------------------------------------------------------------------
# Función pública: agrupar eventos por ActivityId
# ---------------------------------------------------------------------------
function Get-AuthenticationFlow {
    <#
    .SYNOPSIS
        Agrupa eventos en flujos de autenticación indexados por ActivityId.
    .DESCRIPTION
        Los eventos sin ActivityId se agrupan bajo la clave especial '_UNGROUPED'.
        Dentro de cada grupo, los eventos se ordenan cronológicamente y se
        enriquecen con información de posición relativa en el flujo.
    .PARAMETER Events
        Array de PSCustomObject producido por ConvertTo-AdfsEvent.
    .OUTPUTS
        System.Collections.Specialized.OrderedDictionary indexado por ActivityId.
        Cada valor es un array de PSCustomObject (el flujo).
    .EXAMPLE
        $flows = Get-AuthenticationFlow -Events $parsedEvents
        $flows.Keys | ForEach-Object { "Flow: $_"; $flows[$_] | Format-Table }
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Events
    )

    $groups = [System.Collections.Specialized.OrderedDictionary]::new()

    foreach ($ev in $Events) {
        $key = if (-not [string]::IsNullOrEmpty($ev.ActivityId)) {
            $ev.ActivityId.ToUpper()
        } else {
            '_UNGROUPED'
        }

        if (-not $groups.Contains($key)) {
            $groups[$key] = [System.Collections.Generic.List[PSCustomObject]]::new()
        }
        $groups[$key].Add($ev)
    }

    # Ordenar eventos dentro de cada grupo cronológicamente
    # y convertir a array para facilitar indexado
    $sorted = [System.Collections.Specialized.OrderedDictionary]::new()
    foreach ($key in ($groups.Keys | Sort-Object)) {
        $flowEvents = $groups[$key] | Sort-Object TimeCreated
        $sorted[$key] = @($flowEvents)
    }

    return $sorted
}

# ---------------------------------------------------------------------------
# Función pública: obtener el flujo de un ActivityId concreto
# ---------------------------------------------------------------------------
function Get-SingleFlow {
    <#
    .SYNOPSIS
        Devuelve el flujo de autenticación completo para un ActivityId.
    .PARAMETER Events
        Todos los eventos parseados.
    .PARAMETER ActivityId
        GUID del Activity ID a aislar.
    .OUTPUTS
        Array de PSCustomObject ordenado cronológicamente, o $null si no existe.
    .EXAMPLE
        Get-SingleFlow -Events $events -ActivityId '3f2c1a4b-0000-0000-0000-000000000000'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Events,

        [Parameter(Mandatory)]
        [string]$ActivityId
    )

    $normalized = $ActivityId.Trim('{}').ToUpper()
    $flow = $Events | Where-Object { $_.ActivityId -and $_.ActivityId.ToUpper() -eq $normalized } |
            Sort-Object TimeCreated

    if ($null -eq $flow) { return $null }
    return @($flow)
}

# ---------------------------------------------------------------------------
# Función pública: calcular estadísticas de un flujo
# ---------------------------------------------------------------------------
function Get-FlowSummary {
    <#
    .SYNOPSIS
        Calcula estadísticas de un flujo de autenticación.
    .PARAMETER Flow
        Array de PSCustomObject que componen el flujo (mismo ActivityId).
    .OUTPUTS
        PSCustomObject con: ActivityId, StartTime, EndTime, DurationMs,
        EventCount, Outcome (Success/Failure/Incomplete), User, ClientIp,
        Protocol, RelyingParty.
    .EXAMPLE
        Get-FlowSummary -Flow $flows['3F2C1A4B-...']
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Flow
    )

    if ($Flow.Count -eq 0) {
        return $null
    }

    $start     = ($Flow | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
    $end       = ($Flow | Sort-Object TimeCreated | Select-Object -Last  1).TimeCreated
    $durationMs= [int](($end - $start).TotalMilliseconds)

    # Determinar outcome: si hay algún evento Success de emisión de token → éxito
    $successEvents = @('TOKEN_ISSUED','SAML_ASSERTION_ISSUED','OAUTH_TOKEN_ISSUED',
                       'OIDC_ID_TOKEN_ISSUED','DELEGATION_TOKEN_ISSUED','TOKEN_ISSUED_AUDIT')
    $failureEvents = @('AUTH_FAILURE','TOKEN_VALIDATION_ERROR','TOKEN_SIGN_ERROR',
                       'ACCOUNT_LOCKED','ACCOUNT_DISABLED','MFA_FAILURE')

    $outcome = 'Incomplete'
    if ($Flow | Where-Object { $_.EventName -in $successEvents }) { $outcome = 'Success' }
    elseif ($Flow | Where-Object { $_.EventName -in $failureEvents }) { $outcome = 'Failure' }

    # Tomar los primeros valores no nulos de campos de usuario
    $user      = ($Flow | Where-Object { $_.User }          | Select-Object -First 1).User
    $ip        = ($Flow | Where-Object { $_.ClientIp }      | Select-Object -First 1).ClientIp
    $protocol  = ($Flow | Where-Object { $_.Protocol -and $_.Protocol -ne 'Unknown' } | Select-Object -First 1).Protocol
    $rp        = ($Flow | Where-Object { $_.RelyingParty }  | Select-Object -First 1).RelyingParty
    $actId     = ($Flow | Where-Object { $_.ActivityId }    | Select-Object -First 1).ActivityId

    [PSCustomObject]@{
        ActivityId   = $actId
        StartTime    = $start
        EndTime      = $end
        DurationMs   = $durationMs
        EventCount   = $Flow.Count
        Outcome      = $outcome
        User         = $user
        ClientIp     = $ip
        Protocol     = $protocol
        RelyingParty = $rp
    }
}

# ---------------------------------------------------------------------------
# Función pública: obtener el step label del flujo para un evento
# ---------------------------------------------------------------------------
function Get-FlowStepLabel {
    <#
    .SYNOPSIS
        Devuelve la etiqueta de paso del flujo para un evento dado.
    .PARAMETER Event
        PSCustomObject del evento.
    .OUTPUTS
        String con la etiqueta (p.ej. '[3/7] CLAIMS').
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Event
    )

    $step = $script:FlowStepOrder[$Event.EventName]
    if ($step) { return "[$step/7]" }
    return '[?/7]'
}

Export-ModuleMember -Function Get-AuthenticationFlow, Get-SingleFlow, Get-FlowSummary, Get-FlowStepLabel
