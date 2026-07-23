#Requires -Version 5.1
<#
.SYNOPSIS
    Parser de eventos crudos del Event Log de AD FS.
.DESCRIPTION
    Transforma objetos EventLogRecord en PSCustomObject con campos nombrados.
    Las regex están precompiladas al importar el módulo para minimizar overhead.
    Este módulo NO filtra: solo transforma. La lógica de filtrado vive en Filters.psm1.
#>

Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------------
# Regex precompiladas (compiladas una sola vez al importar el módulo)
# ---------------------------------------------------------------------------
$script:RxOptions = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                    [System.Text.RegularExpressions.RegexOptions]::Multiline

$script:Patterns = @{
    # Usuario / UPN — varios formatos que AD FS usa en distintos eventos
    User         = [regex]::new('(?:^|\s)(?:User(?:\s+Name)?|UPN|Account\s+Name|Identity)\s*[:\-]\s*([^\r\n\t]+)', $script:RxOptions)
    Upn          = [regex]::new('(?:UPN|User\s+Principal\s+Name)\s*[:\-]\s*([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', $script:RxOptions)
    # IP de cliente
    ClientIp     = [regex]::new('(?:Client\s*(?:IP|Address)|Source\s*IP|IP\s*Address|ip)\s*[:\-]\s*["]?(\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?)["]?', $script:RxOptions)
    # Activity ID y Correlation ID (GUIDs)
    ActivityId   = [regex]::new('Activity\s*ID\s*[:\-]\s*\{?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}?', $script:RxOptions)
    CorrelationId= [regex]::new('Correlation\s*ID\s*[:\-]\s*\{?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}?', $script:RxOptions)
    # Endpoint / Request URI
    Endpoint     = [regex]::new('(?:Endpoint|Request\s*Path)\s*[:\-]\s*([/][^\r\n\s]+)', $script:RxOptions)
    RequestUri   = [regex]::new('(?:Request\s*URI|Request\s*URL|Url)\s*[:\-]\s*(https?://[^\r\n\s]+|/[^\r\n\s]+)', $script:RxOptions)
    # Relying Party
    RelyingParty = [regex]::new('(?:Relying\s*Party|Resource|Application|Client\s*Application)\s*[:\-]\s*([^\r\n]+)', $script:RxOptions)
    # Claims Provider
    ClaimsProvider = [regex]::new('(?:Claims?\s*Provider|Identity\s*Provider|IdP)\s*[:\-]\s*([^\r\n]+)', $script:RxOptions)
    # Error / detalle de fallo
    ErrorDetail  = [regex]::new('(?:Error|Exception|Failure\s*Reason|Reason)\s*[:\-]\s*([^\r\n]+)', $script:RxOptions)
    # Protocolo inferido desde endpoint
    ProtocolWsTrust   = [regex]::new('/adfs/services/trust/', $script:RxOptions)
    ProtocolWsFed     = [regex]::new('/adfs/ls/', $script:RxOptions)
    ProtocolOAuth     = [regex]::new('/adfs/oauth2/', $script:RxOptions)
    ProtocolOidc      = [regex]::new('/adfs/userinfo|/adfs/.well-known/openid-configuration', $script:RxOptions)
    ProtocolSaml      = [regex]::new('/adfs/saml/', $script:RxOptions)
    ProtocolCertAuth  = [regex]::new('/adfs/portal/certificate|certauth', $script:RxOptions)
    # Instance ID del servidor
    ServerInstance = [regex]::new('(?:Instance|Server\s*Name|Computer\s*Name)\s*[:\-]\s*([^\r\n]+)', $script:RxOptions)
}

# ---------------------------------------------------------------------------
# Función interna: extraer primer grupo capturado o $null
# ---------------------------------------------------------------------------
function script:Invoke-RegexExtract {
    param(
        [string]$Text,
        [regex]$Pattern
    )
    $m = $Pattern.Match($Text)
    if ($m.Success -and $m.Groups.Count -gt 1) {
        return $m.Groups[1].Value.Trim()
    }
    return $null
}

# ---------------------------------------------------------------------------
# Función interna: inferir protocolo desde endpoint o event dict
# ---------------------------------------------------------------------------
function script:Resolve-Protocol {
    param(
        [string]$Endpoint,
        [string]$RequestUri,
        [string]$DictProtocol
    )

    $combined = "$Endpoint $RequestUri"

    if ($script:Patterns.ProtocolOidc.IsMatch($combined))    { return 'OIDC'     }
    if ($script:Patterns.ProtocolOAuth.IsMatch($combined))   { return 'OAuth'    }
    if ($script:Patterns.ProtocolSaml.IsMatch($combined))    { return 'SAML'     }
    if ($script:Patterns.ProtocolWsTrust.IsMatch($combined)) { return 'WS-Trust' }
    if ($script:Patterns.ProtocolWsFed.IsMatch($combined))   { return 'WS-Fed'   }
    if ($script:Patterns.ProtocolCertAuth.IsMatch($combined)){ return 'CertAuth' }
    if (-not [string]::IsNullOrEmpty($DictProtocol))         { return $DictProtocol }
    return 'Unknown'
}

# ---------------------------------------------------------------------------
# Función pública: convertir EventLogRecord a PSCustomObject normalizado
# ---------------------------------------------------------------------------
function ConvertTo-AdfsEvent {
    <#
    .SYNOPSIS
        Convierte un objeto EventLogRecord crudo en un objeto AD FS normalizado.
    .PARAMETER RawEvent
        Objeto devuelto por Get-WinEvent.
    .OUTPUTS
        PSCustomObject con todos los campos extraídos del mensaje del evento.
    .EXAMPLE
        Get-WinEvent -LogName 'AD FS/Admin' -MaxEvents 1 | ConvertTo-AdfsEvent
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$RawEvent
    )

    process {
        # Resolver metadata del diccionario
        $meta = Get-EventMeta -EventId $RawEvent.Id

        $eventName   = if ($meta) { $meta.Name }        else { "EVENT_$($RawEvent.Id)" }
        $severity    = if ($meta) { $meta.Severity }    else { _Map-NativeLevel $RawEvent.LevelDisplayName }
        $dictProto   = if ($meta) { $meta.Protocol }    else { 'Unknown' }
        $description = if ($meta) { $meta.Description } else { $null }

        # Obtener mensaje (puede fallar si el proveedor no está instalado)
        $rawMsg = ''
        try   { $rawMsg = $RawEvent.FormatDescription() }
        catch { $rawMsg = $RawEvent.Message }
        if ([string]::IsNullOrEmpty($rawMsg)) { $rawMsg = '' }

        # Extracción de campos
        $user     = script:Invoke-RegexExtract -Text $rawMsg -Pattern $script:Patterns.Upn
        if (-not $user) {
            $user = script:Invoke-RegexExtract -Text $rawMsg -Pattern $script:Patterns.User
        }
        $clientIp      = script:Invoke-RegexExtract -Text $rawMsg -Pattern $script:Patterns.ClientIp
        $activityId    = script:Invoke-RegexExtract -Text $rawMsg -Pattern $script:Patterns.ActivityId
        $correlationId = script:Invoke-RegexExtract -Text $rawMsg -Pattern $script:Patterns.CorrelationId
        $endpoint      = script:Invoke-RegexExtract -Text $rawMsg -Pattern $script:Patterns.Endpoint
        $requestUri    = script:Invoke-RegexExtract -Text $rawMsg -Pattern $script:Patterns.RequestUri
        $relyingParty  = script:Invoke-RegexExtract -Text $rawMsg -Pattern $script:Patterns.RelyingParty
        $claimsProvider= script:Invoke-RegexExtract -Text $rawMsg -Pattern $script:Patterns.ClaimsProvider
        $errorDetail   = script:Invoke-RegexExtract -Text $rawMsg -Pattern $script:Patterns.ErrorDetail

        # Si el endpoint está en RequestUri, usarlo como fallback
        if (-not $endpoint -and $requestUri) {
            $uri = [System.Uri]::new($requestUri, [System.UriKind]::RelativeOrAbsolute)
            if ($uri.IsAbsoluteUri) { $endpoint = $uri.AbsolutePath }
            else { $endpoint = $requestUri }
        }

        $protocol = script:Resolve-Protocol -Endpoint $endpoint -RequestUri $requestUri -DictProtocol $dictProto

        # Extraer ActivityId también del campo XML si está disponible
        if (-not $activityId) {
            try {
                $xmlDoc = [xml]$RawEvent.ToXml()
                $nsm = New-Object System.Xml.XmlNamespaceManager($xmlDoc.NameTable)
                $nsm.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
                $correlationNode = $xmlDoc.SelectSingleNode('//e:Correlation', $nsm)
                if ($correlationNode) {
                    $activityId = $correlationNode.GetAttribute('ActivityID')
                    if ([string]::IsNullOrEmpty($activityId)) { $activityId = $null }
                    else { $activityId = $activityId.Trim('{}') }
                }
            }
            catch { }
        }

        [PSCustomObject]@{
            EventId        = [int]$RawEvent.Id
            EventName      = $eventName
            TimeCreated    = $RawEvent.TimeCreated
            Severity       = $severity
            Description    = $description
            Protocol       = $protocol
            User           = $user
            ClientIp       = $clientIp
            ActivityId     = $activityId
            CorrelationId  = $correlationId
            Endpoint       = $endpoint
            RequestUri     = $requestUri
            RelyingParty   = $relyingParty
            ClaimsProvider = $claimsProvider
            ErrorDetail    = $errorDetail
            MachineName    = $RawEvent.MachineName
            LogName        = $RawEvent.LogName
            RawMessage     = $rawMsg
        }
    }
}

# ---------------------------------------------------------------------------
# Función interna: mapear LevelDisplayName nativo a severidad canónica
# ---------------------------------------------------------------------------
function script:_Map-NativeLevel {
    param([string]$Level)
    switch -Wildcard ($Level) {
        '*Error*'       { return 'Error'   }
        '*Warning*'     { return 'Warning' }
        '*Information*' { return 'Info'    }
        '*Critical*'    { return 'Error'   }
        '*Verbose*'     { return 'Info'    }
        default         { return 'Info'    }
    }
}

Export-ModuleMember -Function ConvertTo-AdfsEvent
