#Requires -Version 5.1
<#
.SYNOPSIS
    Parser de eventos crudos del Event Log de AD FS.
.DESCRIPTION
    Transforma objetos EventLogRecord en PSCustomObject con campos nombrados.
    Estrategia de extraccion (en orden de prioridad):
      1. XML EventData (campos nombrados, fuente mas fiable)
      2. Nodo System/Correlation del XML (ActivityId)
      3. Regex sobre el texto formateado del mensaje (fallback)
    Este modulo NO filtra: solo transforma. La logica de filtrado vive en Filters.psm1.
#>

Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------------
# Namespace XML de eventos de Windows
# ---------------------------------------------------------------------------
$script:EventXmlNs = 'http://schemas.microsoft.com/win/2004/08/events/event'

# ---------------------------------------------------------------------------
# Mapeo de nombres de campo en EventData XML a nuestros campos normalizados.
# AD FS usa distintos nombres segun la version y el tipo de evento.
# ---------------------------------------------------------------------------
$script:XmlFieldMap = @{
    # Campo User -- multiples nombres posibles en EventData
    User = @(
        'IdentityName',        # evento 307, 364 en ADFS 3.x/4.x (WS2016/2019)
        'CallerIdentity',      # algunos eventos de auditoria
        'UserName',
        'UserId',
        'AccountName',
        'upn',
        'ObjectName'
    )
    # IP de cliente
    ClientIp = @(
        'CallerIpAddress',     # nombre mas comun en ADFS WS2019
        'IpAddress',
        'ClientIpAddress',
        'SourceIp',
        'NetworkIpAddress'
    )
    # Activity ID
    ActivityId = @(
        'ActivityId',
        'activity_id',
        'CorrelationActivityId'
    )
    # Correlation ID
    CorrelationId = @(
        'CorrelationId',
        'correlation_id'
    )
    # Endpoint
    Endpoint = @(
        'Endpoint',
        'EndpointPath',
        'RequestPath'
    )
    # Request URI
    RequestUri = @(
        'RequestUri',
        'RequestUrl',
        'Uri'
    )
    # Relying Party
    RelyingParty = @(
        'RelyingPartyTrustIdentifier',
        'RelyingParty',
        'ResourceUri',
        'Audience',
        'ClientId'
    )
    # Claims Provider
    ClaimsProvider = @(
        'ClaimsProviderName',
        'ClaimsProvider',
        'IdentityProviderName',
        'IdpName'
    )
    # Detalle de error
    ErrorDetail = @(
        'ErrorMessage',
        'ExceptionMessage',
        'FailureReason',
        'ErrorCode',
        'Description'
    )
    # Protocolo
    Protocol = @(
        'ProtocolName',
        'Protocol'
    )
}

# ---------------------------------------------------------------------------
# Regex precompiladas como fallback cuando el XML no tiene el campo
# ---------------------------------------------------------------------------
$script:RxOptions = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                    [System.Text.RegularExpressions.RegexOptions]::Multiline

$script:Patterns = @{
    # UPN con formato email (mas especifico, se intenta primero)
    Upn          = [regex]::new('([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', $script:RxOptions)
    # Usuario generico con varios formatos de etiqueta
    User         = [regex]::new('(?:User(?:\s+Name)?|UPN|Account\s+Name|Identity|Caller\s+Identity|Target\s+Identity|Identity\s+Name)\s*[:\-]\s*([^\r\n\t]+)', $script:RxOptions)
    # IP de cliente
    ClientIp     = [regex]::new('(?:Client\s*(?:IP|Address)|Source\s*IP|IP\s*Address|Caller\s*IP|ip\s*address)\s*[:\-]\s*["]?(\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?)["]?', $script:RxOptions)
    # GUIDs para Activity/Correlation
    ActivityId   = [regex]::new('(?:Activity\s*ID|ActivityId)\s*[:\-]\s*\{?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}?', $script:RxOptions)
    CorrelationId= [regex]::new('(?:Correlation\s*ID|CorrelationId)\s*[:\-]\s*\{?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}?', $script:RxOptions)
    # Endpoint y URI
    Endpoint     = [regex]::new('(?:Endpoint|Request\s*Path)\s*[:\-]\s*([/][^\r\n\s]+)', $script:RxOptions)
    RequestUri   = [regex]::new('(?:Request\s*(?:URI|URL)|Url)\s*[:\-]\s*(https?://[^\r\n\s]+|/[^\r\n\s]+)', $script:RxOptions)
    # Relying Party
    RelyingParty = [regex]::new('(?:Relying\s*Party(?:\s*Trust\s*Identifier)?|Resource|Audience|Client\s*Application)\s*[:\-]\s*([^\r\n]+)', $script:RxOptions)
    # Claims Provider
    ClaimsProvider = [regex]::new('(?:Claims?\s*Provider(?:\s*Name)?|Identity\s*Provider(?:\s*Name)?|IdP)\s*[:\-]\s*([^\r\n]+)', $script:RxOptions)
    # Error detail
    ErrorDetail  = [regex]::new('(?:Error(?:\s*Message)?|Exception(?:\s*Message)?|Failure\s*Reason|Error\s*Code)\s*[:\-]\s*([^\r\n]+)', $script:RxOptions)
    # Deteccion de protocolo por endpoint
    ProtocolWsTrust  = [regex]::new('/adfs/services/trust/', $script:RxOptions)
    ProtocolWsFed    = [regex]::new('/adfs/ls/', $script:RxOptions)
    ProtocolOAuth    = [regex]::new('/adfs/oauth2/', $script:RxOptions)
    ProtocolOidc     = [regex]::new('/adfs/userinfo|openid-configuration', $script:RxOptions)
    ProtocolSaml     = [regex]::new('/adfs/saml/', $script:RxOptions)
    ProtocolCertAuth = [regex]::new('/adfs/portal/certificate|certauth', $script:RxOptions)
    # Deteccion de protocolo por nombre (en texto o XML)
    ProtocolNameWsTrust = [regex]::new('^wstrust', $script:RxOptions)
    ProtocolNameWsFed   = [regex]::new('^wsfed|^passive', $script:RxOptions)
    ProtocolNameOAuth   = [regex]::new('^oauth|^oidc', $script:RxOptions)
    ProtocolNameSaml    = [regex]::new('^saml', $script:RxOptions)
}

# ---------------------------------------------------------------------------
# Funcion interna: extraer campos del XML EventData del evento
# Devuelve hashtable con todos los Data[@Name] encontrados
# ---------------------------------------------------------------------------
function script:Get-XmlEventData {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$Event)

    $result = @{}
    try {
        $xml = [xml]$Event.ToXml()
        $ns  = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace('e', $script:EventXmlNs)

        # Extraer todos los nodos Data con atributo Name
        $nodes = $xml.SelectNodes('//e:EventData/e:Data', $ns)
        if ($nodes) {
            foreach ($node in $nodes) {
                $name = $node.GetAttribute('Name')
                if (-not [string]::IsNullOrEmpty($name)) {
                    $result[$name] = $node.InnerText
                }
            }
        }

        # Tambien extraer Data sin nombre (posicional) como Data_0, Data_1...
        $unnamed = $xml.SelectNodes('//e:EventData/e:Data[not(@Name)]', $ns)
        if ($unnamed) {
            $i = 0
            foreach ($node in $unnamed) {
                $result["Data_$i"] = $node.InnerText
                $i++
            }
        }

        # Extraer ActivityID del nodo System/Correlation
        $corrNode = $xml.SelectSingleNode('//e:System/e:Correlation', $ns)
        if ($corrNode) {
            $aid = $corrNode.GetAttribute('ActivityID')
            if (-not [string]::IsNullOrEmpty($aid)) {
                $result['_CorrelationActivityID'] = $aid.Trim('{}')
            }
        }
    }
    catch { }

    return $result
}

# ---------------------------------------------------------------------------
# Funcion interna: buscar un valor en el hashtable XML usando una lista de nombres
# ---------------------------------------------------------------------------
function script:Find-XmlField {
    param(
        [hashtable]$XmlData,
        [string[]]$FieldNames
    )
    foreach ($name in $FieldNames) {
        if ($XmlData.ContainsKey($name) -and -not [string]::IsNullOrEmpty($XmlData[$name])) {
            return $XmlData[$name].Trim()
        }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Funcion interna: extraer primer grupo capturado con regex o $null
# ---------------------------------------------------------------------------
function script:Invoke-RegexExtract {
    param(
        [string]$Text,
        [regex]$Pattern
    )
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $m = $Pattern.Match($Text)
    if ($m.Success -and $m.Groups.Count -gt 1) {
        return $m.Groups[1].Value.Trim()
    }
    return $null
}

# ---------------------------------------------------------------------------
# Funcion interna: inferir protocolo
# ---------------------------------------------------------------------------
function script:Resolve-Protocol {
    param(
        [string]$Endpoint,
        [string]$RequestUri,
        [string]$ProtocolName,
        [string]$DictProtocol
    )

    # Primero intentar desde el nombre de protocolo explícito (campo XML ProtocolName)
    if (-not [string]::IsNullOrEmpty($ProtocolName)) {
        if ($script:Patterns.ProtocolNameOAuth.IsMatch($ProtocolName))   { return 'OAuth'    }
        if ($script:Patterns.ProtocolNameSaml.IsMatch($ProtocolName))    { return 'SAML'     }
        if ($script:Patterns.ProtocolNameWsFed.IsMatch($ProtocolName))   { return 'WS-Fed'   }
        if ($script:Patterns.ProtocolNameWsTrust.IsMatch($ProtocolName)) { return 'WS-Trust' }
    }

    # Luego por endpoint / URI
    $combined = "$Endpoint $RequestUri"
    if (-not [string]::IsNullOrEmpty($combined.Trim())) {
        if ($script:Patterns.ProtocolOidc.IsMatch($combined))    { return 'OIDC'     }
        if ($script:Patterns.ProtocolOAuth.IsMatch($combined))   { return 'OAuth'    }
        if ($script:Patterns.ProtocolSaml.IsMatch($combined))    { return 'SAML'     }
        if ($script:Patterns.ProtocolWsTrust.IsMatch($combined)) { return 'WS-Trust' }
        if ($script:Patterns.ProtocolWsFed.IsMatch($combined))   { return 'WS-Fed'   }
        if ($script:Patterns.ProtocolCertAuth.IsMatch($combined)){ return 'CertAuth' }
    }

    # Fallback al protocolo del diccionario de eventos
    if (-not [string]::IsNullOrEmpty($DictProtocol)) { return $DictProtocol }
    return 'Unknown'
}

# ---------------------------------------------------------------------------
# Funcion publica: convertir EventLogRecord a PSCustomObject normalizado
# ---------------------------------------------------------------------------
function ConvertTo-AdfsEvent {
    <#
    .SYNOPSIS
        Convierte un objeto EventLogRecord crudo en un objeto AD FS normalizado.
    .DESCRIPTION
        Extrae campos mediante XML EventData (prioritario) y regex sobre el
        texto del mensaje (fallback). Soporta los formatos de AD FS en
        Windows Server 2016 y 2019.
    .PARAMETER RawEvent
        Objeto devuelto por Get-WinEvent.
    .OUTPUTS
        PSCustomObject con todos los campos extraidos del evento.
    .EXAMPLE
        Get-WinEvent -LogName 'AD FS/Admin' -MaxEvents 10 | ConvertTo-AdfsEvent
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$RawEvent
    )

    process {
        # 1. Resolver metadata del diccionario de eventos
        $meta = Get-EventMeta -EventId $RawEvent.Id

        $eventName   = if ($meta) { $meta.Name }        else { "EVENT_$($RawEvent.Id)" }
        $severity    = if ($meta) { $meta.Severity }    else { script:_Map-NativeLevel $RawEvent.LevelDisplayName }
        $dictProto   = if ($meta) { $meta.Protocol }    else { 'Unknown' }
        $description = if ($meta) { $meta.Description } else { $null }

        # 2. Extraer campos del XML EventData (fuente primaria)
        $xmlData = script:Get-XmlEventData -Event $RawEvent

        $user          = script:Find-XmlField -XmlData $xmlData -FieldNames $script:XmlFieldMap.User
        $clientIp      = script:Find-XmlField -XmlData $xmlData -FieldNames $script:XmlFieldMap.ClientIp
        $activityId    = script:Find-XmlField -XmlData $xmlData -FieldNames $script:XmlFieldMap.ActivityId
        $correlationId = script:Find-XmlField -XmlData $xmlData -FieldNames $script:XmlFieldMap.CorrelationId
        $endpoint      = script:Find-XmlField -XmlData $xmlData -FieldNames $script:XmlFieldMap.Endpoint
        $requestUri    = script:Find-XmlField -XmlData $xmlData -FieldNames $script:XmlFieldMap.RequestUri
        $relyingParty  = script:Find-XmlField -XmlData $xmlData -FieldNames $script:XmlFieldMap.RelyingParty
        $claimsProvider= script:Find-XmlField -XmlData $xmlData -FieldNames $script:XmlFieldMap.ClaimsProvider
        $errorDetail   = script:Find-XmlField -XmlData $xmlData -FieldNames $script:XmlFieldMap.ErrorDetail
        $protocolName  = script:Find-XmlField -XmlData $xmlData -FieldNames $script:XmlFieldMap.Protocol

        # ActivityId desde nodo System/Correlation si no vino en EventData
        if (-not $activityId -and $xmlData.ContainsKey('_CorrelationActivityID')) {
            $activityId = $xmlData['_CorrelationActivityID']
        }

        # 3. Obtener texto formateado del mensaje para el fallback regex
        $rawMsg = ''
        try   { $rawMsg = $RawEvent.FormatDescription() }
        catch { try { $rawMsg = $RawEvent.Message } catch { } }
        if ($null -eq $rawMsg) { $rawMsg = '' }

        # 4. Fallback regex para campos no encontrados en XML
        if (-not $user) {
            # Intentar primero UPN con formato email (mas preciso)
            $user = script:Invoke-RegexExtract -Text $rawMsg -Pattern $script:Patterns.Upn
        }
        if (-not $user) {
            $user = script:Invoke-RegexExtract -Text $rawMsg -Pattern $script:Patterns.User
        }
        if (-not $clientIp) {
            $clientIp = script:Invoke-RegexExtract -Text $rawMsg -Pattern $script:Patterns.ClientIp
        }
        if (-not $activityId) {
            $activityId = script:Invoke-RegexExtract -Text $rawMsg -Pattern $script:Patterns.ActivityId
        }
        if (-not $correlationId) {
            $correlationId = script:Invoke-RegexExtract -Text $rawMsg -Pattern $script:Patterns.CorrelationId
        }
        if (-not $endpoint) {
            $endpoint = script:Invoke-RegexExtract -Text $rawMsg -Pattern $script:Patterns.Endpoint
        }
        if (-not $requestUri) {
            $requestUri = script:Invoke-RegexExtract -Text $rawMsg -Pattern $script:Patterns.RequestUri
        }
        if (-not $relyingParty) {
            $relyingParty = script:Invoke-RegexExtract -Text $rawMsg -Pattern $script:Patterns.RelyingParty
        }
        if (-not $claimsProvider) {
            $claimsProvider = script:Invoke-RegexExtract -Text $rawMsg -Pattern $script:Patterns.ClaimsProvider
        }
        if (-not $errorDetail) {
            $errorDetail = script:Invoke-RegexExtract -Text $rawMsg -Pattern $script:Patterns.ErrorDetail
        }

        # 5. Si endpoint vacio, extraerlo de RequestUri
        if (-not $endpoint -and $requestUri) {
            try {
                $uri = [System.Uri]::new($requestUri, [System.UriKind]::RelativeOrAbsolute)
                $endpoint = if ($uri.IsAbsoluteUri) { $uri.AbsolutePath } else { $requestUri }
            } catch { $endpoint = $requestUri }
        }

        # 6. Limpiar guiones del ActivityId
        if ($activityId) { $activityId = $activityId.Trim('{}') }

        # 7. Resolver protocolo
        $protocol = script:Resolve-Protocol `
            -Endpoint     $endpoint `
            -RequestUri   $requestUri `
            -ProtocolName $protocolName `
            -DictProtocol $dictProto

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
# Funcion interna: mapear LevelDisplayName nativo a severidad canonica
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
