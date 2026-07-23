#Requires -Version 5.1
<#
.SYNOPSIS
    Catálogo interno de Event IDs de AD FS con semántica, severidad y protocolo.
.DESCRIPTION
    Provee funciones para resolver Event IDs numéricos a nombres legibles,
    niveles de severidad y protocolos asociados. Es el único módulo que debe
    modificarse para añadir soporte a nuevos protocolos o eventos.
#>

Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------------
# Catálogo principal. Cada entrada: Name, Severity, Protocol, Description
# Severity canónica: Success | Error | Warning | Info | System
# ---------------------------------------------------------------------------
$script:EventCatalog = @{

    # ── Ciclo de vida del servicio ──────────────────────────────────────────
    100 = @{ Name = 'SERVICE_START';             Severity = 'Info';    Protocol = 'System';    Description = 'AD FS service started' }
    101 = @{ Name = 'SERVICE_STOP';              Severity = 'Warning'; Protocol = 'System';    Description = 'AD FS service stopped' }
    102 = @{ Name = 'CONFIG_LOADED';             Severity = 'Info';    Protocol = 'System';    Description = 'Configuration loaded successfully' }
    103 = @{ Name = 'CONFIG_ERROR';              Severity = 'Error';   Protocol = 'System';    Description = 'Configuration error' }
    104 = @{ Name = 'CERTIFICATE_LOADED';        Severity = 'Info';    Protocol = 'System';    Description = 'Certificate loaded' }
    105 = @{ Name = 'CERTIFICATE_EXPIRING';      Severity = 'Warning'; Protocol = 'System';    Description = 'Certificate approaching expiration' }
    106 = @{ Name = 'CERTIFICATE_EXPIRED';       Severity = 'Error';   Protocol = 'System';    Description = 'Certificate has expired' }
    108 = @{ Name = 'DB_CONNECTION_ERROR';       Severity = 'Error';   Protocol = 'System';    Description = 'Database connection failed' }

    # ── Autenticación primaria (WS-Trust / WS-Federation) ──────────────────
    200 = @{ Name = 'AUTH_REQUEST';              Severity = 'Info';    Protocol = 'WS-Trust';  Description = 'Authentication request received' }
    201 = @{ Name = 'FORMS_AUTH_START';          Severity = 'Info';    Protocol = 'WS-Fed';    Description = 'Forms authentication initiated' }
    202 = @{ Name = 'WINDOWS_AUTH_START';        Severity = 'Info';    Protocol = 'WS-Trust';  Description = 'Windows integrated authentication initiated' }
    203 = @{ Name = 'CERT_AUTH_START';           Severity = 'Info';    Protocol = 'WS-Trust';  Description = 'Certificate authentication initiated' }
    204 = @{ Name = 'AUTH_SUCCESS';              Severity = 'Success'; Protocol = 'WS-Trust';  Description = 'Primary authentication succeeded' }
    205 = @{ Name = 'AUTH_FAILURE';              Severity = 'Error';   Protocol = 'WS-Trust';  Description = 'Primary authentication failed' }
    206 = @{ Name = 'ACCOUNT_LOCKED';            Severity = 'Error';   Protocol = 'WS-Trust';  Description = 'Account is locked out' }
    207 = @{ Name = 'ACCOUNT_DISABLED';          Severity = 'Error';   Protocol = 'WS-Trust';  Description = 'Account is disabled' }
    208 = @{ Name = 'PASSWORD_EXPIRED';          Severity = 'Warning'; Protocol = 'WS-Trust';  Description = 'User password has expired' }
    209 = @{ Name = 'INVALID_CREDENTIAL';        Severity = 'Error';   Protocol = 'WS-Trust';  Description = 'Invalid username or password' }

    # ── Token issuance ──────────────────────────────────────────────────────
    299 = @{ Name = 'TOKEN_REQUEST';             Severity = 'Info';    Protocol = 'WS-Trust';  Description = 'Security token request received' }
    300 = @{ Name = 'CLAIMS_PIPELINE_START';     Severity = 'Info';    Protocol = 'WS-Trust';  Description = 'Claims pipeline processing started' }
    301 = @{ Name = 'CLAIMS_LOOKUP';             Severity = 'Info';    Protocol = 'WS-Trust';  Description = 'Attribute store lookup executed' }
    302 = @{ Name = 'CLAIMS_TRANSFORM';          Severity = 'Info';    Protocol = 'WS-Trust';  Description = 'Claims transformation applied' }
    303 = @{ Name = 'CLAIMS_ISSUANCE_POLICY';    Severity = 'Info';    Protocol = 'WS-Trust';  Description = 'Issuance policy evaluated' }
    304 = @{ Name = 'CLAIMS_FILTER_APPLIED';     Severity = 'Info';    Protocol = 'WS-Trust';  Description = 'Claims filter applied' }
    305 = @{ Name = 'RP_NOT_FOUND';              Severity = 'Error';   Protocol = 'WS-Trust';  Description = 'Relying party not found' }
    306 = @{ Name = 'RP_DISABLED';               Severity = 'Error';   Protocol = 'WS-Trust';  Description = 'Relying party is disabled' }
    307 = @{ Name = 'TOKEN_ISSUED';              Severity = 'Success'; Protocol = 'WS-Trust';  Description = 'Security token issued successfully' }
    308 = @{ Name = 'TOKEN_SIGN_ERROR';          Severity = 'Error';   Protocol = 'WS-Trust';  Description = 'Token signing failed' }
    309 = @{ Name = 'TOKEN_ENCRYPT_ERROR';       Severity = 'Error';   Protocol = 'WS-Trust';  Description = 'Token encryption failed' }
    310 = @{ Name = 'DELEGATION_TOKEN_ISSUED';   Severity = 'Success'; Protocol = 'WS-Trust';  Description = 'Delegation token issued' }

    # ── Errores de autenticación (rango clásico AD FS 2.x / 3.x) ──────────
    364 = @{ Name = 'AUTH_FAILURE';              Severity = 'Error';   Protocol = 'WS-Trust';  Description = 'Authentication failed — see details' }
    403 = @{ Name = 'FORBIDDEN';                 Severity = 'Error';   Protocol = 'WS-Trust';  Description = 'Access denied by policy' }
    411 = @{ Name = 'TOKEN_VALIDATION_ERROR';    Severity = 'Error';   Protocol = 'WS-Trust';  Description = 'Incoming token validation failed' }
    412 = @{ Name = 'REPLAY_DETECTED';           Severity = 'Error';   Protocol = 'WS-Trust';  Description = 'Token replay detected' }
    413 = @{ Name = 'TOKEN_EXPIRED';             Severity = 'Error';   Protocol = 'WS-Trust';  Description = 'Security token has expired' }
    510 = @{ Name = 'PROXY_AUTH_ERROR';          Severity = 'Error';   Protocol = 'WAP';       Description = 'Web Application Proxy authentication error' }
    516 = @{ Name = 'EXTRANET_LOCKOUT';          Severity = 'Error';   Protocol = 'WAP';       Description = 'Extranet smart lockout triggered' }
    517 = @{ Name = 'EXTRANET_WARN';             Severity = 'Warning'; Protocol = 'WAP';       Description = 'Extranet lockout threshold approaching' }

    # ── MFA / Autenticación adicional ──────────────────────────────────────
    400 = @{ Name = 'MFA_REQUIRED';              Severity = 'Warning'; Protocol = 'MFA';       Description = 'Multi-factor authentication required' }
    401 = @{ Name = 'MFA_CHALLENGE_SENT';        Severity = 'Info';    Protocol = 'MFA';       Description = 'MFA challenge sent to user' }
    402 = @{ Name = 'MFA_SUCCESS';               Severity = 'Success'; Protocol = 'MFA';       Description = 'MFA verification succeeded' }
    404 = @{ Name = 'MFA_FAILURE';               Severity = 'Error';   Protocol = 'MFA';       Description = 'MFA verification failed' }
    405 = @{ Name = 'MFA_TIMEOUT';               Severity = 'Error';   Protocol = 'MFA';       Description = 'MFA challenge timed out' }
    406 = @{ Name = 'MFA_ADAPTER_ERROR';         Severity = 'Error';   Protocol = 'MFA';       Description = 'MFA adapter returned an error' }
    407 = @{ Name = 'MFA_SKIPPED_CLAIM';         Severity = 'Info';    Protocol = 'MFA';       Description = 'MFA skipped based on claim rule' }
    408 = @{ Name = 'MFA_PROVIDER_UNAVAILABLE';  Severity = 'Error';   Protocol = 'MFA';       Description = 'MFA provider is not available' }

    # ── OAuth 2.0 / OpenID Connect ──────────────────────────────────────────
    1200 = @{ Name = 'OAUTH_AUTH_CODE_ISSUED';   Severity = 'Success'; Protocol = 'OAuth';     Description = 'OAuth authorization code issued' }
    1201 = @{ Name = 'OAUTH_TOKEN_ISSUED';       Severity = 'Success'; Protocol = 'OAuth';     Description = 'OAuth access token issued' }
    1202 = @{ Name = 'OAUTH_REFRESH_ISSUED';     Severity = 'Success'; Protocol = 'OAuth';     Description = 'OAuth refresh token issued' }
    1203 = @{ Name = 'OAUTH_TOKEN_ERROR';        Severity = 'Error';   Protocol = 'OAuth';     Description = 'OAuth token request failed' }
    1204 = @{ Name = 'OAUTH_INVALID_CLIENT';     Severity = 'Error';   Protocol = 'OAuth';     Description = 'OAuth client authentication failed' }
    1205 = @{ Name = 'OAUTH_INVALID_SCOPE';      Severity = 'Error';   Protocol = 'OAuth';     Description = 'Requested OAuth scope is invalid' }
    1206 = @{ Name = 'OAUTH_CONSENT_REQUIRED';   Severity = 'Warning'; Protocol = 'OAuth';     Description = 'OAuth user consent required' }
    1207 = @{ Name = 'OIDC_USERINFO_ISSUED';     Severity = 'Success'; Protocol = 'OIDC';      Description = 'OIDC UserInfo response issued' }
    1208 = @{ Name = 'OIDC_ID_TOKEN_ISSUED';     Severity = 'Success'; Protocol = 'OIDC';      Description = 'OIDC ID token issued' }

    # ── SAML ────────────────────────────────────────────────────────────────
    1100 = @{ Name = 'SAML_REQUEST_RECEIVED';    Severity = 'Info';    Protocol = 'SAML';      Description = 'SAML authentication request received' }
    1101 = @{ Name = 'SAML_ASSERTION_ISSUED';    Severity = 'Success'; Protocol = 'SAML';      Description = 'SAML assertion issued' }
    1102 = @{ Name = 'SAML_SIGN_ERROR';          Severity = 'Error';   Protocol = 'SAML';      Description = 'SAML assertion signing failed' }
    1103 = @{ Name = 'SAML_VALIDATION_ERROR';    Severity = 'Error';   Protocol = 'SAML';      Description = 'Incoming SAML assertion validation failed' }
    1104 = @{ Name = 'SAML_LOGOUT_INITIATED';    Severity = 'Info';    Protocol = 'SAML';      Description = 'SAML single logout initiated' }
    1105 = @{ Name = 'SAML_LOGOUT_COMPLETE';     Severity = 'Info';    Protocol = 'SAML';      Description = 'SAML single logout completed' }

    # ── Device Registration / Hybrid Entra ID ───────────────────────────────
    600 = @{ Name = 'DEVICE_REG_START';          Severity = 'Info';    Protocol = 'DeviceReg'; Description = 'Device registration initiated' }
    601 = @{ Name = 'DEVICE_REG_SUCCESS';        Severity = 'Success'; Protocol = 'DeviceReg'; Description = 'Device registered successfully' }
    602 = @{ Name = 'DEVICE_REG_FAILURE';        Severity = 'Error';   Protocol = 'DeviceReg'; Description = 'Device registration failed' }
    603 = @{ Name = 'DEVICE_AUTH_SUCCESS';       Severity = 'Success'; Protocol = 'DeviceReg'; Description = 'Device authentication succeeded' }
    604 = @{ Name = 'DEVICE_AUTH_FAILURE';       Severity = 'Error';   Protocol = 'DeviceReg'; Description = 'Device authentication failed' }
    605 = @{ Name = 'DEVICE_NOT_FOUND';          Severity = 'Error';   Protocol = 'DeviceReg'; Description = 'Device not found in registry' }
    606 = @{ Name = 'DEVICE_COMPLIANCE_FAIL';    Severity = 'Error';   Protocol = 'DeviceReg'; Description = 'Device failed compliance check' }

    # ── PRT / Seamless SSO ──────────────────────────────────────────────────
    700 = @{ Name = 'PRT_ISSUED';                Severity = 'Success'; Protocol = 'PRT';       Description = 'Primary Refresh Token issued' }
    701 = @{ Name = 'PRT_VALIDATION_ERROR';      Severity = 'Error';   Protocol = 'PRT';       Description = 'Primary Refresh Token validation failed' }
    702 = @{ Name = 'PRT_REFRESH';               Severity = 'Info';    Protocol = 'PRT';       Description = 'Primary Refresh Token refreshed' }
    703 = @{ Name = 'SEAMLESS_SSO_SUCCESS';      Severity = 'Success'; Protocol = 'PRT';       Description = 'Seamless SSO authentication succeeded' }
    704 = @{ Name = 'SEAMLESS_SSO_FAILURE';      Severity = 'Error';   Protocol = 'PRT';       Description = 'Seamless SSO authentication failed' }

    # ── Audit (rango alto, comunes en Security log) ─────────────────────────
    1000 = @{ Name = 'AUDIT_SUCCESS';            Severity = 'Success'; Protocol = 'Audit';     Description = 'Successful audit event' }
    1001 = @{ Name = 'AUDIT_FAILURE';            Severity = 'Error';   Protocol = 'Audit';     Description = 'Failed audit event' }
    1007 = @{ Name = 'TOKEN_ISSUED_AUDIT';       Severity = 'Success'; Protocol = 'Audit';     Description = 'Token issued (audit)' }
    1008 = @{ Name = 'AUTH_FAILURE_AUDIT';       Severity = 'Error';   Protocol = 'Audit';     Description = 'Authentication failed (audit)' }
}

# ---------------------------------------------------------------------------
# Función pública: resolver un EventId
# ---------------------------------------------------------------------------
function Get-EventMeta {
    <#
    .SYNOPSIS
        Devuelve los metadatos de un Event ID conocido de AD FS.
    .PARAMETER EventId
        El ID numérico del evento.
    .OUTPUTS
        Hashtable con claves Name, Severity, Protocol, Description.
        $null si el EventId no está en el catálogo.
    .EXAMPLE
        Get-EventMeta -EventId 307
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [int]$EventId
    )

    if ($script:EventCatalog.ContainsKey($EventId)) {
        return $script:EventCatalog[$EventId]
    }
    return $null
}

# ---------------------------------------------------------------------------
# Función pública: listar todos los IDs conocidos
# ---------------------------------------------------------------------------
function Get-AllKnownEventIds {
    <#
    .SYNOPSIS
        Devuelve todos los Event IDs registrados en el catálogo, ordenados.
    .OUTPUTS
        Array de PSCustomObject con EventId, Name, Severity, Protocol, Description.
    .EXAMPLE
        Get-AllKnownEventIds | Format-Table -AutoSize
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()

    $script:EventCatalog.GetEnumerator() |
        Sort-Object Key |
        ForEach-Object {
            [PSCustomObject]@{
                EventId     = $_.Key
                Name        = $_.Value.Name
                Severity    = $_.Value.Severity
                Protocol    = $_.Value.Protocol
                Description = $_.Value.Description
            }
        }
}

# ---------------------------------------------------------------------------
# Función pública: mapear nombre de severidad a color PS 5.1
# ---------------------------------------------------------------------------
function Get-SeverityColor {
    <#
    .SYNOPSIS
        Devuelve el ConsoleColor correspondiente a una severidad canónica.
    .PARAMETER Severity
        Severidad canónica: Success | Error | Warning | Info | System.
    .OUTPUTS
        System.ConsoleColor
    .EXAMPLE
        Get-SeverityColor -Severity 'Error'
    #>
    [CmdletBinding()]
    [OutputType([System.ConsoleColor])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Success','Error','Warning','Info','System')]
        [string]$Severity
    )

    switch ($Severity) {
        'Success' { return [System.ConsoleColor]::Green   }
        'Error'   { return [System.ConsoleColor]::Red     }
        'Warning' { return [System.ConsoleColor]::Yellow  }
        'Info'    { return [System.ConsoleColor]::Cyan    }
        'System'  { return [System.ConsoleColor]::Gray    }
        default   { return [System.ConsoleColor]::White   }
    }
}

# ---------------------------------------------------------------------------
# Función pública: mapear severidad a icono Unicode
# ---------------------------------------------------------------------------
function Get-SeverityIcon {
    <#
    .SYNOPSIS
        Devuelve el icono de consola para una severidad canónica.
    .PARAMETER Severity
        Severidad canónica.
    .OUTPUTS
        String con el icono.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Severity
    )

    switch ($Severity) {
        'Success' { return '[+]' }
        'Error'   { return '[!]' }
        'Warning' { return '[~]' }
        'Info'    { return '[i]' }
        'System'  { return '[*]' }
        default   { return '[ ]' }
    }
}

Export-ModuleMember -Function Get-EventMeta, Get-AllKnownEventIds, Get-SeverityColor, Get-SeverityIcon
