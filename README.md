# ADFS-Inspector

**Herramienta profesional de análisis de logs de AD FS para Windows Server 2019 / PowerShell 5.1**

ADFS-Inspector transforma los eventos crudos del Event Log de Windows procedentes de AD FS en información accionable: flujos de autenticación correlacionados, resúmenes estadísticos, filtrado avanzado y dashboards exportables — sin ninguna dependencia externa.

---

## Características

- **Parseo completo de eventos** — extrae Usuario, UPN, IP de cliente, Activity ID, Correlation ID, Endpoint, Protocolo, Relying Party, Claims Provider y Detalle de error desde los campos `Message` crudos mediante regex precompiladas
- **Diccionario de eventos** — más de 60 Event IDs conocidos de AD FS con nombres legibles, severidad y etiqueta de protocolo (WS-Trust, SAML, OAuth, OIDC, MFA, Device Registration, PRT)
- **Correlación de flujos de autenticación** — agrupa eventos por Activity ID para mostrar el ciclo de vida completo de un intento de autenticación
- **Múltiples vistas** — bloques detallados por evento o timeline compacta de una línea
- **Modo Follow en tiempo real** — como `tail -f`, imprime nuevos eventos sin recargar la pantalla
- **Resumen estadístico** — totales por severidad, usuarios con más fallos, IPs de origen más activas, distribución por protocolo
- **Exportaciones** — CSV, JSON y dashboard HTML autocontenido (sin dependencias de CDN, compatible con IE11)
- **Consultas eficientes** — utiliza `Get-WinEvent -FilterHashtable` para pre-filtrado a nivel ETW; post-filtrado solo cuando es inevitable
- **Arquitectura modular** — 6 módulos independientes, extensibles sin tocar el núcleo

---

## Requisitos

| Requisito | Valor |
|---|---|
| PowerShell | 5.1 (Windows PowerShell) |
| Sistema operativo | Windows Server 2019 / 2016 |
| Permisos | Administrador local (para leer el log `AD FS/Admin`) |
| Módulos externos | Ninguno |

---

## Instalación

```powershell
# 1. Descargar o clonar el repositorio
git clone https://github.com/foxhaunt/ADFS-Inspector.git

# 2. Copiar a la ubicación preferida en el servidor AD FS
#    (o ejecutar directamente desde la ruta de descarga)
Copy-Item -Recurse .\ADFS-Inspector\ C:\Tools\ADFS-Inspector\

# 3. Desbloquear archivos si se descargaron desde internet
Get-ChildItem C:\Tools\ADFS-Inspector -Recurse | Unblock-File

# 4. Permitir ejecución de scripts (si no está ya configurado)
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

No es necesaria ninguna instalación de módulos ni `Import-Module` — el script carga sus propios módulos automáticamente.

---

## Inicio rápido

```powershell
cd C:\Tools\ADFS-Inspector

# Resumen de la actividad de autenticación de hoy
.\ADFS-Inspector.ps1 -Today -Summary

# Todos los errores de la última hora en vista timeline
.\ADFS-Inspector.ps1 -LastMinutes 60 -ErrorsOnly -View Timeline

# Monitoreo en tiempo real
.\ADFS-Inspector.ps1 -Follow -View Timeline
```

---

## Parámetros

### Rango de tiempo

| Parámetro | Tipo | Descripción |
|---|---|---|
| `-Today` | Switch | Eventos desde las 00:00 del día actual |
| `-LastMinutes <int>` | Int | Eventos de los últimos N minutos (1–525600) |

Si no se especifica ninguno, la herramienta lee hasta `-MaxEvents` eventos más recientes.

### Filtros de contenido

| Parámetro | Tipo | Descripción |
|---|---|---|
| `-User <string>` | String | Filtrar por usuario/UPN. Admite wildcards: `*eva*` |
| `-IP <string>` | String | Filtrar por IP de cliente. Wildcards: `192.168.*` |
| `-ActivityId <string>` | String | Mostrar el flujo completo de autenticación para un Activity ID |
| `-EventId <int>` | Int | Filtrar por un Event ID concreto |
| `-Protocol <string>` | String | Filtrar por protocolo: `WS-Trust`, `OAuth`, `SAML`, `MFA`, etc. |
| `-RelyingParty <string>` | String | Filtrar por nombre de Relying Party. Wildcards: `*Office 365*` |

### Filtros de severidad

| Parámetro | Tipo | Descripción |
|---|---|---|
| `-ErrorsOnly` | Switch | Mostrar solo eventos de error |
| `-WarningsOnly` | Switch | Mostrar solo eventos de advertencia |

### Modos de salida

| Parámetro | Tipo | Descripción |
|---|---|---|
| `-View <string>` | String | `Detailed` (por defecto) o `Timeline` |
| `-Summary` | Switch | Mostrar resumen estadístico en lugar de eventos individuales |
| `-Follow` | Switch | Modo de monitoreo en tiempo real (Ctrl+C para detener) |
| `-FollowInterval <int>` | Int | Intervalo de sondeo en segundos para `-Follow` (por defecto: 5) |
| `-ListEvents` | Switch | Mostrar el catálogo completo de Event IDs conocidos y salir |

### Exportación

| Parámetro | Tipo | Descripción |
|---|---|---|
| `-ExportCsv <ruta>` | String | Exportar resultados a CSV |
| `-ExportJson <ruta>` | String | Exportar resultados a JSON |
| `-ExportHtml <ruta>` | String | Exportar resultados como dashboard HTML |

### Avanzado

| Parámetro | Tipo | Descripción |
|---|---|---|
| `-LogName <string>` | String | Log de eventos a leer (por defecto: `AD FS/Admin`) |
| `-MaxEvents <int>` | Int | Máximo de eventos a leer (por defecto: 500, máximo: 100000) |

---

## Ejemplos de uso

### Operaciones diarias

```powershell
# Resumen de las autenticaciones de hoy
.\ADFS-Inspector.ps1 -Today -Summary

# Última hora, todos los eventos, vista detallada
.\ADFS-Inspector.ps1 -LastMinutes 60

# Última hora, vista timeline
.\ADFS-Inspector.ps1 -LastMinutes 60 -View Timeline
```

### Troubleshooting de usuarios

```powershell
# Todos los eventos de un usuario específico hoy
.\ADFS-Inspector.ps1 -Today -User "eva@foxhaunt.es"

# Solo errores de ese usuario
.\ADFS-Inspector.ps1 -Today -User "eva@foxhaunt.es" -ErrorsOnly

# Actividad del usuario con wildcard (UPN parcial)
.\ADFS-Inspector.ps1 -Today -User "*foxhaunt.es" -View Timeline
```

### Investigación de flujos de autenticación

```powershell
# Mostrar el flujo completo de autenticación para un Activity ID
.\ADFS-Inspector.ps1 -ActivityId "3f2c1a4b-88d0-4e3a-b1c2-000000000001"

# Primero localizar el Activity ID desde un fallo
.\ADFS-Inspector.ps1 -LastMinutes 30 -ErrorsOnly -View Timeline
# Luego profundizar en el flujo:
.\ADFS-Inspector.ps1 -ActivityId "<guid-del-paso-anterior>"
```

### Investigación por IP

```powershell
# Todos los eventos desde una IP sospechosa
.\ADFS-Inspector.ps1 -IP "10.0.0.50" -LastMinutes 60

# Errores desde un rango de IPs
.\ADFS-Inspector.ps1 -IP "192.168.1.*" -ErrorsOnly -Today

# IPs más activas (ver sección Top Source IPs del resumen)
.\ADFS-Inspector.ps1 -Today -Summary
```

### Análisis por protocolo

```powershell
# Autenticaciones OAuth del día
.\ADFS-Inspector.ps1 -Today -Protocol "OAuth" -Summary

# Fallos SAML
.\ADFS-Inspector.ps1 -LastMinutes 120 -Protocol "SAML" -ErrorsOnly

# Eventos MFA
.\ADFS-Inspector.ps1 -Today -Protocol "MFA" -View Timeline
```

### Monitoreo en tiempo real

```powershell
# Monitorear todos los eventos según ocurren
.\ADFS-Inspector.ps1 -Follow

# Monitorear solo errores, sondeo cada 10 segundos
.\ADFS-Inspector.ps1 -Follow -ErrorsOnly -FollowInterval 10

# Monitorear intentos de autenticación de un usuario específico
.\ADFS-Inspector.ps1 -Follow -User "admin@foxhaunt.es" -View Timeline
```

### Exportaciones e informes

```powershell
# Informe HTML diario
.\ADFS-Inspector.ps1 -Today -ExportHtml "C:\Informes\adfs-$(Get-Date -f yyyyMMdd).html"

# Exportar todos los fallos a CSV para análisis en Excel
.\ADFS-Inspector.ps1 -Today -ErrorsOnly -ExportCsv "C:\Informes\fallos.csv"

# Exportación JSON para ingesta en SIEM
.\ADFS-Inspector.ps1 -LastMinutes 60 -ExportJson "C:\Informes\adfs-eventos.json"

# Exportar y mostrar al mismo tiempo
.\ADFS-Inspector.ps1 -Today -Summary -ExportHtml "C:\Informes\hoy.html"
```

### Investigación de eventos específicos

```powershell
# Todos los eventos AUTH_FAILURE (EventId 364)
.\ADFS-Inspector.ps1 -Today -EventId 364

# Eventos TOKEN_ISSUED para una Relying Party específica
.\ADFS-Inspector.ps1 -Today -EventId 307 -RelyingParty "*Office 365*"

# Listar todos los Event IDs conocidos
.\ADFS-Inspector.ps1 -ListEvents
```

---

## Escenarios reales de troubleshooting

### Escenario 1: Usuario reporta "no puedo entrar a Office 365"

```powershell
# Paso 1: Comprobar errores recientes del usuario
.\ADFS-Inspector.ps1 -LastMinutes 30 -User "usuario@dominio.com" -ErrorsOnly

# Paso 2: Si se encuentra un fallo, tomar el Activity ID de la salida
# Paso 3: Ver el flujo de autenticación completo
.\ADFS-Inspector.ps1 -ActivityId "GUID-DEL-PASO-2"

# Buscar: AUTH_FAILURE, ACCOUNT_LOCKED, MFA_FAILURE, EXTRANET_LOCKOUT
```

### Escenario 2: Pico de fallos de autenticación — posible fuerza bruta

```powershell
# Paso 1: Obtener resumen para ver la magnitud
.\ADFS-Inspector.ps1 -LastMinutes 60 -Summary

# Paso 2: Ver las IPs con más fallos en la sección "Top Source IPs"
# Paso 3: Investigar la IP sospechosa
.\ADFS-Inspector.ps1 -LastMinutes 60 -IP "ip.sospechosa" -View Timeline

# Buscar: EXTRANET_LOCKOUT (516), AUTH_FAILURE (364) repetidos
```

### Escenario 3: Fallos de MFA — ¿está caído el proveedor?

```powershell
# Comprobar eventos MFA de la última hora
.\ADFS-Inspector.ps1 -LastMinutes 60 -Protocol "MFA" -View Timeline

# Si aparece MFA_PROVIDER_UNAVAILABLE (408), el adaptador no está accesible
# Investigar el flujo de un fallo MFA concreto
.\ADFS-Inspector.ps1 -ActivityId "GUID-DEL-FALLO-MFA"
```

### Escenario 4: Auth híbrida con Office 365 rota tras renovación de certificado

```powershell
# Buscar errores de firma/cifrado de token
.\ADFS-Inspector.ps1 -Today -EventId 308  # TOKEN_SIGN_ERROR
.\ADFS-Inspector.ps1 -Today -EventId 309  # TOKEN_ENCRYPT_ERROR

# Comprobar eventos de sistema relacionados con certificados
.\ADFS-Inspector.ps1 -Today -EventId 106  # CERTIFICATE_EXPIRED
.\ADFS-Inspector.ps1 -Today -EventId 105  # CERTIFICATE_EXPIRING
```

### Escenario 5: Generar informe de seguridad diario

```powershell
# Dashboard HTML completo del día
.\ADFS-Inspector.ps1 -Today `
    -ExportHtml "C:\Informes\adfs-$(Get-Date -f yyyy-MM-dd).html" `
    -Summary
```

---

## Pruebas sin servidor AD FS

Utiliza el script de pruebas incluido para verificar que el parser, el renderer y todos los módulos funcionan correctamente en cualquier máquina Windows con PowerShell 5.1:

```powershell
.\examples\test-parser.ps1
```

Ejecuta 9 tests que cubren: EventDictionary, helpers de severidad, lógica de filtrado, agrupación de timeline, vista detallada, vista timeline, resumen, vista de flujo de autenticación y exportación HTML.

---

## Arquitectura

```
ADFS-Inspector/
│
├── ADFS-Inspector.ps1          # Punto de entrada — solo orquestación
│
├── Modules/
│   ├── EventDictionary.psm1   # Catálogo de Event IDs con nombre/severidad/protocolo
│   ├── Parser.psm1            # EventLogRecord crudo → PSCustomObject normalizado
│   ├── Filters.psm1           # Filtrado por predicados + constructor de FilterHashtable
│   ├── Timeline.psm1          # Agrupación por ActivityId, resúmenes de flujo
│   ├── Renderer.psm1          # Salida Write-Host: detallada, timeline, flujo, resumen
│   └── Utils.psm1             # Exportación CSV/JSON/HTML + modo Follow
│
├── examples/
│   ├── event-307-token-issued.txt  # Mensajes de eventos de ejemplo para testing
│   ├── event-364-auth-failure.txt
│   ├── event-mfa-flow.txt
│   └── test-parser.ps1             # Suite de tests automatizados (sin AD FS)
│
└── README.md
```

### Dependencias entre módulos

```
EventDictionary  ← (sin dependencias)
Parser           ← EventDictionary
Filters          ← (sin dependencias de dominio)
Timeline         ← (sin dependencias de dominio)
Renderer         ← EventDictionary
Utils            ← Parser, Filters, Renderer (a través del llamador)
```

Sin dependencias circulares. Cada módulo puede importarse y probarse de forma aislada.

---

## Extensión para nuevos protocolos

Para añadir soporte a un nuevo protocolo (p. ej., SSO transparente de Azure AD, WS-Federation B2B):

1. **Añadir Event IDs** en `Modules/EventDictionary.psm1` dentro de `$script:EventCatalog`
2. **Añadir patrones regex** en `Modules/Parser.psm1` dentro de `$script:Patterns` si los nuevos eventos tienen formatos de campo únicos
3. **Añadir entradas en FlowStepOrder** en `Modules/Timeline.psm1` si los nuevos eventos participan en flujos de autenticación
4. No es necesario modificar Filters, Renderer, Utils ni el script principal

---

## Referencia de Event IDs de AD FS

| Rango | Área |
|---|---|
| 100–108 | Ciclo de vida del servicio, certificados, base de datos |
| 200–209 | Autenticación primaria (WS-Trust) |
| 299–310 | Emisión de tokens, pipeline de claims |
| 364, 403, 411–413 | Errores de autenticación y token |
| 400–408 | MFA / autenticación adicional |
| 510, 516–517 | WAP / Extranet lockout |
| 600–606 | Registro de dispositivos |
| 700–704 | PRT / SSO transparente |
| 1000–1008 | Eventos de auditoría |
| 1100–1105 | SAML |
| 1200–1208 | OAuth 2.0 / OpenID Connect |

Ejecuta `.\ADFS-Inspector.ps1 -ListEvents` para ver el catálogo completo.

---

## Historial de cambios

### v1.0.0 (2026-07-23)
- Versión inicial
- Protocolos: WS-Trust, WS-Federation, SAML, OAuth 2.0, OIDC, MFA, Device Registration, PRT
- Vistas: Detallada, Timeline, Flujo de autenticación, Resumen
- Exportaciones: CSV, JSON, dashboard HTML
- Modo Follow (tiempo real)
- Más de 60 Event IDs conocidos
- Suite de tests completa (no requiere servidor AD FS)

---

## Licencia

Licencia MIT. Ver archivo LICENSE.
