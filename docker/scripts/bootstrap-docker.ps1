[CmdletBinding()]
param(
    [string]$AdminEmail = $(if ($env:BOOTSTRAP_ADMIN_EMAIL) { $env:BOOTSTRAP_ADMIN_EMAIL } else { "admin@example.com" }),
    [string]$AdminPassword = $(if ($env:BOOTSTRAP_ADMIN_PASSWORD) { $env:BOOTSTRAP_ADMIN_PASSWORD } else { "ChangeMe123!" }),
    [string]$AdminName = $(if ($env:BOOTSTRAP_ADMIN_NAME) { $env:BOOTSTRAP_ADMIN_NAME } else { "Tawny Admin" }),
    [string]$ProjectName = $(if ($env:TAWNY_DOCKER_PROJECT) { $env:TAWNY_DOCKER_PROJECT } else { "tawny" }),
    [string]$Platform = $(if ($env:DOCKER_DEFAULT_PLATFORM) { $env:DOCKER_DEFAULT_PLATFORM } else { "" }),
    [switch]$NoBuild,
    [switch]$WithAgent,
    [switch]$WithSyntheticAgent,
    [switch]$WithDockerAgent
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DockerDir = Split-Path -Parent $ScriptDir
$RepoDir = Split-Path -Parent $DockerDir
$EnvFile = Join-Path $DockerDir ".env"
$ComposeFile = Join-Path $DockerDir "docker-compose.yml"
$SecretsDir = Join-Path $DockerDir "secrets"
$JwtKey = Join-Path $SecretsDir "tawny-jwt-key"
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Missing required command: $Name"
    }
}

function New-RandomHex {
    param([int]$ByteCount = 32)

    $bytes = New-Object byte[] $ByteCount
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }

    return -join ($bytes | ForEach-Object { $_.ToString("x2") })
}

function Ensure-EnvValue {
    param(
        [string]$Key,
        [string]$Value
    )

    if (-not (Test-Path $EnvFile)) {
        [System.IO.File]::WriteAllText($EnvFile, "", $Utf8NoBom)
    }

    $existing = Get-Content $EnvFile -ErrorAction SilentlyContinue | Where-Object { $_ -match "^$([regex]::Escape($Key))=" } | Select-Object -First 1
    if ($existing) {
        return
    }

    [System.IO.File]::AppendAllText($EnvFile, "$Key=$Value`n", $Utf8NoBom)
}

function Set-EnvValue {
    param(
        [string]$Key,
        [string]$Value
    )

    if (-not (Test-Path $EnvFile)) {
        [System.IO.File]::WriteAllText($EnvFile, "", $Utf8NoBom)
    }

    $lines = @(Get-Content $EnvFile -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch "^$([regex]::Escape($Key))=" })
    $lines += "$Key=$Value"
    [System.IO.File]::WriteAllLines($EnvFile, [string[]]$lines, $Utf8NoBom)
}

function Get-EnvFileValue {
    param([string]$Key)

    if (-not (Test-Path $EnvFile)) {
        return ""
    }

    $line = Get-Content $EnvFile | Where-Object { $_ -match "^$([regex]::Escape($Key))=" } | Select-Object -Last 1
    if (-not $line) {
        return ""
    }

    return ($line -replace "^$([regex]::Escape($Key))=", "")
}

function Test-PortInUse {
    param([int]$Port)

    $listener = $null
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        return $false
    } catch {
        return $true
    } finally {
        if ($listener) {
            $listener.Stop()
        }
    }
}

function Test-PortOwnedByTawny {
    param([int]$Port)

    $ports = & docker ps --filter "name=^/tawny-" --format "{{.Ports}}" 2>$null
    return [bool]($ports | Select-String -SimpleMatch ":$Port->")
}

function Select-AvailablePort {
    param([int]$Preferred)

    $port = $Preferred
    while ((Test-PortInUse $port) -and -not (Test-PortOwnedByTawny $port)) {
        $port += 1
    }

    return $port
}

function Ensure-PortEnvValue {
    param(
        [string]$Key,
        [int]$Preferred
    )

    $configured = Get-EnvFileValue $Key
    if ($configured) {
        return [int]$configured
    }

    $selected = Select-AvailablePort $Preferred
    Set-EnvValue $Key $selected
    if ($selected -ne $Preferred) {
        Write-Host "Port $Preferred is in use; using $selected for $Key"
    }

    return $selected
}

function Invoke-Compose {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    & docker compose -p $ProjectName --env-file $EnvFile -f $ComposeFile @Args
}

function Invoke-ComposeAgent {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    & docker compose -p $ProjectName --env-file $EnvFile -f $ComposeFile --profile agent @Args
}

function New-AgentEnrollmentToken {
    param([int]$ApiPort)

    $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()
    $userId = "00000000-0000-0000-0000-000000000000"
    $role = "Admin"
    $path = "/api/enrollment-tokens"
    $canonical = "POST`n$path`n$timestamp`n$userId`n$role"
    $secret = Get-EnvFileValue "TAWNY_WEB_HMAC_SECRET"

    $hmac = [System.Security.Cryptography.HMACSHA256]::new([System.Text.Encoding]::UTF8.GetBytes($secret))
    try {
        $signatureBytes = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($canonical))
    } finally {
        $hmac.Dispose()
    }
    $signature = -join ($signatureBytes | ForEach-Object { $_.ToString("x2") })

    $headers = @{
        "X-User-Id" = $userId
        "X-User-Role" = $role
        "X-Timestamp" = $timestamp
        "X-Signature" = $signature
    }
    $body = @{ lifetime_hours = 24 } | ConvertTo-Json -Compress
    $response = Invoke-RestMethod -Uri "http://localhost:$ApiPort$path" -Method Post -Headers $headers -Body $body -ContentType "application/json"
    return $response.token
}

function Wait-ForUrl {
    param(
        [string]$Url,
        [string]$Label,
        [int]$TimeoutSeconds = 180
    )

    Write-Host -NoNewline "Waiting for $Label at $Url"
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while ((Get-Date) -lt $deadline) {
        try {
            Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5 | Out-Null
            Write-Host ""
            return
        } catch {
            Write-Host -NoNewline "."
            Start-Sleep -Seconds 2
        }
    }

    Write-Host ""
    Write-Error "Timed out waiting for $Label. Recent logs:"
    Invoke-Compose logs --tail=80 api web db
    throw "Timed out waiting for $Label"
}

Require-Command docker

& docker compose version | Out-Null

Write-Step "Creating local secrets"
New-Item -ItemType Directory -Path $SecretsDir -Force | Out-Null

if (-not (Test-Path $JwtKey)) {
    if (Get-Command openssl -ErrorAction SilentlyContinue) {
        & openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $JwtKey
    } else {
        & docker run --rm -v "${SecretsDir}:/work" alpine:3.20 sh -c "apk add --no-cache openssl >/dev/null && openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /work/tawny-jwt-key"
    }
    Write-Host "created $JwtKey"
} else {
    Write-Host "kept existing $JwtKey"
}

Ensure-EnvValue "TAWNY_WEB_HMAC_SECRET" (New-RandomHex 32)
Ensure-EnvValue "BETTER_AUTH_SECRET" (New-RandomHex 32)
Ensure-EnvValue "TAWNY_APPLY_MIGRATIONS_ON_STARTUP" "true"
Ensure-EnvValue "MSSQL_SA_PASSWORD" "DevPassw0rd!"

$MssqlPassword = Get-EnvFileValue "MSSQL_SA_PASSWORD"
if (-not $MssqlPassword) {
    throw "MSSQL_SA_PASSWORD is missing from $EnvFile"
}

$MssqlPort = Ensure-PortEnvValue "MSSQL_PORT" 1433
$ApiPort = Ensure-PortEnvValue "TAWNY_API_PORT" 5080
$WebPort = Ensure-PortEnvValue "TAWNY_WEB_PORT" 3000

if ($Platform) {
    $env:DOCKER_DEFAULT_PLATFORM = $Platform
}

Write-Step "Starting Tawny Docker services"
if ($NoBuild) {
    Invoke-Compose up -d
} else {
    Invoke-Compose up -d --build
}

Write-Step "Waiting for SQL Server"
Invoke-Compose up -d --wait db

Write-Step "Running web database migration and admin seed"
$WebDir = Join-Path $RepoDir "web"
$NodeModulesVolume = "${ProjectName}-web-node-modules"
$PnpmStoreVolume = "${ProjectName}-pnpm-store"
$DatabaseUrl = "sqlserver://db:1433;database=Tawny;user=sa;password=${MssqlPassword};encrypt=false;trustServerCertificate=true"

& docker run --rm `
    --network "${ProjectName}_default" `
    -v "${WebDir}:/app" `
    -v "${NodeModulesVolume}:/app/node_modules" `
    -v "${PnpmStoreVolume}:/pnpm/store" `
    -w /app `
    -e "PNPM_HOME=/pnpm" `
    -e "DATABASE_URL=$DatabaseUrl" `
    -e "BOOTSTRAP_ADMIN_EMAIL=$AdminEmail" `
    -e "BOOTSTRAP_ADMIN_PASSWORD=$AdminPassword" `
    -e "BOOTSTRAP_ADMIN_NAME=$AdminName" `
    node:22-bookworm `
    bash -lc "corepack enable && pnpm config set store-dir /pnpm/store && pnpm install --frozen-lockfile && pnpm exec prisma generate && (pnpm db:migrate || (pnpm exec prisma db execute --schema prisma/schema.prisma --file prisma/migrations/20260514005000_better_auth_init/migration.sql && pnpm exec prisma migrate resolve --applied 20260514005000_better_auth_init)) && pnpm seed"

Write-Step "Verifying HTTP endpoints"
Wait-ForUrl "http://localhost:${ApiPort}/api/health" "API health"
Wait-ForUrl "http://localhost:${WebPort}" "web app"

if ($WithAgent -or $WithSyntheticAgent -or $WithDockerAgent) {
    Write-Step "Starting real Linux agent container"
    Set-EnvValue "TAWNY_AGENT_ENROLLMENT_TOKEN" (New-AgentEnrollmentToken -ApiPort $ApiPort)
    Invoke-ComposeAgent up -d --build agent
}

Write-Host ""
Write-Host "Tawny is running."
Write-Host ""
Write-Host "Web:  http://localhost:$WebPort"
Write-Host "API:  http://localhost:$ApiPort"
Write-Host "SQL:  localhost:$MssqlPort"
Write-Host ""
Write-Host "Admin login:"
Write-Host "  Email:    $AdminEmail"
Write-Host "  Password: $AdminPassword"
Write-Host ""
Write-Host "Useful commands:"
Write-Host "  cd `"$DockerDir`"; docker compose -p $ProjectName logs -f api web db"
Write-Host "  cd `"$DockerDir`"; docker compose -p $ProjectName --profile agent logs -f agent"
Write-Host "  cd `"$DockerDir`"; docker compose -p $ProjectName down"
