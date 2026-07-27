function Install-TawnyAgent {
    [CmdletBinding()]
    param(
        [string]$BackendUrl,

        [string]$EnrollmentToken,

        [string]$DownloadUrl,
        [string]$LocalBinaryPath,
        [string]$Sha256,
        [string]$InstallDir = "$env:ProgramFiles\Tawny",
        [string]$ConfigPath = "$env:ProgramData\Tawny\config.toml",
        [string]$StateDir = "$env:ProgramData\Tawny\state",
        [string]$ServiceName = "TawnyAgent",
        [switch]$AllowInsecureHttp,
        [switch]$SkipAttestation,
        [switch]$DryRun
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    function Write-Step([string]$Message) {
        if ($DryRun) {
            Write-Host "[dry-run] $Message"
        } else {
            Write-Host $Message
        }
    }

    function Invoke-Step([string]$Message, [scriptblock]$Action) {
        Write-Step $Message
        if (-not $DryRun) {
            & $Action
        }
    }

    function Assert-HttpsUrl([string]$Url, [string]$Label, [bool]$AllowHttp) {
        $parsed = [Uri]$Url
        if (-not $parsed.IsAbsoluteUri) {
            throw "$Label must be an absolute URL."
        }
        if ($parsed.Scheme -ne "https" -and -not ($AllowHttp -and $parsed.Scheme -eq "http")) {
            throw "$Label must use HTTPS."
        }
    }

    function ConvertTo-TomlString([string]$Value) {
        if ($Value.Contains("`r") -or $Value.Contains("`n")) {
            throw "Configuration values must be single-line."
        }
        return $Value.Replace("\", "\\").Replace('"', '\"')
    }

    function Assert-SafeDirectory([string]$Path, [string]$Label) {
        $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
        $protectedPaths = @(
            [IO.Path]::GetPathRoot($fullPath).TrimEnd('\'),
            $env:windir.TrimEnd('\'),
            $env:ProgramFiles.TrimEnd('\'),
            $env:ProgramData.TrimEnd('\')
        )
        foreach ($protectedPath in $protectedPaths) {
            if ($fullPath.Equals($protectedPath, [StringComparison]::OrdinalIgnoreCase)) {
                throw "$Label must be a dedicated subdirectory, not '$fullPath'."
            }
        }
    }

    function Get-LatestAsset([string]$Pattern) {
        $release = Invoke-RestMethod `
            -Headers @{ "Accept" = "application/vnd.github+json"; "User-Agent" = "tawny-install" } `
            -Uri "https://api.github.com/repos/jusso-dev/Tawny/releases/latest"
        $asset = $release.assets | Where-Object { $_.name -match $Pattern } | Select-Object -First 1
        if (-not $asset) {
            throw "No release asset matched '$Pattern'."
        }
        return $asset
    }

    $configExists = Test-Path -LiteralPath $ConfigPath -PathType Leaf
    if (-not $configExists -and (-not $BackendUrl -or -not $EnrollmentToken)) {
        throw "-BackendUrl and -EnrollmentToken are required for a new installation."
    }
    if ($BackendUrl) {
        Assert-HttpsUrl $BackendUrl "Backend URL" $AllowInsecureHttp.IsPresent
    }
    if ($DownloadUrl) {
        Assert-HttpsUrl $DownloadUrl "Agent download URL" $false
    }
    if ($DownloadUrl -and $LocalBinaryPath) {
        throw "-DownloadUrl and -LocalBinaryPath are mutually exclusive."
    }
    if ($LocalBinaryPath -and -not (Test-Path -LiteralPath $LocalBinaryPath -PathType Leaf)) {
        throw "Local agent binary does not exist: $LocalBinaryPath"
    }
    $explicitDownloadUrl = [bool]$DownloadUrl
    if ($explicitDownloadUrl -and -not $Sha256) {
        throw "-Sha256 is required with -DownloadUrl."
    }
    if ($LocalBinaryPath -and -not $Sha256) {
        throw "-Sha256 is required with -LocalBinaryPath."
    }
    Assert-SafeDirectory $InstallDir "InstallDir"
    Assert-SafeDirectory (Split-Path -Parent $ConfigPath) "ConfigPath parent"
    Assert-SafeDirectory $StateDir "StateDir"

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $DryRun -and -not $isAdministrator) {
        throw "Run installer from an elevated PowerShell session."
    }

    if (-not $DownloadUrl -and -not $LocalBinaryPath -and -not $DryRun) {
        $asset = Get-LatestAsset "windows-x64\.exe$"
        $DownloadUrl = $asset.browser_download_url
    }
    if (-not $Sha256 -and -not $LocalBinaryPath -and -not $DryRun) {
        $shaAsset = Get-LatestAsset "windows-x64\.sha256$"
        $Sha256 = ((Invoke-WebRequest -UseBasicParsing `
            -Uri $shaAsset.browser_download_url).Content -split "\s+")[0]
    }
    if (-not $DryRun -and $Sha256 -notmatch "^[0-9a-fA-F]{64}$") {
        throw "A valid 64-character SHA-256 is required."
    }

    $binaryPath = Join-Path $InstallDir "tawny-agent.exe"
    $backupPath = Join-Path $InstallDir "tawny-agent.previous.exe"
    $configDir = Split-Path -Parent $ConfigPath
    $candidatePath = Join-Path $InstallDir ".$([Guid]::NewGuid().ToString('N')).download"
    $serviceIdentity = "NT SERVICE\$ServiceName"
    $installState = @{ ReplacedBinary = $false; InstalledBinary = $false }

    Invoke-Step "Creating protected install, config, and state directories" {
        New-Item -ItemType Directory -Force -Path $InstallDir, $configDir, $StateDir | Out-Null
        & icacls.exe $InstallDir /inheritance:r /grant:r `
            "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" | Out-Null
        & icacls.exe $configDir /inheritance:r /grant:r `
            "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" | Out-Null
        & icacls.exe $StateDir /inheritance:r /grant:r `
            "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" | Out-Null
    }

    try {
        Invoke-Step "Staging Tawny agent binary" {
            if ($LocalBinaryPath) {
                Copy-Item -LiteralPath $LocalBinaryPath -Destination $candidatePath
            } else {
                Invoke-WebRequest -UseBasicParsing -Uri $DownloadUrl -OutFile $candidatePath
            }
        }

        Invoke-Step "Verifying mandatory SHA-256 $Sha256" {
            $actual = (Get-FileHash -Algorithm SHA256 -Path $candidatePath).Hash
            if ($actual -ne $Sha256) {
                throw "SHA-256 mismatch. Expected $Sha256, got $actual."
            }
        }

        if (-not $SkipAttestation) {
            Invoke-Step "Verifying GitHub artifact attestation" {
                $gh = Get-Command gh -ErrorAction SilentlyContinue
                if (-not $gh) {
                    throw "GitHub CLI is required for artifact attestation verification. Install gh, or use -SkipAttestation only under an approved exception."
                }
                & $gh.Source attestation verify $candidatePath --repo jusso-dev/Tawny | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    throw "GitHub artifact attestation verification failed."
                }
            }
        }

        if (-not (Test-Path -LiteralPath $ConfigPath)) {
            $escapedBackendUrl = ConvertTo-TomlString $BackendUrl
            $escapedEnrollmentToken = ConvertTo-TomlString $EnrollmentToken
            $escapedSpillPath = ConvertTo-TomlString (Join-Path $StateDir "events.spool")
            $config = @"
[backend]
url = "$escapedBackendUrl"
enrollment_token = "$escapedEnrollmentToken"

[collection]
heartbeat_interval_seconds = 60
process_interval_seconds = 30
process_events_interval_seconds = 5
network_interval_seconds = 30
users_interval_seconds = 300
system_interval_seconds = 3600
fim_interval_seconds = 300
fs_events_interval_seconds = 5
dns_interval_seconds = 30
supply_chain_interval_seconds = 21600
max_in_memory_events = 1000
max_spool_bytes = 268435456
http_timeout_seconds = 30
max_retry_backoff_seconds = 300
spill_path = "$escapedSpillPath"
fim_paths = []
"@
            Invoke-Step "Atomically creating protected config $ConfigPath" {
                $configCandidate = Join-Path $configDir ".$([Guid]::NewGuid().ToString('N')).config"
                [IO.File]::WriteAllText($configCandidate, $config, [Text.UTF8Encoding]::new($false))
                Move-Item -LiteralPath $configCandidate -Destination $ConfigPath
                & icacls.exe $ConfigPath /inheritance:r /grant:r `
                    "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" | Out-Null
            }
        } else {
            Write-Step "Preserving existing config $ConfigPath"
            if (-not $DryRun) {
                $existingConfig = [IO.File]::ReadAllText($ConfigPath)
                $legacySpill = ConvertTo-TomlString "$ConfigPath.spool"
                $newSpill = ConvertTo-TomlString (Join-Path $StateDir "events.spool")
                $migratedConfig = $existingConfig.Replace(
                    "spill_path = `"$legacySpill`"",
                    "spill_path = `"$newSpill`""
                )
                if ($migratedConfig -ne $existingConfig) {
                    $configCandidate = Join-Path $configDir ".$([Guid]::NewGuid().ToString('N')).config"
                    [IO.File]::WriteAllText(
                        $configCandidate,
                        $migratedConfig,
                        [Text.UTF8Encoding]::new($false)
                    )
                    Move-Item -LiteralPath $configCandidate -Destination $ConfigPath -Force
                }
            }
        }

        Invoke-Step "Stopping $ServiceName before atomic binary replacement" {
            Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $backupPath) {
                Remove-Item -LiteralPath $backupPath -Force
            }
            if (Test-Path -LiteralPath $binaryPath) {
                Move-Item -LiteralPath $binaryPath -Destination $backupPath
                $installState.ReplacedBinary = $true
            }
            Move-Item -LiteralPath $candidatePath -Destination $binaryPath
            $installState.InstalledBinary = $true
        }

        Invoke-Step "Registering least-privilege Windows service $ServiceName" {
            $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($existing) {
                & sc.exe config $ServiceName binPath= "`"$binaryPath`"" start= delayed-auto obj= $serviceIdentity | Out-Null
            } else {
                & sc.exe create $ServiceName `
                    binPath= "`"$binaryPath`"" `
                    DisplayName= "Tawny EDR Agent" `
                    start= delayed-auto `
                    obj= $serviceIdentity | Out-Null
            }
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to configure Windows service $ServiceName."
            }
            & sc.exe sidtype $ServiceName restricted | Out-Null
            & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
            & sc.exe failureflag $ServiceName 1 | Out-Null
            $serviceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
            New-ItemProperty -Path $serviceRegistryPath `
                -Name Environment `
                -PropertyType MultiString `
                -Value @(
                    "TAWNY_CONFIG=$ConfigPath",
                    "TAWNY_STATE_PATH=$(Join-Path $StateDir 'state.toml')"
                ) `
                -Force | Out-Null
            & icacls.exe $InstallDir /grant "${serviceIdentity}:(OI)(CI)(RX)" | Out-Null
            & icacls.exe $configDir /grant "${serviceIdentity}:(OI)(CI)(RX)" | Out-Null
            & icacls.exe $ConfigPath /grant "${serviceIdentity}:(R)" | Out-Null
            & icacls.exe $StateDir /grant "${serviceIdentity}:(OI)(CI)(M)" | Out-Null
            Start-Service -Name $ServiceName
            (Get-Service -Name $ServiceName).WaitForStatus(
                [System.ServiceProcess.ServiceControllerStatus]::Running,
                [TimeSpan]::FromSeconds(30)
            )
        }
    } catch {
        if (-not $DryRun) {
            Remove-Item -LiteralPath $candidatePath -Force -ErrorAction SilentlyContinue
            if ($installState.ReplacedBinary -and (Test-Path -LiteralPath $backupPath)) {
                Write-Warning "Install failed; restoring previous agent binary."
                Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath $binaryPath -Force -ErrorAction SilentlyContinue
                Move-Item -LiteralPath $backupPath -Destination $binaryPath
                Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
            } elseif ($installState.InstalledBinary) {
                Remove-Item -LiteralPath $binaryPath -Force -ErrorAction SilentlyContinue
            }
        }
        throw
    }

    Write-Step "Tawny agent installed. Previous binary retained at $backupPath when upgraded."
}
