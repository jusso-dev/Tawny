function Install-TawnyAgent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackendUrl,

        [Parameter(Mandatory = $true)]
        [string]$EnrollmentToken,

        [string]$DownloadUrl,
        [string]$Sha256,
        [string]$InstallDir = "$env:ProgramFiles\Tawny",
        [string]$ConfigPath = "$env:ProgramData\Tawny\config.toml",
        [string]$ServiceName = "TawnyAgent",
        [switch]$DryRun
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"

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

    function Get-LatestAsset([string]$Pattern) {
        $release = Invoke-RestMethod -Headers @{ "User-Agent" = "tawny-install" } `
            -Uri "https://api.github.com/repos/jusso-dev/Tawny/releases/latest"
        $asset = $release.assets | Where-Object { $_.name -match $Pattern } | Select-Object -First 1
        if (-not $asset) {
            throw "No release asset matched '$Pattern'. Pass -DownloadUrl explicitly."
        }
        return $asset
    }

    if (-not $DownloadUrl -and -not $DryRun) {
        $asset = Get-LatestAsset "windows-x64\.exe$"
        $DownloadUrl = $asset.browser_download_url
        if (-not $Sha256) {
            $shaAsset = Get-LatestAsset "windows-x64\.sha256$"
            $Sha256 = ((Invoke-WebRequest -UseBasicParsing -Uri $shaAsset.browser_download_url).Content -split "\s+")[0]
        }
    }

    $binaryPath = Join-Path $InstallDir "tawny-agent.exe"
    $configDir = Split-Path -Parent $ConfigPath

    Invoke-Step "Creating $InstallDir and $configDir" {
        New-Item -ItemType Directory -Force -Path $InstallDir, $configDir | Out-Null
    }

    Invoke-Step "Downloading Tawny agent from $DownloadUrl" {
        Invoke-WebRequest -UseBasicParsing -Uri $DownloadUrl -OutFile $binaryPath
    }

    if ($Sha256) {
        Invoke-Step "Verifying SHA-256 $Sha256" {
            $actual = (Get-FileHash -Algorithm SHA256 -Path $binaryPath).Hash.ToLowerInvariant()
            if ($actual -ne $Sha256.ToLowerInvariant()) {
                throw "SHA-256 mismatch. Expected $Sha256, got $actual."
            }
        }
    } else {
        Write-Step "Skipping SHA-256 verification because no hash was provided."
    }

    $config = @"
[backend]
url = "$BackendUrl"
enrollment_token = "$EnrollmentToken"

[collection]
heartbeat_interval_seconds = 60
process_interval_seconds = 30
network_interval_seconds = 30
users_interval_seconds = 300
system_interval_seconds = 3600
fim_interval_seconds = 300
max_in_memory_events = 1000
spill_path = "$ConfigPath.spool"
fim_paths = []
"@

    Invoke-Step "Writing $ConfigPath" {
        Set-Content -Path $ConfigPath -Value $config -Encoding UTF8
    }

    Invoke-Step "Registering Windows service $ServiceName" {
        $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($existing) {
            Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
            sc.exe config $ServiceName binPath= "`"$binaryPath`"" start= auto | Out-Null
        } else {
            New-Service -Name $ServiceName `
                -DisplayName "Tawny EDR Agent" `
                -BinaryPathName "`"$binaryPath`"" `
                -StartupType Automatic | Out-Null
        }
        Start-Service -Name $ServiceName
    }
}
