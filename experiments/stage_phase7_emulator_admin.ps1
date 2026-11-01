#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$resultDir = Join-Path $root 'results\phase7'
$stageLog = Join-Path $resultDir 'emulator_stage.log'
$stageError = Join-Path $resultDir 'emulator_stage.err'
$archive = Join-Path $root 'tools\phase7\BeanNetworkTester-v0.8.0-windows-x64.zip'
$expectedHash = 'ED49259A18BBF12424EA79FB31844DA7F87C0D38D3B67677A69A53FBB8F8EEDB'
$destination = Join-Path $env:ProgramFiles 'BeanNetworkTester-Phase7-v0.8.0'

if (-not (Test-Path -LiteralPath $archive)) {
    throw "Verified release archive not found: $archive"
}

try {
    if (-not (Test-Path -LiteralPath $destination)) {
        New-Item -ItemType Directory -Path $destination | Out-Null
    }

    $stagedArchive = Join-Path $destination 'release.zip'
    if (-not (Test-Path -LiteralPath $stagedArchive)) {
        Copy-Item -LiteralPath $archive -Destination $stagedArchive
    }
    $actualHash = (Get-FileHash -LiteralPath $stagedArchive -Algorithm SHA256).Hash
    if ($actualHash -ne $expectedHash) {
        throw "Staged archive hash mismatch: $actualHash"
    }

    $payload = Join-Path $destination 'payload'
    if (-not (Test-Path -LiteralPath $payload)) {
        Expand-Archive -LiteralPath $stagedArchive -DestinationPath $payload
    }
    $package = Join-Path $payload 'BeanNetworkTester'
    $exe = Join-Path $package 'BeanNetworkTester.exe'
    $driver = Get-ChildItem -LiteralPath (Join-Path $package '_internal') `
        -Filter 'WinDivert64.sys' -Recurse -File | Select-Object -First 1 -ExpandProperty FullName

    foreach ($file in @($exe, $driver)) {
        if ([string]::IsNullOrWhiteSpace($file) -or
            -not (Test-Path -LiteralPath $file)) {
            throw "Expected signed executable/driver missing: $file"
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $file
        if ($signature.Status -ne 'Valid') {
            throw "Authenticode verification failed for $file ($($signature.Status))"
        }
    }

    $report = @(
        "Staged verified Bean Network Tester at: $package"
        "Executable signer: $((Get-AuthenticodeSignature -LiteralPath $exe).SignerCertificate.Subject)"
        "Driver signer: $((Get-AuthenticodeSignature -LiteralPath $driver).SignerCertificate.Subject)"
    )
    Set-Content -LiteralPath $stageLog -Value $report -Encoding utf8
    Remove-Item -LiteralPath $stageError -Force -ErrorAction SilentlyContinue
}
catch {
    Set-Content -LiteralPath $stageError -Value $_.ToString() -Encoding utf8
    exit 1
}
