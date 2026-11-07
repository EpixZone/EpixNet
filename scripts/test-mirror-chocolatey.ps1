# Native folder-source compatibility only. Node signature/export is tested separately.
# Run exclusively on a disposable Windows CI runner, never a user's installation.
$ErrorActionPreference = 'Stop'
$mirror = if ($env:EPIX_MIRROR_BINARY) { $env:EPIX_MIRROR_BINARY } else { Join-Path $PSScriptRoot '..\target\debug\epix-mirror.exe' }
if (-not (Test-Path $mirror)) { throw 'Build epix-mirror before running this test.' }
if ($env:GITHUB_ACTIONS -ne 'true' -or -not $env:RUNNER_TEMP) {
    throw 'Use a disposable GitHub Actions Windows runner.'
}
$originalInstall = $env:ChocolateyInstall
if (-not $originalInstall -or -not (Test-Path (Join-Path $originalInstall 'choco.exe'))) {
    throw 'Expected the runner-provided Chocolatey distribution.'
}
$originalConfig = Join-Path $originalInstall 'config\chocolatey.config'
$configHash = (Get-FileHash $originalConfig -Algorithm SHA256).Hash
$taskRoot = Join-Path $env:RUNNER_TEMP ('epix-mirror-choco-' + [guid]::NewGuid())
$isolatedInstall = Join-Path $taskRoot 'chocolatey'
New-Item -ItemType Directory $isolatedInstall | Out-Null
try {
    # Copy the executable and runtime helpers only. No global package inventory,
    # configuration, extensions, hooks, registry or environment settings are copied.
    Get-ChildItem $originalInstall -File | Copy-Item -Destination $isolatedInstall
    foreach ($name in @('helpers', 'tools', 'redirects')) {
        $source = Join-Path $originalInstall $name
        if (Test-Path $source) { Copy-Item -Recurse $source $isolatedInstall }
    }
    $env:ChocolateyInstall = $isolatedInstall
    $choco = Join-Path $isolatedInstall 'choco.exe'
    $expiry = [DateTimeOffset]::UtcNow.AddHours(12).ToString('o')
    foreach ($version in @('1.0.0', '2.0.0')) {
        $feed = Join-Path $taskRoot "feed-$version"
        New-Item -ItemType Directory $feed | Out-Null
        foreach ($kind in @('helper', 'fixture')) {
            $name = "epix-mirror-folder-$kind"
            $package = Join-Path $taskRoot "$name-$version"
            $tools = Join-Path $package 'tools'
            New-Item -ItemType Directory $tools | Out-Null
            Set-Content -Path (Join-Path $tools 'version.txt') -Value $version
            $dependency = if ($kind -eq 'fixture') {
                "<dependencies><dependency id=`"epix-mirror-folder-helper`" version=`"[$version]`" /></dependencies>"
            } else { '' }
            $nuspec = Join-Path $package "$name.nuspec"
            @"
<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata><id>$name</id><version>$version</version><authors>Fixture</authors>
  <description>Disposable offline mirror fixture</description>$dependency</metadata>
  <files><file src="tools\**" target="tools" /></files>
</package>
"@ | Set-Content $nuspec
            & $choco pack $nuspec --outputdirectory $feed --limit-output
            if ($LASTEXITCODE -ne 0) { throw 'Packing fixture failed.' }
        }
        $snapshot = Join-Path $taskRoot "snapshot-$version"
        & $mirror stage --manager chocolatey --source $feed --output $snapshot --expires $expiry
        if ($LASTEXITCODE -ne 0) { throw 'Staging folder source failed.' }
        & $mirror verify --snapshot $snapshot
        if ($LASTEXITCODE -ne 0) { throw 'Snapshot verification failed.' }
        $operation = if ($version -eq '1.0.0') { 'install' } else { 'upgrade' }
        & $choco $operation epix-mirror-folder-fixture --yes --no-progress --limit-output --source (Join-Path $snapshot 'repo') --cache-location (Join-Path $taskRoot 'cache')
        if ($LASTEXITCODE -ne 0) { throw "Chocolatey $operation failed." }
        foreach ($kind in @('fixture', 'helper')) {
            $actual = (Get-Content (Join-Path $isolatedInstall "lib\epix-mirror-folder-$kind\tools\version.txt") -Raw).Trim()
            if ($actual -ne $version) { throw "Expected $kind $version, got $actual" }
        }
    }
    Write-Output 'Chocolatey flat-folder install 1.0.0 and upgrade 2.0.0, including dependency, passed.'
} finally {
    $env:ChocolateyInstall = $originalInstall
    if ((Get-FileHash $originalConfig -Algorithm SHA256).Hash -ne $configHash) {
        throw 'Runner Chocolatey configuration changed unexpectedly.'
    }
    Remove-Item -Recurse -Force $taskRoot
}
