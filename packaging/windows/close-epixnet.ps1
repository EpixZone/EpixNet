# Close a running EpixNet before its install tree is replaced or removed.
#
# Run by installer.nsi (extracted next to the installer's plugins) and usable by
# hand. Everything running from the install directory counts: the launcher
# (epix-browser.exe), the native host (epix-nmh.exe) and the bundled Firefox
# and its child processes. Nothing outside that directory is ever touched, so a
# user's own Firefox keeps running.
#
#   -InstallDir  the EpixNet install directory (%LOCALAPPDATA%\Epix)
#   -Mode        detect  exit 0 when nothing runs from InstallDir, 1 when
#                        something does (default)
#                close   ask EpixNet to quit, then stop what is left;
#                        exit 0 when nothing runs any more, 1 otherwise
#   -Launcher    a launcher that understands --quit (the NEW epix-browser.exe
#                the installer is about to install). Asked first, so a current
#                EpixNet closes its browser and shuts its node down cleanly.
#                Older launchers ignore --quit; those are stopped directly.
#
# Exit codes are the whole interface: the installer branches on them.
param(
    [Parameter(Mandatory = $true)][string]$InstallDir,
    [ValidateSet('detect', 'close')][string]$Mode = 'detect',
    [string]$Launcher = ''
)

$ErrorActionPreference = 'SilentlyContinue'

$root = [System.IO.Path]::GetFullPath($InstallDir).TrimEnd('\') + '\'

function Get-EpixProcesses {
    $found = @()
    foreach ($p in Get-Process) {
        $path = $null
        try { $path = $p.Path } catch { $path = $null }
        if ($path -and $path.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            $found += $p
        }
    }
    return $found
}

function Wait-EpixGone([int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        if ((Get-EpixProcesses).Count -eq 0) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return (Get-EpixProcesses).Count -eq 0
}

$running = Get-EpixProcesses
if ($Mode -eq 'detect') {
    if ($running.Count -gt 0) { exit 1 } else { exit 0 }
}

if ($running.Count -eq 0) { exit 0 }

# Graceful first: the launcher closes its browser and shuts the node down.
if ($Launcher -and (Test-Path -LiteralPath $Launcher)) {
    $asked = $false
    try {
        Start-Process -FilePath $Launcher -ArgumentList '--quit' -Wait -WindowStyle Hidden
        $asked = $true
    } catch {}
    if ($asked -and (Wait-EpixGone 5)) { exit 0 }
}

# Still there: an older launcher without --quit, a tray-less run, or a stuck
# process. Stop the launcher first so it cannot reopen the browser, then
# whatever remains under the install tree.
foreach ($p in (Get-EpixProcesses | Sort-Object { $_.ProcessName -ne 'epix-browser' })) {
    try { Stop-Process -Id $p.Id -Force } catch {}
}
if (Wait-EpixGone 15) { exit 0 }
exit 1
