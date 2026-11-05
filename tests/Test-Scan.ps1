# Synthetic folders and mocked check groups only; no player data or system settings are changed.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repository = Split-Path $PSScriptRoot -Parent
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('NikkeTrace-scan-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$oldLocal = $env:LOCALAPPDATA
$oldRoaming = $env:APPDATA
$checks = 0
function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
    $script:checks++
}
try {
    [void][IO.Directory]::CreateDirectory($fixture)
    . (Join-Path $repository 'NikkeTrace.ps1') -Language en -NoPrompt
    $env:LOCALAPPDATA = Join-Path $fixture 'Local'
    $env:APPDATA = Join-Path $fixture 'Roaming'
    Initialize-Report

    $longParent = Join-Path $fixture ('a' * 100)
    $longFolder = Join-Path $longParent ('b' * (240 - $longParent.Length - 1))
    [void][IO.Directory]::CreateDirectory(('\\?\' + $longFolder))
    [IO.File]::WriteAllText(('\\?\' + (Join-Path $longFolder 'platform_experience_helper.dll')), 'INERT TEST FILE')
    $found = @(Find-IndicatorFiles $fixture 'platform_experience_helper.dll')
    Assert ($found.Count -eq 1 -and $script:Issues.Count -eq 0) 'long folder plus filename is searched without a false incomplete check'
    Assert (-not $found[0].FullName.StartsWith('\\?\')) 'read-only namespace handling preserves normal evidence paths'
    [IO.File]::WriteAllText((Join-Path $fixture 'debug.log'), 'k2f_chan')
    [IO.File]::WriteAllText((Join-Path $fixture 'tinyget.test.log'), 'agent started as')
    $logs = @(Find-IndicatorFiles $fixture @('debug.log*', 'tinyget.*.log'))
    Assert ($logs.Count -eq 2) 'one traversal keeps both log families'

    $NoPrompt = $false
    $writer = [IO.StringWriter]::new()
    $originalOut = [Console]::Out
    [Console]::SetOut([IO.TextWriter]::Synchronized($writer))
    try {
        Start-ScanFeedback
        Assert ($null -ne $script:ScanFeedback) 'independent feedback worker starts'
        $script:ScanFeedback.State.Phase = 'fixture phase'
        $script:ScanFeedback.State.Started = [datetime]::UtcNow.AddSeconds(-65)
        Start-Sleep -Seconds 11
        $timer = [Diagnostics.Stopwatch]::StartNew()
        Stop-ScanFeedback
        Assert ($timer.Elapsed.TotalSeconds -lt 2) 'feedback stops promptly without waiting for the refresh interval'
    } finally {
        Stop-ScanFeedback
        [Console]::SetOut($originalOut)
    }
    Assert ($writer.ToString() -match 'Still waiting: fixture phase' -and $writer.ToString() -match 'Ctrl\+C') 'a waiting operation produces independent, localized reminders'
    $writer.Dispose()

    $NoPrompt = $true
    Initialize-Report
    $result = Invoke-IndependentCheck 'fixture failure' { throw 'INERT FAILURE' }
    Assert ($result.State -eq 'Partiel' -and $result.Reasons.Count -eq 1) 'check failure remains incomplete'
    Assert ($result.DurationSeconds -ge 0 -and ($script:Report -join "`n") -match 'Check duration') 'completed and failed checks retain timing evidence'

    function Get-CacheLocations { [pscustomobject]@{ Path = $fixture; Shared = $false } }
    function Initialize-CacheReader {}
    function Read-CacheEvidence { param($Path, $Budget) [pscustomobject]@{ Markers = @(); Complete = $true; Bytes = 1 } }
    $script:produced = 0
    $nativeCacheFiles = ${function:Get-CacheFiles}
    function Get-CacheFiles {
        param($Root)
        for ($i = 0; $i -lt 2000; $i++) {
            $script:produced++
            [pscustomobject]@{ FullName = (Join-Path $Root ("inert-$i")); Length = 1 }
        }
    }
    Initialize-Report
    Test-LauncherCache
    Assert ($script:produced -le 513) 'cache budget stops upstream enumeration rather than collecting every file first'
    Assert ($script:Issues.Count -gt 0) 'reaching the cache budget never becomes a negative result'

    $cacheRoot = Join-Path $fixture 'cache'
    $js = Join-Path $cacheRoot 'Code Cache\js'
    [void][IO.Directory]::CreateDirectory($js)
    for ($i = 0; $i -lt 600; $i++) { [IO.File]::WriteAllText((Join-Path $js "inert-$i"), 'x') }
    function Get-CacheLocations { [pscustomobject]@{ Path = $cacheRoot; Shared = $false } }
    $script:produced = 0
    function Get-CacheFiles {
        param($Root)
        & $nativeCacheFiles $Root | ForEach-Object { $script:produced++; $_ }
    }
    Initialize-Report
    Test-LauncherCache
    Assert ($script:produced -le 513 -and $script:Issues.Count -gt 0) 'the real cache traversal also stops streaming at the file budget'

    Initialize-Report
    $script:visited = New-Object 'System.Collections.Generic.List[string]'
    function Test-NikkePath { param($Path) $script:visited.Add('logs'); $script:LogsRead++ }
    function Test-BrowserFiles { $script:visited.Add('browsers'); throw 'INERT BROWSER ERROR' }
    function Test-Persistence { $script:visited.Add('registry') }
    function Test-TemporaryFiles { $script:visited.Add('temporary') }
    function Test-LauncherCache { $script:visited.Add('cache') }
    function Test-LoadedModules { $script:visited.Add('modules') }
    function Test-TcpConnections { $script:visited.Add('tcp') }
    function Test-DnsCache { $script:visited.Add('dns') }
    function Test-HostsFile { $script:visited.Add('hosts') }
    $script:ScanPaths = @('C:\Synthetic')
    $NoPrompt = $false
    $whole = Invoke-TraceScan
    $NoPrompt = $true
    Assert ($script:visited.Count -eq 9 -and $whole.Checks.Count -eq 9) 'all check groups continue after a simulated failure'
    Assert ($whole.Checks[1].State -eq 'Partiel' -and (Get-SnapshotConclusion $whole).Color -ne 'Green') 'the real scan aggregates an incomplete group without a green result'
    Assert ($null -eq $script:ScanFeedback -and @($whole.Checks | Where-Object { $null -eq $_.PSObject.Properties['DurationSeconds'] }).Count -eq 0) 'every group is timed and the feedback worker is disposed'

    Initialize-Report
    $snapshot = [pscustomobject]@{
        Findings = @([pscustomobject]@{ Type = 'Observation'; Strong = $false; Target = @{ Area = 'DNS' }; Location = 'inert'; Kind = 'inert' })
        Checks = @([pscustomobject]@{ Name = 'Cache DNS local'; State = 'Effectué'; Reasons = @() }, [pscustomobject]@{ Name = 'Journaux NIKKE disponibles'; State = 'Partiel'; Reasons = @('Aucun journal NIKKE lisible : fixture') })
        Issues = @('fixture limit')
    }
    $script:screen = New-Object 'System.Collections.Generic.List[object]'
    function Write-Host {
        param($Object, [ConsoleColor]$ForegroundColor = 'Gray')
        $script:screen.Add([pscustomobject]@{ Text = (Convert-UiText ([string]$Object)); Color = $ForegroundColor })
    }
    Show-Snapshot $snapshot
    $visible = $script:screen.Text -join "`n"
    Assert ($visible -match 'check is incomplete' -and @($script:screen | Where-Object { $_.Color -eq 'Green' }).Count -eq 0) 'incomplete coverage has no green overall reassurance'
    Assert ($visible -match 'Old log missing' -and $visible -match 'Visiting the site') 'missing history and weak DNS evidence have separate explanations'
    Assert (@($script:screen | Where-Object { $_.Color -eq 'Yellow' }).Count -eq 1) 'only the incomplete status is highlighted, not the entire result'
    function Get-NikkeRemovalCandidates { @() }
    $script:CurrentSnapshot = $snapshot
    Assert (-not (Test-CleanupAvailable)) 'a DNS reference alone does not offer an empty cleanup'
    Microsoft.PowerShell.Utility\Write-Host "SUCCESS: $checks scan checks passed."
} finally {
    Stop-ScanFeedback
    $env:LOCALAPPDATA = $oldLocal
    $env:APPDATA = $oldRoaming
    if ([IO.Directory]::Exists($fixture)) { [IO.Directory]::Delete(('\\?\' + $fixture), $true) }
}
